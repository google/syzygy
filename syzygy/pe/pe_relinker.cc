// Copyright 2012 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "syzygy/pe/pe_relinker.h"

#include "base/file_util.h"
#include "syzygy/core/zstream.h"
#include "syzygy/pdb/pdb_byte_stream.h"
#include "syzygy/pdb/pdb_file.h"
#include "syzygy/pdb/pdb_reader.h"
#include "syzygy/pdb/pdb_util.h"
#include "syzygy/pdb/pdb_writer.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/find.h"
#include "syzygy/pe/image_source_map.h"
#include "syzygy/pe/metadata.h"
#include "syzygy/pe/new_decomposer.h"
#include "syzygy/pe/pdb_info.h"
#include "syzygy/pe/pe_file_writer.h"
#include "syzygy/pe/pe_image_layout_builder.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/serialization.h"
#include "syzygy/pe/orderers/pe_orderer.h"
#include "syzygy/pe/transforms/add_metadata_transform.h"
#include "syzygy/pe/transforms/add_pdb_info_transform.h"
#include "syzygy/pe/transforms/pe_prepare_headers_transform.h"

namespace pe {

namespace {

typedef block_graph::BlockGraphTransformInterface Transform;
typedef block_graph::BlockGraphOrdererInterface Orderer;

using block_graph::ApplyBlockGraphTransform;
using block_graph::BlockGraph;
using block_graph::OrderedBlockGraph;
using core::RelativeAddress;
using pdb::NameStreamMap;
using pdb::PdbByteStream;
using pdb::PdbFile;
using pdb::PdbInfoHeader70;
using pdb::PdbMutatorInterface;
using pdb::PdbStream;
using pdb::WritablePdbStream;

// A utility class for wrapping a serialization OutStream around a
// WritablePdbStream.
// TODO(chrisha): We really need to centralize stream/buffer semantics in
//     a small set of clean interfaces, and make all input/output/parsing work
//     on these interfaces.
class PdbOutStream : public core::OutStream {
 public:
  explicit PdbOutStream(WritablePdbStream* pdb_stream)
      : pdb_stream_(pdb_stream) {
    DCHECK(pdb_stream != NULL);
  }

  virtual ~PdbOutStream() { }

  virtual bool Write(size_t length, const core::Byte* bytes) OVERRIDE {
    return pdb_stream_->Write(length, bytes);
  }

 private:
  scoped_refptr<WritablePdbStream> pdb_stream_;
};

void GetOmapRange(const std::vector<ImageLayout::SectionInfo>& sections,
                  RelativeAddressRange* range) {
  DCHECK(range != NULL);

  // There need to be at least two sections, one containing something and the
  // other containing the relocs.
  DCHECK_GT(sections.size(), 1u);
  DCHECK_EQ(sections.back().name, std::string(kRelocSectionName));

  // For some reason, if we output OMAP entries for the headers (before the
  // first section), everything falls apart. Not outputting these allows the
  // unittests to pass. Also, we don't want to output OMAP information for
  // the relocs, as these are entirely different from image to image.
  RelativeAddress start_of_image = sections.front().addr;
  RelativeAddress end_of_image = sections.back().addr;
  *range = RelativeAddressRange(start_of_image, end_of_image - start_of_image);
}

bool ApplyPdbMutator(PdbMutatorInterface* pdb_mutator,
                     PdbFile* pdb_file) {
  DCHECK(pdb_mutator != NULL);
  DCHECK(pdb_file != NULL);

  if (!pdb_mutator->MutatePdb(pdb_file)) {
    LOG(ERROR) << "PDB mutator failed: " << pdb_mutator->name();
    return false;
  }

  return true;
}

// Initializes input_pdb_path, output_pdb_path, pe_file and guid. If the input
// paths are unable to be found this will return false. If @p allow_overwrite is
// false and output path or output_pdb_path will overwrite an existing file this
// will return false. @p input_pdb_path may be left empty in which case it will
// be automatically determined from the debug information in @p input_path; this
// step may fail causing this to return false. @p output_pdb_path may also be
// left empty in which case it will be inferred from input_pdb_path, being
// placed alongside output_path.
bool InitializePaths(const base::FilePath& input_path,
                     const base::FilePath& output_path,
                     bool allow_overwrite,
                     base::FilePath* input_pdb_path,
                     base::FilePath* output_pdb_path) {
  DCHECK(input_pdb_path != NULL);
  DCHECK(output_pdb_path != NULL);

  // At a very minimum we have to specify input and outputs.
  if (input_path.empty() || output_path.empty()) {
    LOG(ERROR) << "input_path and output_path must be set!";
    return false;
  }

  if (!file_util::PathExists(input_path)) {
    LOG(ERROR) << "Input module not found: " << input_path.value();
    return false;
  }

  // No input PDB specified? Find it automagically.
  if (input_pdb_path->empty()) {
    LOG(INFO) << "Input PDB not specified, searching for it.";
    if (!FindPdbForModule(input_path, input_pdb_path) ||
        input_pdb_path->empty()) {
      LOG(ERROR) << "Unable to find PDB file for module: "
                 << input_path.value();
      return false;
    }
  }

  if (!file_util::PathExists(*input_pdb_path)) {
    LOG(ERROR) << "Input PDB not found: " << input_pdb_path->value();
    return false;
  }

  // If no output PDB path is specified, infer one.
  if (output_pdb_path->empty()) {
    // If the input and output DLLs have the same basename, default to writing
    // using the same PDB basename, but alongside the new module.
    if (input_path.BaseName() == output_path.BaseName()) {
      *output_pdb_path = output_path.DirName().Append(
          input_pdb_path->BaseName());
    } else {
      // Otherwise, default to using the output basename with a PDB extension.
      *output_pdb_path = output_path.ReplaceExtension(L"pdb");
    }

    LOG(INFO) << "Using default output PDB path: " << output_pdb_path->value();
  }

  // Ensure we aren't about to overwrite anything we don't want to. We do this
  // early on so that we abort before decomposition, transformation, etc.
  if (!allow_overwrite) {
    bool terminate = false;
    if (file_util::PathExists(output_path)) {
      terminate = true;
      LOG(ERROR) << "Output module path already exists.";
    }
    if (file_util::PathExists(*output_pdb_path)) {
      terminate = true;
      LOG(ERROR) << "Output PDB path already exists.";
    }
    if (terminate)
      return false;
  }

  return true;
}

// Decomposes the module enclosed by the given PE file.
bool Decompose(bool use_new_decomposer,
               const PEFile& pe_file,
               const base::FilePath& pdb_path,
               ImageLayout* image_layout,
               BlockGraph::Block** dos_header_block) {
  DCHECK(image_layout != NULL);
  DCHECK(dos_header_block != NULL);

  LOG(INFO) << "Decomposing module: " << pe_file.path().value();

  BlockGraph* block_graph = image_layout->blocks.graph();
  ImageLayout orig_image_layout(block_graph);

  // Decompose the input image.
  if (use_new_decomposer) {
    LOG(INFO) << "Using new decomposer for decomposition.";
    NewDecomposer decomposer(pe_file);
    decomposer.set_pdb_path(pdb_path);
    if (!decomposer.Decompose(&orig_image_layout)) {
      LOG(ERROR) << "Unable to decompose module: " << pe_file.path().value();
      return false;
    }
  } else {
    Decomposer decomposer(pe_file);
    decomposer.set_pdb_path(pdb_path);
    if (!decomposer.Decompose(&orig_image_layout)) {
      LOG(ERROR) << "Unable to decompose module: " << pe_file.path().value();
      return false;
    }
  }

  // Make a copy of the image layout without padding. We don't want to carry
  // the padding through the toolchain.
  LOG(INFO) << "Removing padding blocks.";
  if (!pe::CopyImageLayoutWithoutPadding(orig_image_layout, image_layout)) {
    LOG(ERROR) << "Failed to remove padding blocks.";
    return false;
  }

  // Get the DOS header block.
  *dos_header_block =
      image_layout->blocks.GetBlockByAddress(
          BlockGraph::RelativeAddress(0));
  if (*dos_header_block == NULL) {
    LOG(ERROR) << "Unable to find the DOS header block.";
    return false;
  }

  return true;
}

bool ApplyPdbMutators(const std::vector<PdbMutatorInterface*>& pdb_mutators,
                      PdbFile* pdb_file) {
  DCHECK(pdb_file != NULL);

  LOG(INFO) << "Mutating PDB.";

  // Apply the orderers.
  for (size_t i = 0; i < pdb_mutators.size(); ++i) {
    LOG(INFO) << "Applying PDB mutator: " << pdb_mutators[i]->name();
    if (!ApplyPdbMutator(pdb_mutators[i], pdb_file))
      return false;
  }

  return true;
}

// Lays out the image.
bool BuildImageLayout(size_t padding,
                      size_t code_alignment,
                      const OrderedBlockGraph& ordered_block_graph,
                      BlockGraph::Block* dos_header_block,
                      ImageLayout* image_layout) {
  DCHECK(dos_header_block != NULL);
  DCHECK(image_layout != NULL);

  LOG(INFO) << "Building image layout.";

  PEImageLayoutBuilder builder(image_layout);
  builder.set_padding(padding);
  builder.set_code_alignment(code_alignment);
  if (!builder.LayoutImageHeaders(dos_header_block)) {
    LOG(ERROR) << "PEImageLayoutBuilder::LayoutImageHeaders failed.";
    return false;
  }

  if (!builder.LayoutOrderedBlockGraph(ordered_block_graph)) {
    LOG(ERROR) << "PEImageLayoutBuilder::LayoutOrderedBlockGraph failed.";
    return false;
  }

  LOG(INFO) << "Finalizing image layout.";
  if (!builder.Finalize()) {
    LOG(ERROR) << "PEImageLayoutBuilder::Finalize failed.";
    return false;
  }

  return true;
}

// Writes the image.
bool WriteImage(const ImageLayout& image_layout,
                const base::FilePath& output_path) {
  PEFileWriter writer(image_layout);

  LOG(INFO) << "Writing image: " << output_path.value();
  if (!writer.WriteImage(output_path)) {
    LOG(ERROR) << "Failed to write image \"" << output_path.value() << "\".";
    return false;
  }

  return true;
}

void BuildOmapVectors(const RelativeAddressRange& input_range,
                      const ImageLayout& output_image_layout,
                      std::vector<OMAP>* omap_to,
                      std::vector<OMAP>* omap_from) {
  DCHECK(omap_to != NULL);
  DCHECK(omap_from != NULL);

  LOG(INFO) << "Building OMAP vectors.";

  // Get the range of the output image, sans headers. This is required for
  // generating OMAP information.
  RelativeAddressRange output_range;
  GetOmapRange(output_image_layout.sections, &output_range);

  ImageSourceMap reverse_map;
  BuildImageSourceMap(output_image_layout, &reverse_map);

  ImageSourceMap forward_map;
  if (reverse_map.ComputeInverse(&forward_map) != 0) {
    LOG(WARNING) << "OMAPFROM not unique (there exist repeated source ranges).";
  }

  // Build the two OMAP vectors.
  BuildOmapVectorFromImageSourceMap(output_range, reverse_map, omap_to);
  BuildOmapVectorFromImageSourceMap(input_range, forward_map, omap_from);
}

// Updates the OMAP and GUID info in the given PDB file.
bool SetOmapAndGuid(const RelativeAddressRange input_range,
                    const ImageLayout& image_layout,
                    const GUID& guid,
                    PdbFile* pdb_file) {
  DCHECK(pdb_file != NULL);

  LOG(INFO) << "Updating OMAP and GUID information.";

  std::vector<OMAP> omap_to, omap_from;
  BuildOmapVectors(input_range, image_layout, &omap_to, &omap_from);

  if (!pdb::SetGuid(guid, pdb_file)) {
    LOG(ERROR) << "Unable to set PDB GUID.";
    return false;
  }

  if (!pdb::SetOmapToStream(omap_to, pdb_file)) {
    LOG(ERROR) << "Unable to set OMAP_TO.";
    return false;
  }

  if (!pdb::SetOmapFromStream(omap_from, pdb_file)) {
    LOG(ERROR) << "Unable to set OMAP_FROM.";
    return false;
  }

  return true;
}

bool WritePdbFile(const base::FilePath& output_pdb_path,
                  const PdbFile& pdb_file) {
  LOG(INFO) << "Writing PDB file: " << output_pdb_path.value();

  base::FilePath temp_pdb;
  if (!file_util::CreateTemporaryFileInDir(output_pdb_path.DirName(),
                                           &temp_pdb)) {
    LOG(ERROR) << "Unable to create temporary PDB file.";
    return false;
  }

  pdb::PdbWriter pdb_writer;
  if (!pdb_writer.Write(temp_pdb, pdb_file)) {
    LOG(ERROR) << "Failed to write temporary PDB file to \""
               << temp_pdb.value() << "\".";
  }

  if (!file_util::ReplaceFile(temp_pdb, output_pdb_path)) {
    LOG(ERROR) << "Unable to move temporary PDB file to \""
        << output_pdb_path.value() << "\".";
    file_util::Delete(temp_pdb, false);
    return false;
  }

  return true;
}

// Get a specific named stream if it already exists, otherwise create one.
// @param stream_name The name of the stream.
// @param name_stream_map The map containing the names of the streams in the
//     PDB. If the stream doesn't already exist the map will be augmented with
//     another entry.
// @param pdb_file The PDB file to which the stream will be added.
// @param replace_stream If true, will cause a new stream to be created even if
//     another one already existed.
// @returns a pointer to the PDB stream on success, NULL on failure.
PdbStream* GetOrCreatePdbStreamByName(const char* stream_name,
                                      bool replace_stream,
                                      NameStreamMap* name_stream_map,
                                      PdbFile* pdb_file) {
  DCHECK(name_stream_map != NULL);
  DCHECK(pdb_file != NULL);
  scoped_refptr<PdbStream> stream;

  NameStreamMap::const_iterator name_it = name_stream_map->find(stream_name);
  if (name_it != name_stream_map->end()) {
    // Replace the existing stream by a brand-new one if it's required.
    if (replace_stream) {
      stream = new PdbByteStream();
      pdb_file->ReplaceStream(name_it->second, stream.get());
    } else {
      if (!pdb::EnsureStreamWritable(name_it->second, pdb_file)) {
        LOG(ERROR) << "Failed to make " << stream_name << " stream writable.";
        return NULL;
      }
      stream = pdb_file->GetStream(name_it->second);
    }
  } else {
    stream = new PdbByteStream();
    uint32 index = pdb_file->AppendStream(stream.get());
    (*name_stream_map)[stream_name] = index;
  }

  return stream.get();
}

// This updates or creates the Syzygy history stream, appending the metadata
// describing this module and transform. The history stream consists of
// a named PDB stream with the name /Syzygy/History. It consists of:
//
//   uint32 version
//   uint32 history_length
//   serialized pe::Metadata 0
//   ...
//   serialized pe::Metadata history_length - 1
//
// If the format is changed, be sure to update this documentation and
// pdb::kSyzygyHistoryStreamVersion (in pdb_constants.h).
bool WriteSyzygyHistoryStream(const base::FilePath& input_path,
                              NameStreamMap* name_stream_map,
                              PdbFile* pdb_file) {
  // Get the history stream.
  scoped_refptr<PdbStream> history_reader =
      GetOrCreatePdbStreamByName(pdb::kSyzygyHistoryStreamName,
                                 false,
                                 name_stream_map,
                                 pdb_file);

  if (history_reader == NULL) {
    LOG(ERROR) << "Failed to get the history stream.";
    return false;
  }

  scoped_refptr<WritablePdbStream> history_writer =
      history_reader->GetWritablePdbStream();
  DCHECK(history_writer.get() != NULL);

  // Get the metadata.
  Metadata metadata;
  PEFile pe_file;
  if (!pe_file.Init(input_path)) {
    LOG(ERROR) << "Failed to initialize PE file for \"" << input_path.value()
               << "\".";
    return false;
  }

  PEFile::Signature pe_sig;
  pe_file.GetSignature(&pe_sig);
  if (!metadata.Init(pe_sig)) {
    LOG(ERROR) << "Failed to initialize metadata for \"" << input_path.value()
               << "\".";
    return false;
  }

  // Validate the history stream if it is non-empty.
  if (history_reader->length() > 0) {
    // Read the header.
    uint32 version = 0;
    uint32 history_length = 0;
    if (!history_reader->Seek(0) ||
        !history_reader->Read(&version, 1) ||
        !history_reader->Read(&history_length, 1)) {
      LOG(ERROR) << "Failed to read existing Syzygy history stream header.";
      return false;
    }

    // Check the version.
    if (version != pdb::kSyzygyHistoryStreamVersion) {
      LOG(ERROR) << "PDB contains unsupported Syzygy history stream version "
                 << "(got " << version << ", expected "
                 << pdb::kSyzygyHistoryStreamVersion << ").";
      return false;
    }

    // Increment the history length and rewrite it.
    history_length++;
    history_writer->set_pos(sizeof(pdb::kSyzygyHistoryStreamVersion));
    if (!history_writer->Write(history_length)) {
      LOG(ERROR) << "Failed to write new Syzygy history stream length.";
      return false;
    }
  } else {
    // If there wasn't already a history stream, create one and write the
    // header.
    DCHECK_EQ(0u, history_writer->pos());
    const uint32 kHistoryLength = 1;
    if (!history_writer->Write(pdb::kSyzygyHistoryStreamVersion) ||
        !history_writer->Write(kHistoryLength)) {
      LOG(ERROR) << "Failed to write Syzygy history stream header.";
      return false;
    }
  }

  // Append the metadata to the history.
  history_writer->set_pos(history_writer->length());
  PdbOutStream out_stream(history_writer.get());
  core::OutArchive out_archive(&out_stream);
  if (!out_archive.Save(metadata)) {
    LOG(ERROR) << "Failed to write metadata to Syzygy history stream.";
    return false;
  }

  return true;
}

// This writes the serialized block-graph and the image layout in a PDB stream
// named /Syzygy/BlockGraph. If the format is changed, be sure to update this
// documentation and pdb::kSyzygyBlockGraphStreamVersion (in pdb_constants.h).
// The block graph stream will not include the data from the blocks of the
// block-graph. If the strip-strings flag is set to true the strings contained
// in the block-graph won't be saved.
bool WriteSyzygyBlockGraphStream(const PEFile& pe_file,
                                 const ImageLayout& image_layout,
                                 bool strip_strings,
                                 bool compress,
                                 NameStreamMap* name_stream_map,
                                 PdbFile* pdb_file) {
  // Get the redecomposition data stream.
  scoped_refptr<PdbStream> block_graph_reader =
      GetOrCreatePdbStreamByName(pdb::kSyzygyBlockGraphStreamName,
                                 true,
                                 name_stream_map,
                                 pdb_file);

  if (block_graph_reader == NULL) {
    LOG(ERROR) << "Failed to get the block-graph stream.";
    return false;
  }
  DCHECK_EQ(0u, block_graph_reader->length());

  scoped_refptr<WritablePdbStream> block_graph_writer =
      block_graph_reader->GetWritablePdbStream();
  DCHECK(block_graph_writer.get() != NULL);

  // Write the version of the BlockGraph stream, and whether or not its
  // contents are compressed.
  if (!block_graph_writer->Write(pdb::kSyzygyBlockGraphStreamVersion) ||
      !block_graph_writer->Write(static_cast<unsigned char>(compress))) {
    LOG(ERROR) << "Failed to write Syzygy BlockGraph stream header.";
    return false;
  }

  // Set up the output stream.
  PdbOutStream pdb_out_stream(block_graph_writer.get());
  core::OutStream* out_stream = &pdb_out_stream;

  // If requested, compress the output.
  scoped_ptr<core::ZOutStream> zip_stream;
  if (compress) {
    zip_stream.reset(new core::ZOutStream(&pdb_out_stream));
    out_stream = zip_stream.get();
    if (!zip_stream->Init(core::ZOutStream::kZBestCompression)) {
      LOG(ERROR) << "Failed to initialize zlib compressor.";
      return false;
    }
  }

  core::OutArchive out_archive(out_stream);

  // Set up the serialization properties.
  block_graph::BlockGraphSerializer::Attributes attributes = 0;
  if (strip_strings)
    attributes |= block_graph::BlockGraphSerializer::OMIT_STRINGS;

  // And finally, perform the serialization.
  if (!SaveBlockGraphAndImageLayout(pe_file, attributes, image_layout,
                                    &out_archive)) {
    LOG(ERROR) << "SaveBlockGraphAndImageLayout failed.";
    return false;
  }

  // We have to flush the stream in case it's a zstream.
  out_stream->Flush();

  return true;
}

}  // namespace

PERelinker::PERelinker(const PETransformPolicy* transform_policy)
    : PECoffRelinker(transform_policy),
      add_metadata_(true), augment_pdb_(true),
      compress_pdb_(false), strip_strings_(false), use_new_decomposer_(false),
      padding_(0), code_alignment_(1), output_guid_(GUID_NULL) {
  DCHECK(transform_policy != NULL);
}

bool PERelinker::AppendPdbMutator(PdbMutatorInterface* pdb_mutator) {
  DCHECK(pdb_mutator != NULL);
  pdb_mutators_.push_back(pdb_mutator);
  return true;
}

bool PERelinker::AppendPdbMutators(
    const std::vector<PdbMutatorInterface*>& pdb_mutators) {
  pdb_mutators_.insert(pdb_mutators_.end(),
                       pdb_mutators.begin(),
                       pdb_mutators.end());
  return true;
}

bool PERelinker::Init() {
  DCHECK(inited_ == false);

  // Initialize the paths.
  if (!InitializePaths(input_path_, output_path_, allow_overwrite_,
                       &input_pdb_path_, &output_pdb_path_)) {
    return false;
  }

  LOG(INFO) << "Input module : " << input_path_.value();
  LOG(INFO) << "Input PDB    : " << input_pdb_path_.value();
  LOG(INFO) << "Output module: " << output_path_.value();
  LOG(INFO) << "Output PDB   : " << output_pdb_path_.value();

  // Open the input PE file.
  if (!input_pe_file_.Init(input_path_)) {
    LOG(ERROR) << "Unable to load \"" << input_path_.value() << "\".";
    return false;
  }

  // Generate a GUID for the relinked image's PDB file.
  if (FAILED(::CoCreateGuid(&output_guid_))) {
    LOG(ERROR) << "Failed to create new PDB GUID.";
    return false;
  }

  // Decompose the image.
  if (!Decompose(use_new_decomposer_, input_pe_file_, input_pdb_path_,
                 &input_image_layout_, &headers_block_)) {
    return false;
  }

  inited_ = true;

  return true;
}

bool PERelinker::Relink() {
  if (!inited_) {
    LOG(ERROR) << "Init has not been successfully called.";
    return false;
  }

  // Transform it. In addition to user-supplied transforms, we apply the
  // following mandatory extra transforms for PE, in order:
  //  1. Add metadata if asked to.
  //  2. Update the PDB information to point to the correct PDB file.
  //  3. Finally, run the prepare headers transform. This ensures that the
  //     header block is properly sized to receive layout information
  //     post-ordering.
  std::vector<Transform*> post_transforms;
  pe::transforms::AddMetadataTransform add_metadata_tx(input_path_);
  pe::transforms::AddPdbInfoTransform add_pdb_info_tx(output_pdb_path_, 1,
                                                      output_guid_);
  pe::transforms::PEPrepareHeadersTransform prep_headers_tx;

  if (add_metadata_)
    post_transforms.push_back(&add_metadata_tx);
  post_transforms.push_back(&add_pdb_info_tx);
  post_transforms.push_back(&prep_headers_tx);

  if (!ApplyTransforms(post_transforms))
    return false;

  // Order it.
  std::vector<Orderer*> post_orderers;
  pe::orderers::PEOrderer pe_orderer;
  post_orderers.push_back(&pe_orderer);

  OrderedBlockGraph ordered_block_graph(&block_graph_);
  if (!ApplyOrderers(post_orderers, &ordered_block_graph))
    return false;

  // Lay it out.
  ImageLayout output_image_layout(&block_graph_);
  if (!BuildImageLayout(padding_, code_alignment_,
                        ordered_block_graph, headers_block_,
                        &output_image_layout)) {
    return false;
  }

  // Write the image.
  if (!WriteImage(output_image_layout, output_path_))
    return false;

  // From here on down we are processing the PDB file.

  // Read the PDB file.
  LOG(INFO) << "Reading PDB file: " << input_pdb_path_.value();
  pdb::PdbReader pdb_reader;
  PdbFile pdb_file;
  if (!pdb_reader.Read(input_pdb_path_, &pdb_file)) {
    LOG(ERROR) << "Unable to read PDB file: " << input_pdb_path_.value();
    return false;
  }

  // Apply the mutators to the PDB file.
  if (!ApplyPdbMutators(pdb_mutators_, &pdb_file))
    return false;

  // TODO(chrisha): Make the following 3 PDB updates PdbMutatorInterface
  //     implementations.

  // Update the OMAP and GUID information.
  RelativeAddressRange input_range;
  GetOmapRange(input_image_layout_.sections, &input_range);
  if (!SetOmapAndGuid(input_range, output_image_layout, output_guid_,
                      &pdb_file)) {
    return false;
  }

  // Parse the header and named streams.
  pdb::PdbInfoHeader70 header = {};
  pdb::NameStreamMap name_stream_map;
  if (!pdb::ReadHeaderInfoStream(pdb_file, &header, &name_stream_map))
    return false;

  // Update/create the Syzygy history stream.
  if (!WriteSyzygyHistoryStream(input_path_, &name_stream_map, &pdb_file))
    return false;

  // Add redecomposition data in another stream, only if augment_pdb_ is set.
  if (augment_pdb_) {
    LOG(INFO) << "The block-graph stream is being written to the PDB.";

    PEFile new_pe_file;
    if (!new_pe_file.Init(output_path_)) {
      LOG(ERROR) << "Failed to read newly written PE file.";
      return false;
    }

    if (!WriteSyzygyBlockGraphStream(new_pe_file,
                                     output_image_layout,
                                     strip_strings_,
                                     compress_pdb_,
                                     &name_stream_map,
                                     &pdb_file)) {
      return false;
    }
  }

  // Write the updated name-stream map back to the header info stream.
  if (!pdb::WriteHeaderInfoStream(header, name_stream_map, &pdb_file))
    return false;

  // Stream 0 contains a copy of the previous PDB's directory. This, combined
  // with copy-on-write semantics of individual blocks makes the file contain
  // its whole edit history. Since we're writing a 'new' PDB file (we reset the
  // GUID and age), we have no history so can safely throw away this stream.
  pdb_file.ReplaceStream(0, NULL);

  // Write the PDB file. We use a helper function that first writes it to a
  // temporary file and then moves it, enabling overwrites.
  if (!WritePdbFile(output_pdb_path_, pdb_file))
    return false;

  return true;
}

}  // namespace pe
