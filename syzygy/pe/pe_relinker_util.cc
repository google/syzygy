// Copyright 2013 Google Inc. All Rights Reserved.
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

#include "syzygy/pe/pe_relinker_util.h"

#include "base/file_util.h"
#include "syzygy/block_graph/transform.h"
#include "syzygy/core/file_util.h"
#include "syzygy/core/zstream.h"
#include "syzygy/pdb/pdb_byte_stream.h"
#include "syzygy/pdb/pdb_util.h"
#include "syzygy/pe/find.h"
#include "syzygy/pe/metadata.h"
#include "syzygy/pe/pe_image_layout_builder.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/serialization.h"
#include "syzygy/pe/orderers/pe_orderer.h"
#include "syzygy/pe/transforms/add_metadata_transform.h"
#include "syzygy/pe/transforms/add_pdb_info_transform.h"
#include "syzygy/pe/transforms/pe_prepare_headers_transform.h"
#include "syzygy/pe/transforms/pe_remove_empty_sections_transform.h"

namespace pe {

namespace {

using block_graph::BlockGraph;
using block_graph::BlockGraphTransformInterface;
using block_graph::OrderedBlockGraph;
using core::RelativeAddress;
using pdb::NameStreamMap;
using pdb::PdbByteStream;
using pdb::PdbFile;
using pdb::PdbInfoHeader70;
using pdb::PdbStream;
using pdb::WritablePdbStream;
using pe::PETransformPolicy;

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

// Get a specific named stream if it already exists, otherwise create one.
// @param stream_name The name of the stream.
// @param name_stream_map The map containing the names of the streams in the
//     PDB. If the stream doesn't already exist the map will be augmented with
//     another entry.
// @param pdb_file The PDB file to which the stream will be added.
// @param replace_stream If true, will cause a new stream to be created even if
//     another one already existed.
// @return a pointer to the PDB stream on success, NULL on failure.
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

bool ValidateAndInferPaths(
    const base::FilePath& input_module,
    const base::FilePath& output_module,
    bool allow_overwrite,
    base::FilePath* input_pdb,
    base::FilePath* output_pdb) {
  DCHECK(!input_module.empty());
  DCHECK(!output_module.empty());
  DCHECK_NE(reinterpret_cast<base::FilePath*>(NULL), input_pdb);
  DCHECK_NE(reinterpret_cast<base::FilePath*>(NULL), output_pdb);

  if (!file_util::PathExists(input_module)) {
    LOG(ERROR) << "Input module not found: " << input_module.value();
    return false;
  }

  if (!allow_overwrite && file_util::PathExists(output_module)) {
    LOG(ERROR) << "Output module exists: " << output_module.value();
    LOG(ERROR) << "Specify --overwrite to ignore this error.";
    return false;
  }

  // If no input PDB was specified then search for it.
  if (input_pdb->empty()) {
    LOG(INFO) << "Input PDB not specified, searching for it.";
    if (!pe::FindPdbForModule(input_module, input_pdb) ||
        input_pdb->empty()) {
      LOG(ERROR) << "Unable to find PDB file for module: "
                 << input_module.value();
      return NULL;
    }
  }

  if (!file_util::PathExists(*input_pdb)) {
    LOG(ERROR) << "Input PDB not found: " << input_pdb->value();
    return false;
  }

  // If no output PDB path is specified, infer one.
  if (output_pdb->empty()) {
    // If the input and output DLLs have the same basename, default to writing
    // using the same PDB basename, but alongside the new module.
    if (input_module.BaseName() == output_module.BaseName()) {
      *output_pdb = output_module.DirName().Append(input_pdb->BaseName());
    } else {
      // Otherwise, default to using the output basename with a PDB extension
      // added to it.
      *output_pdb = output_module.AddExtension(L"pdb");
    }

    LOG(INFO) << "Using default output PDB path: " << output_pdb->value();
  }

  if (!allow_overwrite && file_util::PathExists(*output_pdb)) {
    LOG(ERROR) << "Output PDB exists: " << output_pdb->value();
    LOG(ERROR) << "Specify --overwrite to ignore this error.";
    return false;
  }

  // Perform some extra checking to make sure that writes aren't going to
  // collide. This prevents us from overwriting the input, effectively
  // preventing in-place transforms. This is not fool-proof in the face of
  // weird junctions but it will catch common errors.

  core::FilePathCompareResult result =
      core::CompareFilePaths(input_module, output_module);
  if (result == core::kEquivalentFilePaths) {
    LOG(ERROR) << "Input and output module paths are equivalent.";
    LOG(ERROR) << "Input module path: " << input_module.value();
    LOG(ERROR) << "Output module path: " << output_module.value();
    return false;
  }

  result = core::CompareFilePaths(*input_pdb, *output_pdb);
  if (result == core::kEquivalentFilePaths) {
    LOG(ERROR) << "Input and output PDB paths are equivalent.";
    LOG(ERROR) << "Input PDB path: " << input_pdb->value();
    LOG(ERROR) << "Output PDB path: " << output_pdb->value();
    return false;
  }

  result = core::CompareFilePaths(output_module, *output_pdb);
  if (result == core::kEquivalentFilePaths) {
    LOG(ERROR) << "Output module and PDB paths are equivalent.";
    LOG(ERROR) << "Output module path: " << output_module.value();
    LOG(ERROR) << "Output PDB path: " << output_pdb->value();
    return false;
  }

  return true;
}

bool FinalizeBlockGraph(const base::FilePath& input_module,
                        const base::FilePath& output_pdb,
                        const GUID& pdb_guid,
                        bool add_metadata,
                        const PETransformPolicy* policy,
                        BlockGraph* block_graph,
                        BlockGraph::Block* dos_header_block) {
  DCHECK_NE(reinterpret_cast<PETransformPolicy*>(NULL), policy);
  DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), dos_header_block);
  LOG(INFO) << "Finalizing block-graph for \"" << input_module.value() << "\".";

  std::vector<BlockGraphTransformInterface*> post_transforms;
  pe::transforms::AddMetadataTransform add_metadata_tx(input_module);
  pe::transforms::AddPdbInfoTransform add_pdb_info_tx(output_pdb, 1,
                                                      pdb_guid);
  pe::transforms::PERemoveEmptySectionsTransform remove_empty_sections;
  pe::transforms::PEPrepareHeadersTransform prep_headers_tx;

  if (add_metadata)
    post_transforms.push_back(&add_metadata_tx);
  post_transforms.push_back(&add_pdb_info_tx);
  post_transforms.push_back(&remove_empty_sections);
  post_transforms.push_back(&prep_headers_tx);

  if (!block_graph::ApplyBlockGraphTransforms(post_transforms,
                                              policy,
                                              block_graph,
                                              dos_header_block)) {
    return false;
  }

  return true;
}

bool FinalizeOrderedBlockGraph(
    OrderedBlockGraph* ordered_block_graph,
    BlockGraph::Block* dos_header_block) {
  DCHECK_NE(reinterpret_cast<OrderedBlockGraph*>(NULL), ordered_block_graph);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), dos_header_block);
  pe::orderers::PEOrderer pe_orderer;
  if (!pe_orderer.OrderBlockGraph(ordered_block_graph, dos_header_block))
    return false;
  return true;
}

bool BuildImageLayout(size_t padding,
                      size_t code_alignment,
                      const OrderedBlockGraph& ordered_block_graph,
                      BlockGraph::Block* dos_header_block,
                      ImageLayout* image_layout) {
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), dos_header_block);
  DCHECK_NE(reinterpret_cast<ImageLayout*>(NULL), image_layout);

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

void GetOmapRange(const std::vector<ImageLayout::SectionInfo>& sections,
                  RelativeAddressRange* range) {
  DCHECK_NE(reinterpret_cast<RelativeAddressRange*>(NULL), range);

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

bool FinalizePdbFile(const base::FilePath input_module,
                     const base::FilePath output_module,
                     const RelativeAddressRange input_range,
                     const ImageLayout& image_layout,
                     const GUID& guid,
                     bool augment_pdb,
                     bool strip_strings,
                     bool compress_pdb,
                     pdb::PdbFile* pdb_file) {
  DCHECK(pdb_file != NULL);

  LOG(INFO) << "Finalizing PDB file.";

  VLOG(1) << "Updating GUID.";
  if (!pdb::SetGuid(guid, pdb_file)) {
    LOG(ERROR) << "Unable to set PDB GUID.";
    return false;
  }

  VLOG(1) << "Building OMAP vectors.";
  std::vector<OMAP> omap_to, omap_from;
  BuildOmapVectors(input_range, image_layout, &omap_to, &omap_from);

  VLOG(1) << "Writing OMAP vectors.";
  if (!pdb::SetOmapToStream(omap_to, pdb_file)) {
    LOG(ERROR) << "Unable to set OMAP_TO.";
    return false;
  }
  if (!pdb::SetOmapFromStream(omap_from, pdb_file)) {
    LOG(ERROR) << "Unable to set OMAP_FROM.";
    return false;
  }

  // Parse the header and named streams.
  pdb::PdbInfoHeader70 header = {};
  pdb::NameStreamMap name_stream_map;
  if (!pdb::ReadHeaderInfoStream(*pdb_file, &header, &name_stream_map))
    return false;

  // Update/create the Syzygy history stream.
  VLOG(1) << "Adding history stream to PDB.";
  if (!WriteSyzygyHistoryStream(input_module, &name_stream_map, pdb_file))
    return false;

  // Add redecomposition data in another stream, only if augment_pdb_ is set.
  if (augment_pdb) {
    PEFile new_pe_file;
    if (!new_pe_file.Init(output_module)) {
      LOG(ERROR) << "Failed to read newly written PE file.";
      return false;
    }

    VLOG(1) << "Adding serialized block-graph stream to PDB.";
    if (!WriteSyzygyBlockGraphStream(new_pe_file,
                                     image_layout,
                                     strip_strings,
                                     compress_pdb,
                                     &name_stream_map,
                                     pdb_file)) {
      return false;
    }
  }

  // Write the updated name-stream map back to the header info stream.
  VLOG(1) << "Updating PDB headers.";
  if (!pdb::WriteHeaderInfoStream(header, name_stream_map, pdb_file))
    return false;

  // Stream 0 contains a copy of the previous PDB's directory. This, combined
  // with copy-on-write semantics of individual blocks makes the file contain
  // its whole edit history. Since we're writing a 'new' PDB file (we reset the
  // GUID and age), we have no history so can safely throw away this stream.
  VLOG(1) << "Removing previous PDB directory stream.";
  pdb_file->ReplaceStream(0, NULL);

  return true;
}

}  // namespace pe
