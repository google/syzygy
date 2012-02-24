// Copyright 2012 Google Inc.
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
#include "syzygy/block_graph/orderers/original_orderer.h"
#include "syzygy/pdb/pdb_util.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/find.h"
#include "syzygy/pe/image_layout_builder.h"
#include "syzygy/pe/image_source_map.h"
#include "syzygy/pe/orderers/pe_orderer.h"
#include "syzygy/pe/pe_file_builder.h"
#include "syzygy/pe/pe_file_writer.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/pdb_info.h"
#include "syzygy/pe/transforms/add_metadata_transform.h"
#include "syzygy/pe/transforms/add_pdb_info_transform.h"
#include "syzygy/pe/transforms/prepare_headers_transform.h"

namespace pe {

namespace {

typedef block_graph::BlockGraphTransformInterface Transform;
typedef block_graph::BlockGraphOrdererInterface Orderer;

using block_graph::ApplyTransform;
using block_graph::BlockGraph;
using block_graph::OrderedBlockGraph;
using core::RelativeAddress;

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

// TODO(chrisha): Make this utility function part of orderer.h.
bool ApplyOrderer(Orderer* orderer,
                  OrderedBlockGraph* obg,
                  BlockGraph::Block* header_block) {
  DCHECK(orderer != NULL);
  DCHECK(obg != NULL);
  DCHECK(header_block != NULL);

  if (!orderer->Apply(obg, header_block)) {
    LOG(ERROR) << "Orderer failed: " << orderer->name();
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
bool InitializePaths(const FilePath& input_path,
                     const FilePath& output_path,
                     bool allow_overwrite,
                     FilePath* input_pdb_path,
                     FilePath* output_pdb_path) {
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
bool Decompose(const PEFile& pe_file,
               const FilePath& pdb_path,
               ImageLayout* image_layout,
               BlockGraph* bg,
               BlockGraph::Block** dos_header_block) {
  DCHECK(image_layout != NULL);
  DCHECK(bg != NULL);
  DCHECK(dos_header_block != NULL);

  LOG(INFO) << "Decomposing module: " << pe_file.path().value();

  // Decompose the input image.
  Decomposer decomposer(pe_file);
  decomposer.set_pdb_path(pdb_path);
  if (!decomposer.Decompose(image_layout)) {
    LOG(ERROR) << "Unable to decompose module: " << pe_file.path().value();
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

bool ApplyTransforms(const FilePath& input_path,
                     const FilePath& output_pdb_path,
                     const GUID& guid,
                     bool add_metadata,
                     std::vector<Transform*>* transforms,
                     BlockGraph* block_graph,
                     BlockGraph::Block* dos_header_block) {
  DCHECK(transforms != NULL);
  DCHECK(block_graph != NULL);
  DCHECK(dos_header_block != NULL);

  LOG(INFO) << "Transforming block graph.";

  std::vector<Transform*> local_transforms(*transforms);

  pe::transforms::AddMetadataTransform add_metadata_tx(input_path);
  pe::transforms::AddPdbInfoTransform add_pdb_info_tx(output_pdb_path, 0, guid);
  pe::transforms::PrepareHeadersTransform prep_headers_tx;

  if (add_metadata)
    local_transforms.push_back(&add_metadata_tx);
  local_transforms.push_back(&add_pdb_info_tx);
  local_transforms.push_back(&prep_headers_tx);

  // Apply the transforms.
  for (size_t i = 0; i < local_transforms.size(); ++i) {
    LOG(INFO) << "Applying transform: " << local_transforms[i]->name() << ".";
    // ApplyTransform takes care of verbosely logging any failures.
    if (!ApplyTransform(local_transforms[i], block_graph, dos_header_block))
      return false;
  }

  return true;
}

bool ApplyOrderers(std::vector<Orderer*>* orderers,
                   OrderedBlockGraph* obg,
                   BlockGraph::Block* dos_header_block) {
  DCHECK(orderers != NULL);
  DCHECK(obg != NULL);
  DCHECK(dos_header_block != NULL);

  LOG(INFO) << "Ordering block graph.";

  std::vector<Orderer*> local_orderers(*orderers);

  block_graph::orderers::OriginalOrderer orig_orderer;
  pe::orderers::PEOrderer pe_orderer;

  if (local_orderers.size() == 0) {
    LOG(INFO) << "No orderers specified, using original orderer.";
    local_orderers.push_back(&orig_orderer);
  }

  local_orderers.push_back(&pe_orderer);

  // Apply the orderers.
  for (size_t i = 0; i < local_orderers.size(); ++i) {
    LOG(INFO) << "Applying orderer: " << local_orderers[i]->name();
    if (!ApplyOrderer(local_orderers[i], obg, dos_header_block))
      return false;
  }

  return true;
}

// Lays out the image.
bool BuildImageLayout(size_t padding,
                      const OrderedBlockGraph& ordered_block_graph,
                      BlockGraph::Block* dos_header_block,
                      ImageLayout* image_layout) {
  DCHECK(dos_header_block != NULL);
  DCHECK(image_layout != NULL);

  LOG(INFO) << "Building image layout.";

  ImageLayoutBuilder builder(image_layout);
  builder.set_padding(padding);
  if (!builder.LayoutImageHeaders(dos_header_block)) {
    LOG(ERROR) << "ImageLayoutBuilder::LayoutImageHeaders failed.";
    return false;
  }

  if (!builder.LayoutOrderedBlockGraph(ordered_block_graph)) {
    LOG(ERROR) << "ImageLayoutBuilder::LayoutOrderedBlockGraph failed.";
    return false;
  }

  LOG(INFO) << "Finalizing image layout.";
  if (!builder.Finalize()) {
    LOG(ERROR) << "ImageLayoutBuilder::Finalize failed.";
    return false;
  }

  return true;
}

// Writes the image.
bool WriteImage(const ImageLayout& image_layout, const FilePath& output_path) {
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

// Write the PDB file. We take the pains to go through a temporary file so as
// to support rewriting an existing file.
bool WritePdbFile(const RelativeAddressRange input_range,
                  const ImageLayout& image_layout,
                  const GUID& guid,
                  const FilePath& input_pdb_path,
                  const FilePath& output_pdb_path) {
  std::vector<OMAP> omap_to, omap_from;
  BuildOmapVectors(input_range, image_layout, &omap_to, &omap_from);

  LOG(INFO) << "Writing PDB file: " << output_pdb_path.value();

  FilePath temp_pdb;
  if (!file_util::CreateTemporaryFileInDir(output_pdb_path.DirName(),
                                           &temp_pdb)) {
    LOG(ERROR) << "Unable to create temporary PDB file.";
    return false;
  }

  if (!pdb::AddOmapStreamToPdbFile(input_pdb_path,
                                   temp_pdb,
                                   guid,
                                   omap_to,
                                   omap_from)) {
    LOG(ERROR) << "Unable to add OMAP data to PDB.";
    file_util::Delete(temp_pdb, false);
    return false;
  }

  if (!file_util::ReplaceFile(temp_pdb, output_pdb_path)) {
    LOG(ERROR) << "Unable to write PDB file to \""
        << output_pdb_path.value() << "\".";
    file_util::Delete(temp_pdb, false);
    return false;
  }

  return true;
}

}  // namespace

PERelinker::PERelinker()
    : add_metadata_(true), allow_overwrite_(false), padding_(0),
      inited_(false), input_image_layout_(&block_graph_),
      dos_header_block_(NULL), output_guid_(GUID_NULL) {
}

void PERelinker::AppendTransform(Transform* transform) {
  DCHECK(transform != NULL);
  transforms_.push_back(transform);
}

void PERelinker::AppendTransforms(const std::vector<Transform*>& transforms) {
  transforms_.insert(transforms_.end(), transforms.begin(), transforms.end());
}

void PERelinker::AppendOrderer(Orderer* orderer) {
  DCHECK(orderer != NULL);
  orderers_.push_back(orderer);
}

void PERelinker::AppendOrderers(const std::vector<Orderer*>& orderers) {
  orderers_.insert(orderers_.end(), orderers.begin(), orderers.end());
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
  if (!Decompose(input_pe_file_, input_pdb_path_, &input_image_layout_,
                 &block_graph_, &dos_header_block_)) {
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

  // Transform it.
  if (!ApplyTransforms(input_path_, output_pdb_path_, output_guid_,
                       add_metadata_, &transforms_, &block_graph_,
                       dos_header_block_)) {
    return false;
  }

  // Order it.
  OrderedBlockGraph ordered_block_graph(&block_graph_);
  if (!ApplyOrderers(&orderers_, &ordered_block_graph, dos_header_block_))
    return false;

  // Lay it out.
  ImageLayout output_image_layout(&block_graph_);
  if (!BuildImageLayout(padding_, ordered_block_graph, dos_header_block_,
                        &output_image_layout)) {
    return false;
  }

  // Write the image.
  if (!WriteImage(output_image_layout, output_path_))
    return false;

  // Get the input range of the image. This is needed for writing the OMAPs.
  RelativeAddressRange input_range;
  GetOmapRange(input_image_layout_.sections, &input_range);

  // Write the PDB file.
  if (!WritePdbFile(input_range, output_image_layout, output_guid_,
                    input_pdb_path_, output_pdb_path_)) {
    return false;
  }

  return true;
}

}  // namespace pe
