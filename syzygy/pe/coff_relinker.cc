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

#include "syzygy/pe/coff_relinker.h"

#include "base/file_util.h"
#include "syzygy/pe/coff_decomposer.h"
#include "syzygy/pe/coff_file_writer.h"
#include "syzygy/pe/coff_image_layout_builder.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/transforms/coff_convert_legacy_code_references_transform.h"
#include "syzygy/pe/transforms/coff_prepare_headers_transform.h"

namespace pe {

namespace {

using block_graph::ApplyBlockGraphTransform;
using block_graph::BlockGraph;
using block_graph::OrderedBlockGraph;
using core::RelativeAddress;

typedef block_graph::BlockGraphOrdererInterface Orderer;
typedef block_graph::BlockGraphTransformInterface Transform;

// Decompose @p image_file into @p image_layout.
//
// @param image_file the COFF file to decompose.
// @param image_layout the layout to fill with the results.
// @param headers_block where to place the headers block pointer.
// @returns true on success, or false on failure.
bool Decompose(const CoffFile& image_file,
               ImageLayout* image_layout,
               BlockGraph::Block** headers_block) {
  DCHECK(image_layout != NULL);
  DCHECK(headers_block != NULL);

  LOG(INFO) << "Decomposing module: " << image_file.path().value() << ".";

  BlockGraph* block_graph = image_layout->blocks.graph();

  // Decompose the input image.
  CoffDecomposer decomposer(image_file);
  if (!decomposer.Decompose(image_layout)) {
    LOG(ERROR) << "Unable to decompose module: "
               << image_file.path().value() << ".";
    return false;
  }

  // Get the headers block.
  *headers_block = image_layout->blocks.GetBlockByAddress(RelativeAddress(0));
  if (*headers_block == NULL) {
    LOG(ERROR) << "Unable to find the headers block.";
    return false;
  }

  return true;
}

// Build an image layout from an ordered block graph.
//
// @param ordered_graph the ordered block graph to lay out.
// @param headers_block the headers block in @p ordered_graph.
// @param image_layout the image layout to fill with the results.
// @returns true on success, or false on failure.
bool BuildImageLayout(const OrderedBlockGraph& ordered_graph,
                      BlockGraph::Block* headers_block,
                      ImageLayout* image_layout) {
  DCHECK(headers_block != NULL);
  DCHECK(image_layout != NULL);

  LOG(INFO) << "Building image layout.";

  CoffImageLayoutBuilder builder(image_layout);
  if (!builder.LayoutImage(ordered_graph)) {
    LOG(ERROR) << "Image layout failed.";
    return false;
  }

  return true;
}

// Write an image layout to disk.
//
// @param image_layout the image layout.
// @param output_path the path to which the result is written.
// @returns true on success, or false on failure.
bool WriteImage(const ImageLayout& image_layout,
                const base::FilePath& output_path) {
  CoffFileWriter writer(&image_layout);

  LOG(INFO) << "Writing image to file: " << output_path.value() << ".";
  if (!writer.WriteImage(output_path)) {
    LOG(ERROR) << "Failed to write image: " << output_path.value() << ".";
    return false;
  }

  return true;
}

}  // namespace

CoffRelinker::CoffRelinker(const CoffTransformPolicy* transform_policy)
    : PECoffRelinker(transform_policy) {
}

bool CoffRelinker::Init() {
  DCHECK(inited_ == false);

  // Initialize the paths.
  if (!CheckPaths())
    return false;

  LOG(INFO) << "Input module: " << input_path_.value() << ".";
  LOG(INFO) << "Output module: " << output_path_.value() << ".";

  // Open the input PE file.
  if (!input_image_file_.Init(input_path_)) {
    LOG(ERROR) << "Unable to load input image: " << input_path_.value() << ".";
    return false;
  }

  // Decompose the image.
  if (!Decompose(input_image_file_, &input_image_layout_, &headers_block_))
    return false;

  inited_ = true;

  return true;
}

bool CoffRelinker::Relink() {
  if (!inited_) {
    LOG(ERROR) << "Init() has not been successfully called.";
    return false;
  }

  if (!ApplyUserTransforms())
    return false;

  // We apply the extra prepare headers transform. This ensures that the
  // header block is properly sized to receive layout information
  // post-ordering.
  //
  // TODO(chrisha): Remove CoffConvertLegacyCodeReferencesTransform when the
  //     basic block assembler is made fully COFF-compatible.
  pe::transforms::CoffConvertLegacyCodeReferencesTransform fix_refs_tx;
  pe::transforms::CoffPrepareHeadersTransform prep_headers_tx;
  std::vector<Transform*> post_transforms;
  post_transforms.push_back(&fix_refs_tx);
  post_transforms.push_back(&prep_headers_tx);
  if (!block_graph::ApplyBlockGraphTransforms(
           post_transforms, transform_policy_, &block_graph_, headers_block_)) {
    return false;
  }

  OrderedBlockGraph ordered_graph(&block_graph_);
  if (!ApplyUserOrderers(&ordered_graph))
    return false;

  // Lay it out.
  ImageLayout output_image_layout(&block_graph_);
  if (!BuildImageLayout(ordered_graph, headers_block_,
                        &output_image_layout)) {
    return false;
  }

  // Write the image.
  if (!WriteImage(output_image_layout, output_path_))
    return false;

  return true;
}

bool CoffRelinker::CheckPaths() {
  // At a very minimum we have to specify input and output.
  if (input_path_.empty() || output_path_.empty()) {
    LOG(ERROR) << "Input path and output path must be set and non-empty.";
    return false;
  }

  if (!file_util::PathExists(input_path_)) {
    LOG(ERROR) << "Input file not found: " << input_path_.value() << ".";
    return false;
  }

  // Ensure we aren't about to overwrite anything we don't want to. We do this
  // early on so that we abort before decomposition, transformation, etc.
  if (!allow_overwrite_) {
    if (file_util::PathExists(output_path_)) {
      LOG(ERROR) << "Output file already exists: "
                 << output_path_.value() << ".";
      return false;
    }
  }

  return true;
}

}  // namespace pe
