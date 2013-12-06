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
#include "syzygy/pdb/pdb_byte_stream.h"
#include "syzygy/pdb/pdb_file.h"
#include "syzygy/pdb/pdb_reader.h"
#include "syzygy/pdb/pdb_util.h"
#include "syzygy/pdb/pdb_writer.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/metadata.h"
#include "syzygy/pe/new_decomposer.h"
#include "syzygy/pe/pdb_info.h"
#include "syzygy/pe/pe_file_writer.h"
#include "syzygy/pe/pe_relinker_util.h"
#include "syzygy/pe/serialization.h"

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

}  // namespace

PERelinker::PERelinker(const PETransformPolicy* pe_transform_policy)
    : PECoffRelinker(pe_transform_policy),
      pe_transform_policy_(pe_transform_policy),
      add_metadata_(true), augment_pdb_(true),
      compress_pdb_(false), strip_strings_(false), use_new_decomposer_(false),
      padding_(0), code_alignment_(1), output_guid_(GUID_NULL) {
  DCHECK(pe_transform_policy != NULL);
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
  DCHECK(!inited_);

  // Initialize the paths.
  if (!ValidateAndInferPaths(input_path_, output_path_, allow_overwrite_,
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

  // Apply the user supplied transforms.
  if (!ApplyUserTransforms())
    return false;

  // Finalize the block-graph. This applies PE and Syzygy specific transforms.
  if (!FinalizeBlockGraph(input_path_, output_pdb_path_, output_guid_,
                          add_metadata_, pe_transform_policy_, &block_graph_,
                          headers_block_)) {
    return false;
  }

  // Apply the user supplied orderers.
  OrderedBlockGraph ordered_block_graph(&block_graph_);
  if (!ApplyUserOrderers(&ordered_block_graph))
    return false;

  // Finalize the ordered block graph. This applies PE specific orderers.
  if (!FinalizeOrderedBlockGraph(&ordered_block_graph, headers_block_))
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

  // Apply any user specified mutators to the PDB file.
  if (!pdb::ApplyPdbMutators(pdb_mutators_, &pdb_file))
    return false;

  // Finalize the PDB file.
  RelativeAddressRange input_range;
  GetOmapRange(input_image_layout_.sections, &input_range);
  if (!FinalizePdbFile(input_path_, output_path_, input_range,
                       output_image_layout, output_guid_, augment_pdb_,
                       strip_strings_, compress_pdb_, &pdb_file)) {
    return false;
  }

  // Write the PDB file.
  pdb::PdbWriter pdb_writer;
  if (!pdb_writer.Write(output_pdb_path_, pdb_file)) {
    LOG(ERROR) << "Failed to write PDB file \"" << output_pdb_path_.value()
               << "\".";
    return false;
  }

  return true;
}

}  // namespace pe
