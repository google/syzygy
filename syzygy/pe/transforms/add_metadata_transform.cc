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

#include "syzygy/pe/transforms/add_metadata_transform.h"

#include "syzygy/block_graph/typed_block.h"
#include "syzygy/common/defs.h"
#include "syzygy/pe/metadata.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/pe/pe_utils.h"

namespace pe {
namespace transforms {

const char AddMetadataTransform::kTransformName[] =
    "AddMetadataTransform";

AddMetadataTransform::AddMetadataTransform(const base::FilePath& module_path)
    : module_path_(module_path) {
}

bool AddMetadataTransform::TransformBlockGraph(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* /*dos_header_block*/) {
  DCHECK_NE(reinterpret_cast<TransformPolicyInterface*>(NULL), policy);
  DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);
  DCHECK_EQ(BlockGraph::PE_IMAGE, block_graph->image_format());

  metadata_block_ = NULL;

  pe::PEFile pe_file;
  if (!pe_file.Init(module_path_)) {
    LOG(ERROR) << "Unable to initialize PEFile for module \""
               << module_path_.value() << "\".";
    return false;
  }

  pe::PEFile::Signature pe_signature;
  pe_file.GetSignature(&pe_signature);

  pe::Metadata metadata;
  if (!metadata.Init(pe_signature)) {
    LOG(ERROR) << "Unable to initialize metadata.";
    return false;
  }

  const BlockGraph::Section* section = NULL;
  BlockGraph::Block* block = NULL;

  // Look for the section.
  section = block_graph->FindSection(common::kSyzygyMetadataSectionName);

  // If we found the section then look for the block.
  if (section != NULL) {
    BlockGraph::BlockMap::iterator block_it =
        block_graph->blocks_mutable().begin();
    for (; block_it != block_graph->blocks_mutable().end(); ++block_it) {
      if (block_it->second.section() == section->id()) {
        // We reuse the first metadata block we find, but we shouldn't find
        // any others.
        if (block != NULL) {
          LOG(ERROR) << "Found multiple metadata blocks.";
          return false;
        }
        block = &block_it->second;
      }
    }
  } else {
    // Otherwise, create the section.
    section = block_graph->AddSection(common::kSyzygyMetadataSectionName,
                                      kReadOnlyDataCharacteristics);
    DCHECK(section != NULL);
  }

  // If no block was found, create one.
  if (block == NULL) {
    block = block_graph->AddBlock(BlockGraph::DATA_BLOCK, 0, "Metadata");
    block->set_section(section->id());
  }
  DCHECK(block != NULL);

  // Fill in the metadata block.
  if (!metadata.SaveToBlock(block)) {
    LOG(ERROR) << "Unable to create metadata block.";
    return false;
  }

  metadata_block_ = block;

  return true;
}

}  // namespace transforms
}  // namespace pe
