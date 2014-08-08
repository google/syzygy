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

#include "syzygy/pe/transforms/add_pdb_info_transform.h"

#include "base/file_util.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "base/time/time.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/pe/pe_data.h"
#include "syzygy/pe/transforms/add_debug_directory_entry_transform.h"

namespace pe {
namespace transforms {

using block_graph::TypedBlock;

typedef TypedBlock<IMAGE_DEBUG_DIRECTORY> ImageDebugDirectory;
typedef TypedBlock<CvInfoPdb70> CvInfoPdb;

const char AddPdbInfoTransform::kTransformName[] =
    "AddPdbInfoTransform";

bool AddPdbInfoTransform::TransformBlockGraph(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* dos_header_block) {
  DCHECK_NE(reinterpret_cast<TransformPolicyInterface*>(NULL), policy);
  DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), dos_header_block);
  DCHECK_EQ(BlockGraph::PE_IMAGE, block_graph->image_format());

  // Make sure the PDB path is absolute.
  pdb_path_ = base::MakeAbsoluteFilePath(pdb_path_);
  if (pdb_path_.empty()) {
    LOG(ERROR) << "Unable to get absolute PDB path.";
    return false;
  }

  // Find or create the appropriate debug directory entry.
  AddDebugDirectoryEntryTransform debug_dir_tx(IMAGE_DEBUG_TYPE_CODEVIEW,
                                               false);
  if (!block_graph::ApplyBlockGraphTransform(
          &debug_dir_tx, policy, block_graph, dos_header_block)) {
    LOG(ERROR) << debug_dir_tx.name() << " failed.";
    return false;
  }

  ImageDebugDirectory debug_dir;
  if (!debug_dir.Init(debug_dir_tx.offset(), debug_dir_tx.block())) {
    LOG(ERROR) << "Unable to cast IMAGE_DEBUG_DIRECTORY.";
    return false;
  }

  // Get the path to the PDB in UTF8.
  std::string new_pdb_path;
  if (!base::WideToUTF8(pdb_path_.value().c_str(), pdb_path_.value().size(),
                        &new_pdb_path)) {
    LOG(ERROR) << "Unable to convert PDB path to UTF8.";
    return false;
  }

  // Calculate the size of the updated debug info struct. The size of the
  // struct includes the trailing zero of the path.
  size_t new_debug_info_size = sizeof(pe::CvInfoPdb70) + new_pdb_path.size();

  // If the debug directory entry is empty, then create a new CvInfoPdb
  // block.
  if (!debug_dir.HasReference(debug_dir->AddressOfRawData)) {
    BlockGraph::Block* cv_info_pdb_block = block_graph->AddBlock(
        BlockGraph::DATA_BLOCK, new_debug_info_size, "PDB Info");
    DCHECK(cv_info_pdb_block != NULL);
    cv_info_pdb_block->set_section(debug_dir.block()->section());
    cv_info_pdb_block->set_attribute(BlockGraph::PE_PARSED);
    if (cv_info_pdb_block->AllocateData(new_debug_info_size) == NULL) {
      LOG(ERROR) << "Failed to allocate block data.";
      return false;
    }

    debug_dir.SetReference(BlockGraph::RELATIVE_REF,
                           debug_dir->AddressOfRawData,
                           cv_info_pdb_block,
                           0, 0);
    debug_dir.SetReference(BlockGraph::FILE_OFFSET_REF,
                           debug_dir->PointerToRawData,
                           cv_info_pdb_block,
                           0, 0);

    // The type is set by the AddDebugDirectoryEntry transform, and everything
    // else is zero initialized. We only need to set the size so that the
    // following dereference works.
    debug_dir->SizeOfData = new_debug_info_size;
  }

  CvInfoPdb cv_info_pdb;
  if (!debug_dir.DereferenceWithSize(debug_dir->AddressOfRawData,
                                     debug_dir->SizeOfData,
                                     &cv_info_pdb)) {
    LOG(ERROR) << "Failed to dereference CvInfoPdb.";
    return false;
  }

  // Update the debug directory.
  debug_dir->TimeDateStamp = static_cast<uint32>(time(NULL));
  debug_dir->SizeOfData = new_debug_info_size;

  // Resize the debug info struct while patching up its metadata.
  if (!cv_info_pdb.block()->InsertOrRemoveData(cv_info_pdb.offset(),
                                               cv_info_pdb.size(),
                                               new_debug_info_size,
                                               true)) {
    LOG(ERROR) << "InsertOrRemoveData failed.";
    return false;
  }

#ifndef NDEBUG
  // We need to reinit cv_info_pdb as the data may have been reallocated and
  // in that case the debug object is not up to date. This just makes the
  // following code more easily debuggable.
  if (!cv_info_pdb.InitWithSize(cv_info_pdb.offset(),
                                new_debug_info_size,
                                cv_info_pdb.block())) {
    LOG(ERROR) << "Failed to reinitialize CvInfoPdb.";
    return false;
  }
#endif  // NDEBUG

  // Fill in the debug info structure.
  cv_info_pdb->cv_signature = pe::kPdb70Signature;
  cv_info_pdb->pdb_age = pdb_age_;
  cv_info_pdb->signature = pdb_guid_;
  base::strlcpy(cv_info_pdb->pdb_file_name,
                new_pdb_path.c_str(),
                new_pdb_path.size() + 1);

  return true;
}

}  // namespace transforms
}  // namespace pe
