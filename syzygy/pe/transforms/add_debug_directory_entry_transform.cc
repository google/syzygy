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

#include "syzygy/pe/transforms/add_debug_directory_entry_transform.h"

#include "syzygy/block_graph/typed_block.h"
#include "syzygy/pe/pe_utils.h"

namespace pe {
namespace transforms {

using block_graph::TypedBlock;

typedef TypedBlock<IMAGE_DOS_HEADER> DosHeader;
typedef TypedBlock<IMAGE_NT_HEADERS> NtHeaders;
typedef TypedBlock<IMAGE_DEBUG_DIRECTORY> ImageDebugDirectory;

const char AddDebugDirectoryEntryTransform::kTransformName[] =
    "AddDebugDirectoryEntryTransform";

bool AddDebugDirectoryEntryTransform::TransformBlockGraph(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* dos_header_block) {
  DCHECK_NE(reinterpret_cast<TransformPolicyInterface*>(NULL), policy);
  DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), dos_header_block);
  DCHECK_EQ(BlockGraph::PE_IMAGE, block_graph->image_format());

  added_ = false;
  block_ = NULL;
  offset_ = -1;

  DosHeader dos_header;
  NtHeaders nt_headers;
  if (!dos_header.Init(0, dos_header_block) ||
      !dos_header.Dereference(dos_header->e_lfanew, &nt_headers)) {
    LOG(ERROR) << "Unable to dereference PE image headers.";
    return false;
  }

  // Don't have a debug directory? Then make one with a single entry.
  // In general, keeping around a reference to data inside a TypedBlock is not
  // safe, as if the data is resized the reference will no longer be valid.
  // However, I do not modify the underlying block for the lifetime of this
  // function, hence reusing this reference is safe.
  IMAGE_DATA_DIRECTORY& debug_dir_info =
      nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
  if (!nt_headers.HasReference(debug_dir_info.VirtualAddress)) {
    debug_dir_info.Size = sizeof(IMAGE_DEBUG_DIRECTORY);

    BlockGraph::Section* section = block_graph->FindOrAddSection(
        kReadOnlyDataSectionName, kReadOnlyDataCharacteristics);
    DCHECK(section != NULL);

    BlockGraph::Block* debug_dir_block = block_graph->AddBlock(
        BlockGraph::DATA_BLOCK, debug_dir_info.Size, "Debug Directory");
    DCHECK(debug_dir_block != NULL);
    debug_dir_block->set_section(section->id());
    debug_dir_block->AllocateData(debug_dir_info.Size);

    nt_headers.SetReference(BlockGraph::RELATIVE_REF,
                            debug_dir_info.VirtualAddress,
                            debug_dir_block,
                            0, 0);

    added_ = true;
  }

  // Get the debug directory, and remember it for post-transform.
  ImageDebugDirectory debug_dir;
  if (!nt_headers.Dereference(debug_dir_info.VirtualAddress, &debug_dir)) {
      LOG(ERROR) << "Unable to dereference ImageDebugDirectory.";
      return false;
  }
  block_ = debug_dir.block();

  // Did we already add an entry? Initialize it and be done with it. This can
  // happen if there was no debug directory to begin with.
  if (added_) {
    offset_ = 0;
    debug_dir->Type = type_;
    return true;
  }

  // If we get here we've got a non-empty debug data directory with entries
  // that we did not make. We either have to find an existing entry or create
  // a new one.

  // If we're not explicitly adding another entry, look for an existing one
  // with the matching type.
  if (!always_add_) {
    for (size_t i = 0; i < debug_dir.ElementCount(); ++i) {
      if (debug_dir[i].Type == type_) {
        offset_ = debug_dir.OffsetOf(debug_dir[i]);
        break;
      }
    }
  }

  // If we found an existing entry we're done.
  if (offset_ != -1)
    return true;

  // Make the new entry and initialize it. We only set the type as the rest of
  // it is already going to be initialized with zeros.
  added_ = true;
  size_t entry_index = debug_dir.ElementCount();
  size_t entry_size = sizeof(IMAGE_DEBUG_DIRECTORY);
  offset_ = debug_dir.offset() +
      entry_index * entry_size;
  debug_dir.block()->InsertData(offset_, entry_size, true);
  DCHECK_EQ(entry_index + 1, debug_dir.ElementCount());
  debug_dir[entry_index].Type = type_;

  // Update the debug directory info struct.
  debug_dir_info.Size += entry_size;

  return true;
}

}  // namespace transforms
}  // namespace pe
