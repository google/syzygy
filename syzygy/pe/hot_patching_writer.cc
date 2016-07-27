// Copyright 2015 Google Inc. All Rights Reserved.
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

#include "syzygy/pe/hot_patching_writer.h"

namespace pe {

namespace {

using block_graph::BlockGraph;

// Finalizes the references in a block that has been copied to executable
// memory. This will go through all references of the block and writes the final
// absolute of PC-relative address to the block at the offset of the reference.
// @param block The block whose references should be finalized.
// @pre This assumes that the data of the block has been laid out to its final
//     address. Also, all referred blocks must be backed up by in-memory
//     executable data.
void FinalizeReferences(BlockGraph::Block* block) {
  DCHECK_NE(static_cast<BlockGraph::Block*>(nullptr), block);

  using block_graph::BlockGraph;
  typedef BlockGraph::Offset Offset;

  // Loop through the references and update them in the laid out block.
  for (auto entry : block->references()) {
    Offset offset = entry.first;
    const BlockGraph::Reference& ref = entry.second;

    // We are going to write the new value to this memory address.
    uint8_t* src_addr = const_cast<uint8_t*>(block->data()) + offset;
    DCHECK(src_addr >= block->data());
    DCHECK(src_addr < block->data() + block->data_size() - ref.size() + 1);

    // We only support direct references. This is enough for now, because the
    // hot patching decomposer does not emit indirect references.
    DCHECK(ref.IsDirect());

    // Calculate the value that we need to write.
    uintptr_t value = 0;
    switch (ref.type()) {
      case BlockGraph::ABSOLUTE_REF: {
        value = reinterpret_cast<uintptr_t>(
            ref.referenced()->data() + ref.offset());
        break;
      }
      case BlockGraph::PC_RELATIVE_REF: {
        // PC-relative references are always the last operand of an instruction
        // and expressed relative to the first byte after the instruction
        // (hence after the reference).
        value = (ref.referenced()->data() + ref.offset()) -
            (block->data() + offset + ref.size());
        break;
      }
      default:
        NOTREACHED();
    }

    // Now store the new value.
    switch (ref.size()) {
      case sizeof(uint8_t): {
        *reinterpret_cast<uint8_t*>(src_addr) = static_cast<uint8_t>(value);
        break;
      }
      case sizeof(uint16_t): {
        *reinterpret_cast<uint16_t*>(src_addr) = static_cast<uint16_t>(value);
        break;
      }
      case sizeof(uint32_t): {
        *reinterpret_cast<uint32_t*>(src_addr) = static_cast<uint32_t>(value);
        break;
      }
      default:
        NOTREACHED();
    }
  }
}

}  // namespace

HotPatchingWriter::HotPatchingWriter() :
    virtual_memory_(nullptr),
    virtual_memory_size_(0),
    virtual_memory_cursor_(nullptr) {
}

HotPatchingWriter::~HotPatchingWriter() {
}

size_t HotPatchingWriter::GetUsedMemory() const {
  return virtual_memory_cursor_ - reinterpret_cast<uint8_t*>(virtual_memory_);
}

bool HotPatchingWriter::Init(size_t virtual_memory_size) {
  // Allocate virtual memory.
  virtual_memory_ = ::VirtualAlloc(nullptr,
                                   virtual_memory_size,
                                   MEM_COMMIT,
                                   PAGE_EXECUTE_READWRITE);
  if (virtual_memory_ == nullptr) {
    LOG(ERROR) << "Could not allocate virtual memory for hot patching writer.";
    return false;
  }

  // Set up members.
  virtual_memory_cursor_ = static_cast<uint8_t*>(virtual_memory_);
  virtual_memory_size_ = virtual_memory_size;

  return true;
}

HotPatchingWriter::FunctionPointer HotPatchingWriter::Write(
    BlockGraph::Block* block) {
  DCHECK_NE(static_cast<BlockGraph::Block*>(nullptr), block);

  // Respect block padding.
  uint8_t* block_location = virtual_memory_cursor_ + block->padding_before();

  // Respect block alignment.
  block_location = reinterpret_cast<uint8_t*>(common::AlignUp(
      reinterpret_cast<size_t>(block_location), block->alignment()));

  // Check if we fit into the allocated memory.
  if (!(block_location + block->size() <
        static_cast<uint8_t*>(virtual_memory_) + virtual_memory_size_)) {
    return false;
  }

  // Move the virtual memory cursor ahead.
  virtual_memory_cursor_ = block_location + block->size();

  // Copy the contents of the new block to the virtual memory.
  ::memcpy(block_location, block->data(), block->data_size());

  // Set block data to the final location!
  block->SetData(block_location, block->data_size());

  // Update the bytes of the references to their final value.
  FinalizeReferences(block);

  return reinterpret_cast<FunctionPointer>(block_location);
}

}  // namespace pe
