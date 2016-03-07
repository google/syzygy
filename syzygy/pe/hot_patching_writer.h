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
//
// The HotPatchingWriter allocates executable memory pages and writes blocks
// into this memory area, where they can be executed.
//
// First the |Init| function must be called. This allocates a new executable
// virtual memory of a given size using VirtualAlloc.
//
// The |Write| function can be used to write a block into this memory area.
// It does the following:
// - Copies the block data into the executable virtual memory.
// - Changes the data of the block to point into the new location (the block
//     will not own the data)
// - Finalizes the bytes of inter-block references in the block data.
//
// NOTE: To write a block with this class, the |data| of all referred blocks
//     must be backed by executable memory: they must be either blocks
//     decomposed by the hot patching decomposer or blocks already written by
//     the writer. The reason for this restriction is because the references
//     will be calculated using the |data| pointers of the blocks.
// TODO(cseri): The precondition is currently not checked. We could introduce
//     a new flag for in-memory executable blocks.
//
// TODO(cseri): Implement some page protection logic, the write permission
//     should be removed after the writes are finished.
// TODO(cseri): Consider freeing the allocated virtual memory in destructor.

#ifndef SYZYGY_PE_HOT_PATCHING_WRITER_H_
#define SYZYGY_PE_HOT_PATCHING_WRITER_H_

#include "syzygy/block_graph/block_graph.h"

namespace pe {

class HotPatchingWriter {
 public:
  typedef block_graph::BlockGraph BlockGraph;
  typedef void* FunctionPointer;

  HotPatchingWriter();
  ~HotPatchingWriter();

  // Queries how much of the virtual memory of the writer has used so far.
  // @returns the size of the written code, in bytes.
  size_t GetUsedMemory() const;

  // Allocates an executable virtual page with a given size that will be used to
  // write the code into.
  // @param virtual_memory_size The size of the requested virtual memory, in
  //    bytes.
  bool Init(size_t virtual_memory_size);

  // Writes a block into the executable memory.
  // @param block The block to write.
  // @returns A pointer to the written function on success, nullptr if there was
  //     not enough space to write the function.
  // @pre |Init| must be called before a call to this function.
  FunctionPointer Write(BlockGraph::Block* block);

  // Returns the size of the allocated virtual memory. Valid after the |Init|
  // function is called.
  // @returns the size of the virtual memory, in bytes.
  size_t virtual_memory_size() const {
    return virtual_memory_size_;
  }

 protected:
  // The pointer to the virtual memory.
  LPVOID virtual_memory_;

  // The size of the allocated virtual memory. Valid after the |Init| function
  // is called.
  size_t virtual_memory_size_;

  // The pointer to the current position in the virtual memory.
  uint8_t* virtual_memory_cursor_;

 private:
  DISALLOW_COPY_AND_ASSIGN(HotPatchingWriter);
};

}  // namespace pe

#endif  // SYZYGY_PE_HOT_PATCHING_WRITER_H_
