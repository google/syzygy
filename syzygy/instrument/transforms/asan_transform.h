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
//
// Implementation of the SyzyAsan instrumentation transform.

#ifndef SYZYGY_INSTRUMENT_TRANSFORMS_ASAN_TRANSFORM_H_
#define SYZYGY_INSTRUMENT_TRANSFORMS_ASAN_TRANSFORM_H_

#include <set>
#include <string>
#include <utility>

#include "base/string_piece.h"
#include "syzygy/block_graph/iterate.h"
#include "syzygy/block_graph/transforms/iterative_transform.h"
#include "syzygy/block_graph/transforms/named_transform.h"

namespace instrument {
namespace transforms {

// This class implements the transformation applied to each basic block.
class AsanBasicBlockTransform
    : public block_graph::transforms::NamedBasicBlockSubGraphTransformImpl<
          AsanBasicBlockTransform> {
 public:
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::BasicBlockSubGraph BasicBlockSubGraph;

  // Constructor.
  // @param hook_write a reference to the hook to call when we found a write
  //     access to the memory.
  // @param hook_read a reference to the hook to call when we found a read
  //     access to the memory.
  AsanBasicBlockTransform(BlockGraph::Reference* hook_write,
                          BlockGraph::Reference* hook_read) :
      hook_write_(hook_write),
      hook_read_(hook_read) {
    DCHECK(hook_write != NULL);
    DCHECK(hook_read != NULL);
  }

  // The transform name.
  static const char kTransformName[];

 protected:
  // @name BasicBlockSubGraphTransformInterface method.
  virtual bool TransformBasicBlockSubGraph(BlockGraph* block_graph,
      BasicBlockSubGraph* basic_block_subgraph) OVERRIDE;

  // Instruments the memory accesses in a basic block.
  // @param basic_block The basic block to be instrumented.
  // @returns true on success, false otherwise.
  bool InstrumentBasicBlock(block_graph::BasicBlock* basic_block);

 private:
  // The references to the Asan hooks.
  BlockGraph::Reference* hook_write_;
  BlockGraph::Reference* hook_read_;

  DISALLOW_COPY_AND_ASSIGN(AsanBasicBlockTransform);
};

class AsanTransform
    : public block_graph::transforms::IterativeTransformImpl<AsanTransform> {
 public:
  typedef block_graph::BlockGraph BlockGraph;

  // Initialize a new AsanTransform instance.
  AsanTransform();

  // @name IterativeTransformImpl implementation.
  // @{
  bool PreBlockGraphIteration(BlockGraph* block_graph,
                              BlockGraph::Block* header_block);
  bool OnBlock(BlockGraph* block_graph, BlockGraph::Block* block);
  bool PostBlockGraphIteration(BlockGraph* block_graph,
                               BlockGraph::Block* header_block);
  // @}

  // @name Accessors.
  // @{
  void set_instrument_dll_name(const base::StringPiece& instrument_dll_name) {
    instrument_dll_name.CopyToString(&asan_dll_name_);
  }
  const char* instrument_dll_name() const {
    return asan_dll_name_.c_str();
  }
  // @}

  // The names of the imports for the Asan hooks.
  static const char kAsanHookWriteTestName[];
  static const char kAsanHookReadTestName[];

  // The name of the DLL that is imported by default.
  static const char kSyzyAsanDll[];

  // The transform name.
  static const char kTransformName[];

 protected:
  // Name of the asan_rtl DLL we import. Defaults to "asan_rtl.dll".
  std::string asan_dll_name_;

  // References to __asan_write_access import entry. Valid after successful
  // PreBlockGraphIteration.
  BlockGraph::Reference hook_asan_write_test_;

  // References to __asan_read_access import entry. Valid after successful
  // PreBlockGraphIteration.
  BlockGraph::Reference hook_asan_read_test_;

  DISALLOW_COPY_AND_ASSIGN(AsanTransform);
};

}  // namespace transforms
}  // namespace instrument

#endif  // SYZYGY_INSTRUMENT_TRANSFORMS_ASAN_TRANSFORM_H_
