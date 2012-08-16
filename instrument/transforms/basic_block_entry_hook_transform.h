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
// Implementation of the basic-block entry hook instrumentation transform.

#ifndef SYZYGY_INSTRUMENT_TRANSFORMS_BASIC_BLOCK_ENTRY_HOOK_TRANSFORM_H_
#define SYZYGY_INSTRUMENT_TRANSFORMS_BASIC_BLOCK_ENTRY_HOOK_TRANSFORM_H_

#include <string>
#include <vector>

#include "base/string_piece.h"
#include "syzygy/block_graph/basic_block_assembler.h"
#include "syzygy/block_graph/iterate.h"
#include "syzygy/block_graph/transforms/iterative_transform.h"
#include "syzygy/block_graph/transforms/named_transform.h"

namespace instrument {
namespace transforms {

// An iterative block transformation that augments the binary with an import
// for a basic-block entry-hook function and, for each code basic-block,
// prepends a call to the entry-hook function taking a unique basic-block ID.
// The entry-hook function is responsible for being non-disruptive to the
// the calling environment. I.e., it must preserve all volatile registers, any
// registers it uses, and the processor flags.
class BasicBlockEntryHookTransform
    : public block_graph::transforms::IterativeTransformImpl<
          BasicBlockEntryHookTransform>,
      public block_graph::transforms::NamedBasicBlockSubGraphTransformImpl<
          BasicBlockEntryHookTransform> {
 public:
  typedef block_graph::BasicBlock BasicBlock;
  typedef block_graph::BasicBlockSubGraph BasicBlockSubGraph;
  typedef block_graph::BlockGraph BlockGraph;
  typedef BlockGraph::Block Block;
  typedef BlockGraph::Offset Offset;
  typedef BlockGraph::Reference Reference;
  typedef std::vector<core::RelativeAddress> RelativeAddressVector;

  // Initialize a new BasicBlockEntryHookTransform instance using the default
  // module and function names.
  BasicBlockEntryHookTransform();

  // Initialize a new BasicBlockEntryHookTransform instance.
  // @param module_name The name of the module containing the basic-block
  //     entry-hook function.
  // @param function_name The name of basic-block entry-hook function.
  // @param id_generator The functor that will return a unique id for each
  //     basic-block in the image under transformation.
  BasicBlockEntryHookTransform(const base::StringPiece& module_name,
                               const base::StringPiece& function_name);

  const std::string& module_name() const { return module_name_; }
  void set_module_name(const base::StringPiece& value) {
    DCHECK(!value.empty());
    value.CopyToString(&module_name_);
  }

  const std::string& function_name() const { return function_name_; }
  void set_function_name(const base::StringPiece& value) {
    DCHECK(!value.empty());
    value.CopyToString(&function_name_);
  }

  // Get the entry-hook reference that was used to instrument each basic-block.
  // This will only be valid after a successful application of the transform.
  const Reference& bb_entry_hook_ref() const { return bb_entry_hook_ref_; }

  // Gen an id-to-address map for the basic-block entry-hook calls.
  // @returns the RVAs in the original image of the instrumented basic blocks.
  //    They are in the order in which they were encountered during
  //    instrumentation, such that the index of the BB in the vector serves
  //    as its unique ID.
  const RelativeAddressVector& bb_addresses() const { return bb_addresses_; }

  // The default module name to which to bind the instrumentation.
  static const char kDefaultModuleName[];

  // The default function name to which to bind the instrumentation.
  static const char kDefaultFunctionName[];

 protected:
  friend NamedBlockGraphTransformImpl<BasicBlockEntryHookTransform>;
  friend IterativeTransformImpl<BasicBlockEntryHookTransform>;
  friend NamedBasicBlockSubGraphTransformImpl<BasicBlockEntryHookTransform>;

  // @name IterativeTransformImpl implementation.
  // @{
  bool PreBlockGraphIteration(BlockGraph* block_graph,
                              BlockGraph::Block* header_block);
  bool OnBlock(BlockGraph* block_graph, BlockGraph::Block* block);
  // @}

  // @name BasicBlockSubGraphTransformInterface methods.
  // @{
  virtual bool TransformBasicBlockSubGraph(
      BlockGraph* block_graph,
      BasicBlockSubGraph* basic_block_subgraph) OVERRIDE;
  // @}

  // Name of the instrumentation DLL we import.
  std::string module_name_;

  // Name of the hook function (in module_name) to which we insert calls.
  std::string function_name_;

  // Stores the RVAs in the original image for each instrumented basic block.
  RelativeAddressVector bb_addresses_;

  // The entry hook to which basic-block entry events are directed.
  Reference bb_entry_hook_ref_;

  // The name of this transform.
  static const char kTransformName[];

  DISALLOW_COPY_AND_ASSIGN(BasicBlockEntryHookTransform);
};

}  // namespace transforms
}  // namespace instrument

#endif  // SYZYGY_INSTRUMENT_TRANSFORMS_BASIC_BLOCK_ENTRY_HOOK_TRANSFORM_H_
