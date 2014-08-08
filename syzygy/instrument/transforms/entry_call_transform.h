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
//
// Declaration of the entry call instrumentation transform. This instruments
// individual functions by injecting a call to a transformation import at the
// start of each function.

#ifndef SYZYGY_INSTRUMENT_TRANSFORMS_ENTRY_CALL_TRANSFORM_H_
#define SYZYGY_INSTRUMENT_TRANSFORMS_ENTRY_CALL_TRANSFORM_H_

#include <set>
#include <string>

#include "base/strings/string_piece.h"
#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/iterate.h"
#include "syzygy/block_graph/transforms/iterative_transform.h"
#include "syzygy/block_graph/transforms/named_transform.h"
#include "syzygy/pe/pe_utils.h"

namespace instrument {
namespace transforms {

class EntryCallBasicBlockTransform
    : public block_graph::transforms::NamedBasicBlockSubGraphTransformImpl<
          EntryCallBasicBlockTransform> {
 public:
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::BasicBlockSubGraph BasicBlockSubGraph;
  typedef block_graph::TransformPolicyInterface TransformPolicyInterface;

  EntryCallBasicBlockTransform(
      const BlockGraph::Reference& hook_reference,
      bool debug_friendly);

  // For NamedBlockGraphTransformImpl.
  static const char kTransformName[];

 protected:
  // @name BasicBlockSubGraphTransformInterface implementation.
  // @{
  virtual bool TransformBasicBlockSubGraph(
      const TransformPolicyInterface* policy,
      BlockGraph* block_graph,
      BasicBlockSubGraph* basic_block_subgraph);
  // @}

 private:
  // Iff true, assigns the first instruction's source range to
  // the inserted call.
  bool debug_friendly_;
  // The hook we call to.
  const BlockGraph::Reference hook_reference_;

  DISALLOW_COPY_AND_ASSIGN(EntryCallBasicBlockTransform);
};

class EntryCallTransform
    : public block_graph::transforms::IterativeTransformImpl<
          EntryCallTransform> {
 public:
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::TransformPolicyInterface TransformPolicyInterface;

  explicit EntryCallTransform(bool debug_friendly);

  // @name Accessors.
  // @{
  bool debug_friendly() const { return debug_friendly_; }
  void set_instrument_dll_name(const base::StringPiece& instrument_dll_name) {
    instrument_dll_name.CopyToString(&instrument_dll_name_);
  }
  const char* instrument_dll_name() const {
    return instrument_dll_name_.c_str();
  }
  // @}

  // The name of the import for general entry hooks.
  static const char kEntryHookName[];
  // The name of the import for DllMain-like function entry hooks.
  static const char kDllMainEntryHookName[];
  // The name of the import for EXE entry point hook.
  static const char kExeMainEntryHookName[];

  // The name of the DLL imported default.
  static const char kDefaultInstrumentDll[];

 protected:
  typedef std::map<BlockGraph::Offset, BlockGraph::Block*> ThunkBlockMap;

  // @name IterativeTransformImpl implementation.
  // @{
  bool PreBlockGraphIteration(const TransformPolicyInterface* policy,
                              BlockGraph* block_graph,
                              BlockGraph::Block* header_block);
  bool OnBlock(const TransformPolicyInterface* policy,
               BlockGraph* block_graph,
               BlockGraph::Block* block);
  bool PostBlockGraphIteration(const TransformPolicyInterface* policy,
                               BlockGraph* block_graph,
                               BlockGraph::Block* header_block);
  // @}

 private:
  friend IterativeTransformImpl<EntryCallTransform>;
  friend NamedBlockGraphTransformImpl<EntryCallTransform>;

  bool GetEntryPoints(BlockGraph::Block* header_block);

  // For NamedBlockGraphTransformImpl.
  static const char kTransformName[];

  // References to _indirect_penter and _indirect_penter_dllmain import
  // entries. Valid after successful PreBlockGraphIteration.
  BlockGraph::Reference hook_ref_;
  BlockGraph::Reference hook_dllmain_ref_;
  BlockGraph::Reference hook_exe_entry_ref_;

  // Iff true, assigns the first instruction's source range to
  // inserted calls.
  bool debug_friendly_;

  // Name of the instrumentation DLL we import.
  // Defaults to "profile_client.dll".
  std::string instrument_dll_name_;

  // This contains the set of entrypoints that have DllMain calling conventions.
  // These are thunked to the dllmain hook import, instead of the generic
  // hook import. Valid after successful call to GetEntryPoints.
  pe::EntryPointSet dllmain_entrypoints_;
  // If the module being instrumented is an executable, this will hold the
  // EXE main entry point. Valid after successful call to GetEntryPoints.
  pe::EntryPoint exe_entry_point_;

  DISALLOW_COPY_AND_ASSIGN(EntryCallTransform);
};

}  // namespace transforms
}  // namespace instrument

#endif  // SYZYGY_INSTRUMENT_TRANSFORMS_ENTRY_CALL_TRANSFORM_H_
