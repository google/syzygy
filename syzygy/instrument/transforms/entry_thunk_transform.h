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
//
// Declaration of the entry thunk instrumentation transform. This instruments
// module entry points (DLL and EXE) and individual functions with different
// hook functions (provided to the transform). The details as to which
// entry points and functions are hooked (and how) can be individually
// controlled.
//
// A generic hook (without a parameter) redirects a call to a thunk of the
// form:
//
//   0x68 0x44 0x33 0x22 0x11       push 0x11223344
//   0xff 0x25 0x88 0x77 0x66 0x55  jmp [0x55667788]
//
// Where 0x11223344 is the address of the original function to be invoked,
// and 0x55667788 is the address of the import pointing at the hook to be
// invoked. The hook is responsible for cleaning up the stack with a 'ret' so
// that 0x11223344 is popped, and control is transferred to the original
// function.
//
// A parameterized hook redirects a call to a thunk of the form:
//
//   0x68 0xdd 0xcc 0xbb 0xaa       push 0xaabbccdd  ; must be a 32 bit value.
//   0x68 0x44 0x33 0x22 0x11       push 0x11223344
//   0xff 0x25 0x88 0x77 0x66 0x55  jmp [0x55667788]
//
// Where 0xaabbccdd is an additional immediate value, the semantics of which
// are known to the hook function. The hook is responsible for cleaning up
// the stack with a 'ret 4' so that both 0xaabbccdd and 0x11223344 are popped
// and control is returned to the original function.
//
// Prior to executing the thunk the stack is set up as if the call was going to
// be directly to the original function.

#ifndef SYZYGY_INSTRUMENT_TRANSFORMS_ENTRY_THUNK_TRANSFORM_H_
#define SYZYGY_INSTRUMENT_TRANSFORMS_ENTRY_THUNK_TRANSFORM_H_

#include <set>
#include <string>

#include "base/strings/string_piece.h"
#include "syzygy/block_graph/basic_block_assembler.h"
#include "syzygy/block_graph/iterate.h"
#include "syzygy/block_graph/transforms/iterative_transform.h"
#include "syzygy/pe/pe_utils.h"

namespace instrument {
namespace transforms {

class EntryThunkTransform
    : public block_graph::transforms::IterativeTransformImpl<
        EntryThunkTransform> {
 public:
  typedef block_graph::Immediate Immediate;
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::TransformPolicyInterface TransformPolicyInterface;

  EntryThunkTransform();

  // @name Accessors.
  // @{
  void set_instrument_unsafe_references(bool instrument) {
    instrument_unsafe_references_ = instrument;
  }
  bool instrument_unsafe_references() const {
    return instrument_unsafe_references_;
  }

  void set_src_ranges_for_thunks(bool src_ranges_for_thunks) {
    src_ranges_for_thunks_ = src_ranges_for_thunks;
  }
  bool src_ranges_for_thunks() const {
    return src_ranges_for_thunks_;
  }

  void set_only_instrument_module_entry(bool only_instrument_module_entry) {
    only_instrument_module_entry_ = only_instrument_module_entry;
  }

  bool only_instrument_module_entry() const {
    return only_instrument_module_entry_;
  }

  void set_instrument_dll_name(const base::StringPiece& instrument_dll_name) {
    instrument_dll_name.CopyToString(&instrument_dll_name_);
  }
  const char* instrument_dll_name() const {
    return instrument_dll_name_.c_str();
  }

  const Immediate& entry_thunk_parameter() const {
    return entry_thunk_parameter_;
  }
  const Immediate& function_thunk_parameter() const {
    return function_thunk_parameter_;
  }

  BlockGraph::Section* thunk_section() const { return thunk_section_; }
  // @}

  // @{
  // Sets the parameter to be used by entry/function thunks. Only 32-bit
  // parameters may be used. Set to an invalid parameter (default constructed)
  // with a size of core::kSizeNone in order to disable parameterized thunks.
  // @param immediate the parameter to be used.
  // @returns true if the parameter was accepted, false otherwise.
  bool SetEntryThunkParameter(const Immediate& immediate);
  bool SetFunctionThunkParameter(const Immediate& immediate);
  // @}

  // @{
  // @returns true if the thunk type will be parameterized.
  bool EntryThunkIsParameterized() const;
  bool FunctionThunkIsParameterized() const;
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
  // @}

  // Instrument a single block.
  bool InstrumentCodeBlock(BlockGraph* block_graph, BlockGraph::Block* block);

  // Instruments a single referrer to a code block.
  bool InstrumentCodeBlockReferrer(const BlockGraph::Block::Referrer& referrer,
                                   BlockGraph* block_graph,
                                   BlockGraph::Block* block,
                                   ThunkBlockMap* thunk_block_map);

  // Create a single thunk to destination.
  // @param block_graph the block-graph being instrumented.
  // @param destination the destination reference.
  // @param hook a reference to the hook to use.
  // @param parameter the parameter to be passed to the thunk. If this is NULL
  //     then an unparameterized thunk will be created.
  BlockGraph::Block* CreateOneThunk(BlockGraph* block_graph,
                                    const BlockGraph::Reference& destination,
                                    const BlockGraph::Reference& hook,
                                    const Immediate* parameter);

 private:
  friend IterativeTransformImpl<EntryThunkTransform>;
  friend NamedBlockGraphTransformImpl<EntryThunkTransform>;

  bool GetEntryPoints(BlockGraph::Block* header_block);

  // For NamedBlockGraphTransformImpl.
  static const char kTransformName[];

  // The section we put our thunks in. Valid after successful
  // PreBlockGraphIteration.
  BlockGraph::Section* thunk_section_;

  // References to _indirect_penter and _indirect_penter_dllmain import
  // entries. Valid after successful PreBlockGraphIteration.
  BlockGraph::Reference hook_ref_;
  BlockGraph::Reference hook_dllmain_ref_;
  BlockGraph::Reference hook_exe_entry_ref_;

  // Iff true, instrument references with a non-zero offset into the
  // destination block.
  bool instrument_unsafe_references_;

  // Iff true, thunks will be adorned with a source range identifying them
  // with the function they address. This makes the output more debugging
  // friendly, at the cost of the uniqueness of address->name resolution.
  bool src_ranges_for_thunks_;

  // If true, only instrument DLL entry points.
  bool only_instrument_module_entry_;

  // If has a size of 32 bits, then entry thunks will be set up with an extra
  // parameter on the stack prior to the address of the original function.
  Immediate entry_thunk_parameter_;

  // If has a size of 32 bits, then function hook thunks will be set up with an
  // extra parameter on the stack prior to the address of the original function.
  Immediate function_thunk_parameter_;

  // Name of the instrumentation DLL we import.
  // Defaults to "call_trace_client.dll".
  std::string instrument_dll_name_;

  // This contains the set of entrypoints that have DllMain calling conventions.
  // These are thunked to the dllmain hook import, instead of the generic
  // hook import. Valid after successful call to GetEntryPoints.
  pe::EntryPointSet dllmain_entrypoints_;
  // If the module being instrumented is an executable, this will hold the
  // EXE main entry point. Valid after successful call to GetEntryPoints.
  pe::EntryPoint exe_entry_point_;

  DISALLOW_COPY_AND_ASSIGN(EntryThunkTransform);
};

}  // namespace transforms
}  // namespace instrument

#endif  // SYZYGY_INSTRUMENT_TRANSFORMS_ENTRY_THUNK_TRANSFORM_H_
