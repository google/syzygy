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
// The runtime portion of a basic-block counting agent. This is responsible for
// initializing the RPC connection and per-thread indexed-data-count buffer on
// demand as necessary as well as saturation incrementing the appropriate
// counter when requested.
//
// The instrumenter can be used to inject a run-time dependency on this
// library as well as to add the appropriate entry-hook code.

#ifndef SYZYGY_AGENT_BASIC_BLOCK_ENTRY_BASIC_BLOCK_ENTRY_H_
#define SYZYGY_AGENT_BASIC_BLOCK_ENTRY_BASIC_BLOCK_ENTRY_H_

#include <windows.h>
#include <winnt.h>
#include <vector>

#include "base/lazy_instance.h"
#include "base/win/pe_image.h"
#include "syzygy/agent/common/thread_state.h"
#include "syzygy/common/indexed_frequency_data.h"
#include "syzygy/trace/client/rpc_session.h"

// Instrumentation stub to increment an indexed frequency data counter.
extern "C" void _cdecl _increment_indexed_freq_data();

// Instrumentation stub to handle the invocation of a DllMain-like entry point.
extern "C" void _cdecl _indirect_penter_dllmain();

// Instrumentation stub to handle a request for a pointer to frequency data.
extern "C" uint32* _stdcall _get_raw_frequency_data(
    ::common::IndexedFrequencyData* data);

namespace agent {
namespace basic_block_entry {

// The basic-block counting agent.
// @note: There's a single instance of this class.
// TODO(sebmarchand): Rename this class to BasicBlockAgent (or something
//     similar) as this is used by various modes of instrumentation (basic block
//     entry counting, basic block arc counts, jump table entry counts, etc).
class BasicBlockEntry {
 public:
  typedef ::common::IndexedFrequencyData IndexedFrequencyData;
  typedef ::agent::common::ThreadStateManager ThreadStateManager;

  // This structure describes the contents of the stack above a call to
  // BasicBlockEntry::IncrementIndexedFreqDataHook. A pointer to this structure
  // will be given to the IncrementIndexedFreqDataHook by
  // _increment_indexed_freq_data.
  struct IncrementIndexedFreqDataFrame;

  // This structure describes the contents of the stack above a call to
  // BasicBlockEntry::DllMainEntryHook(). A pointer to this structure will
  // be given to the DllMainEntryHook by _indirect_penter_dllmain.
  struct DllMainEntryFrame;

  // This structure describes the contents of the stack above a call to
  // BasicBlockEntry::ExeMainEntryHook(). A pointer to this structure will
  // be given to the ExeMainEntryHook by _indirect_penter_exemain.
  struct ExeMainEntryFrame;

  // Retrieves the basic block entry singleton instance.
  static BasicBlockEntry* Instance();

  // Returns a pointer to thread local frequency data. Used by the fast-path.
  static uint32* WINAPI GetRawFrequencyData(IndexedFrequencyData* data);

  // Called from _increment_indexed_freq_data().
  static void WINAPI IncrementIndexedFreqDataHook(
      IncrementIndexedFreqDataFrame* entry_frame);

  // Called from _branch_enter.
  static void WINAPI BranchEnterHook(
      IncrementIndexedFreqDataFrame* entry_frame);

  // Called from _branch_exit.
  static void WINAPI BranchExitHook(
      IncrementIndexedFreqDataFrame* entry_frame);

  // Called from _indirect_penter_dllmain.
  static void WINAPI DllMainEntryHook(DllMainEntryFrame* entry_frame);

  // Called from _indirect_penter_exemain.
  static void WINAPI ExeMainEntryHook(ExeMainEntryFrame* entry_frame);

 protected:
  // This class defines the per-thread-per-instrumented-module state managed
  // by this agent.
  class ThreadState;
  friend class ThreadState;

  // Make sure the LazyInstance can be created.
  friend struct base::DefaultLazyInstanceTraits<BasicBlockEntry>;

  BasicBlockEntry();
  ~BasicBlockEntry();

  // Handles EXE startup on ExeMainEntryHook and DLL_PROCESS_ATTACH messages
  // received by DllMainEntryHook().
  void OnProcessAttach(IndexedFrequencyData* module_data);

  // Handles DLL_THREAD_DETACH and DLL_PROCESS_DETACH messages received by
  // DllMainEntryHook().
  void OnThreadDetach(IndexedFrequencyData* module_data);

  // Registers the module containing @p addr with the call_trace_service.
  void RegisterModule(const void* addr);

  // Create the local thread state for the current thread. This should only
  // be called if the local thread state has not already been created.
  ThreadState* CreateThreadState(IndexedFrequencyData* module_data);

  // The RPC session we're logging to/through.
  trace::client::RpcSession session_;

  // A helper to manage the life-cycle of the ThreadState instances allocated
  // by this agent.
  ThreadStateManager thread_state_manager_;
};

}  // namespace basic_block_entry
}  // namespace agent

#endif  // SYZYGY_AGENT_BASIC_BLOCK_ENTRY_BASIC_BLOCK_ENTRY_H_
