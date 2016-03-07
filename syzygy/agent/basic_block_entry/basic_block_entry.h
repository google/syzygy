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
// initializing the RPC connection and per-thread counter buffering on
// demand as necessary as well as saturation incrementing the appropriate
// counter when requested.
//
// The instrumenter can be used to inject a run-time dependency on this
// library as well as to add the appropriate entry-hook code.
// For details on the implementation, see basic_block_entry.cc.

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

namespace agent {
namespace basic_block_entry {

// The basic-block counting agent.
// @note: There's a single instance of this class.
// TODO(sebmarchand): Rename this class to BasicBlockAgent (or something
//     similar) as this is used by various modes of instrumentation (basic block
//     entry counting, basic block arc counts, jump table entry counts, etc).
class BasicBlockEntry {
 public:
  using IndexedFrequencyData = ::common::IndexedFrequencyData;
  using ThreadLocalIndexedFrequencyData =
      ::common::ThreadLocalIndexedFrequencyData;
  using ThreadStateManager = ::agent::common::ThreadStateManager;

  // The size in DWORD of the buffer. We choose a multiple of memory page size.
  static const size_t kBufferSize = 4096;
  // The number of entries in the simulated branch predictor cache.
  static const size_t kPredictorCacheSize = 4096;

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

  // Called from _increment_indexed_freq_data().
  static void WINAPI IncrementIndexedFreqDataHook(
      IncrementIndexedFreqDataFrame* entry_frame);

  // Called from _branch_enter.
  static void WINAPI BranchEnterHook(
      IncrementIndexedFreqDataFrame* entry_frame);

  // Called from _branch_enter_buffered.
  static void WINAPI BranchEnterBufferedHook(
      IncrementIndexedFreqDataFrame* entry_frame);

  // Called from _branch_exit.
  static void WINAPI BranchExitHook(
      IncrementIndexedFreqDataFrame* entry_frame);

  // Called from _function_enter_slotX.
  template<int S>
  static inline void __fastcall FunctionEnterHookSlot(
      IndexedFrequencyData* module_data);

  // Called from _branch_enter_slotX.
  template <int S>
  static inline void __fastcall BranchEnterHookSlot(uint32_t index);

  // Called from _branch_enter_buffered_slotX.
  template <int S>
  static inline void __fastcall BranchEnterBufferedHookSlot(uint32_t index);

  // Called from _branch_exit_slotX.
  template <int S>
  static inline void __fastcall BranchExitHookSlot(uint32_t index);

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

  // Initializes the given frequency data element.
  bool InitializeFrequencyData(IndexedFrequencyData* data);

  // Handles EXE startup on ExeMainEntryHook and DLL_PROCESS_ATTACH messages
  // received by DllMainEntryHook().
  void OnProcessAttach(IndexedFrequencyData* module_data);

  // Handles DLL_THREAD_DETACH and DLL_PROCESS_DETACH messages received by
  // DllMainEntryHook().
  void OnThreadDetach(IndexedFrequencyData* module_data);

  // Registers the module containing @p addr with the call_trace_service.
  void RegisterModule(const void* addr);

  // Register a TLS slot for this module.
  void RegisterFastPathSlot(IndexedFrequencyData* module_data,
                            unsigned int slot);

  // Unregister a TLS slot for this module.
  void UnregisterFastPathSlot(IndexedFrequencyData* module_data,
                              unsigned int slot);

  // Create the local thread state for the current thread. This should only
  // be called if the local thread state has not already been created.
  ThreadState* CreateThreadState(IndexedFrequencyData* module_data);

  // Returns the local thread state for the current thread. If the thread state
  // is unavailable, this function returns NULL.
  static ThreadState* GetThreadState(IndexedFrequencyData* module_data);

  // Returns the local thread state for the current thread (when instrumented
  // with fast-path).
  template<int S>
  static ThreadState* GetThreadStateSlot();

  // Registered thread local specific slot.
  uint32_t registered_slots_;

  // The RPC session we're logging to/through.
  trace::client::RpcSession session_;

  // A helper to manage the life-cycle of the ThreadState instances allocated
  // by this agent.
  ThreadStateManager thread_state_manager_;

  // The trace file segment we're writing module events to. The frequency data
  // goes to specially allocated segments that we don't explicitly keep track
  // of, but rather that we let live until the client gets torn down.
  trace::client::TraceFileSegment segment_;  // Under lock_.

  // Global lock to avoid concurrent segment_ update.
  base::Lock lock_;
};

}  // namespace basic_block_entry
}  // namespace agent

#endif  // SYZYGY_AGENT_BASIC_BLOCK_ENTRY_BASIC_BLOCK_ENTRY_H_
