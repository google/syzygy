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
// The runtime portion of a basic-block entry counting agent. This is
// responsible for initializing the RPC connection and per-thread entry-count
// buffer on demand as necessary as well as saturation incrementing the
// appropriate counter when requested.
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
#include "syzygy/common/basic_block_frequency_data.h"
#include "syzygy/trace/client/rpc_session.h"

// Instrumentation stub to handle entry to a basic-block.
extern "C" void _cdecl _basic_block_enter();

// Instrumentation stub to handle the invocation of a DllMain-like entry point.
extern "C" void _cdecl _indirect_penter_dllmain();

namespace agent {
namespace basic_block_entry {

// The basic-block entry counting agent.
// @note: There's a single instance of this class.
class BasicBlockEntry {
 public:
  // This structure describes the contents of the stack above a call to
  // BasicBlockEntry::BasicBlockEntryHook. A pointer to this structure will
  // be given to the BasicBlockEntryHook by _basic_block_enter.
  struct BasicBlockEntryFrame;

  // This structure describes the contents of the stack above a call to
  // BasicBlockEntry::DllMainEntryHook(). A pointer to this structure will
  // be given to the BasicBlockEntryHook by _indirect_penter_dllmain.
  struct DllMainEntryFrame;

  // Retrieves the coverage singleton instance.
  static BasicBlockEntry* Instance();

  // Called from _basic_block_enter().
  static void WINAPI BasicBlockEntryHook(BasicBlockEntryFrame* entry_frame);

  // Called from _indirect_penter_dllmain.
  static void WINAPI DllMainEntryHook(DllMainEntryFrame* entry_frame);

 protected:
  // This class defines the per-thread-per-instrumented-module state managed
  // by this agent.
  class ThreadState;
  friend class ThreadState;

  // Make sure the LazyInstance can be created.
  friend struct base::DefaultLazyInstanceTraits<BasicBlockEntry>;

  BasicBlockEntry();
  ~BasicBlockEntry();

  // Handles DLL_PROCESS_ATTACH messages received by DllMainEntryHook().
  void OnProcessAttach(DllMainEntryFrame* entry_frame);

  // Handles DLL_THREAD_DETACH and DLL_PROCESS_DETACH messages received by
  // DllMainEntryHook().
  void OnThreadDetach(DllMainEntryFrame* entry_frame);

  // Registers the module containing @p addr with the call_trace_service.
  void RegisterModule(const void* addr);

  // Create the local thread state for the current thread. This should only
  // be called if the local thread state has not already been created.
  ThreadState* CreateThreadState(BasicBlockEntryFrame* entry_frame);

  // The RPC session we're logging to/through.
  trace::client::RpcSession session_;

  // A helper to manage the life-cycle of the ThreadState instances allocated
  // by this agent.
  agent::common::ThreadStateManager thread_state_manager_;
};

}  // namespace coverage
}  // namespace agent

#endif  // SYZYGY_AGENT_BASIC_BLOCK_ENTRY_BASIC_BLOCK_ENTRY_H_
