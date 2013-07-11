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
// This file declares the Call Trace "Client" class, which is responsible
// for providing all of the Call Trace DLL functionality.

#ifndef SYZYGY_AGENT_CALL_TRACE_CLIENT_RPC_H_
#define SYZYGY_AGENT_CALL_TRACE_CLIENT_RPC_H_

#include <map>
#include <utility>
#include <vector>

#include "base/synchronization/lock.h"
#include "base/threading/thread_local.h"
#include "syzygy/agent/common/entry_frame.h"
#include "syzygy/trace/client/rpc_session.h"

// Assembly instrumentation stubs to handle function entry and exit. These
// respectively invoke Client::FunctionEntryHook, Client::DllMainEntryHook,
// Client::FunctionExitHook and Client::DllMainExitHook.
extern "C" void _cdecl _indirect_penter();
extern "C" void _cdecl _indirect_penter_dllmain();

namespace agent {
namespace client {

class Client {
 public:
  Client();
  ~Client();

  static Client* Instance();

  BOOL WINAPI DllMain(HMODULE module, DWORD reason, LPVOID reserved);

 protected:
  typedef agent::EntryFrame EntryFrame;
  friend void _indirect_penter();
  friend void _indirect_penter_dll_main();

  // Invoked by _indirect_penter_dllmain on entry to a DLL's entry point.
  //
  // This function will initialize a call trace session if none currently
  // exists and will transmit module information to the call trace service.
  // It will then log the entry into the DLL's entry point.
  //
  // @param entry_frame The entry frame for the module entry point
  // @param function The module entry point
  static void WINAPI DllMainEntryHook(EntryFrame* entry_frame,
                                      FuncAddr function);

  // Invoked by _indirect_penter on function entry.
  //
  // @param entry_frame The entry frame for the called function.
  // @param function The called function.
  static void WINAPI FunctionEntryHook(EntryFrame* entry_frame,
                                       FuncAddr function);

 private:
  // We keep a structure of this type for each thread.
  class ThreadLocalData;

  // The functions we use to manage the thread local data.
  ThreadLocalData* GetThreadData();
  ThreadLocalData* GetOrAllocateThreadData();
  void FreeThreadData(ThreadLocalData* data);
  void FreeThreadData();

  // DllMain Handler functions. We only handle detach events in DllMain, the
  // attachment events are deferred to the first use of an event hook. This
  // is an attempt to avoid running afoul of the module loader lock and/or
  // load order problems. Further, we don't need/want to handle attachment
  // events for non-instrumented modules, anyway.
  void OnClientProcessDetach();
  void OnClientThreadDetach();

  // This function will initialize a call trace session if none currently
  // exists and the event is DLL_PROCESS_ATTACH. It will then transmit a
  // module event record to the call trace service.
  //
  // @param data the thread local data describing this threads call trace
  //     log buffer.
  // @param entry_frame the entry frame for the module entry point
  // @param function the module entry point
  void LogEvent_ModuleEvent(ThreadLocalData *data,
                            HMODULE module,
                            DWORD reason);

  // Called by FunctionEntryHook and DllMainEntryHook.
  //
  // This function will log the entry into the given function.
  //
  // If module is not NULL and reason is either DLL_THREAD_ATTACH or
  // DLL_PROCESS_ATTACH, the function first logs the module event before
  // logging the function entry.
  //
  // @param entry_frame The entry frame for the called function.
  // @param function The called function.
  // @param module NULL unless the entry denotes an instrumented dll's entry
  //     point being called.
  // @param reason If module is NULL this is ignored; otherwise, it must be
  //     DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH, DLL_THREAD_ATTACH or
  //     DLL_THREAD_DETACH.
  void LogEvent_FunctionEntry(EntryFrame* entry_frame,
                              FuncAddr function,
                              HMODULE module,
                              DWORD reason);

  // The initialization lock.
  base::Lock init_lock_;

  // Our RPC session state.
  trace::client::RpcSession session_;

  // This points to our per-thread state.
  mutable base::ThreadLocalPointer<ThreadLocalData> tls_;
};

}  // namespace client
}  // namespace agent

#endif  // SYZYGY_AGENT_CALL_TRACE_CLIENT_RPC_H_
