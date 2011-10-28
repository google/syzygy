// Copyright 2011 Google Inc.
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

#ifndef SYZYGY_CALL_TRACE_CLIENT_RPC_H_
#define SYZYGY_CALL_TRACE_CLIENT_RPC_H_

#include <atlbase.h>
#include <map>
#include <utility>
#include <vector>

#include "base/synchronization/lock.h"
#include "base/win/scoped_handle.h"
#include "syzygy/call_trace/call_trace_defs.h"

// Assembly instrumentation stubs to handle function entry and exit. These
// respectively invoke Client::FunctionEntryHook, Client::DllMainEntryHook,
// Client::FunctionExitHook and Client::DllMainExitHook.
extern "C" void _cdecl _indirect_penter();
extern "C" void _cdecl _indirect_penter_dllmain();
extern void pexit();
extern void pexit_dllmain();

namespace call_trace {
namespace client {

class Client {
 public:
  Client();
  ~Client();

  static Client* Instance();

  bool IsTracing() const {
    return session_handle_ != NULL;
  }

  bool IsDisabled() const {
    return is_disabled_;
  }

  BOOL WINAPI DllMain(HMODULE module, DWORD reason, LPVOID reserved);

 protected:
  friend void _indirect_penter();
  friend void _indirect_penter_dll_main();
  friend void pexit();
  friend void pexit_dllmain();

  // This structure is overlaid on the entry frame to access and modify it.
  struct EntryFrame {
    RetAddr retaddr;
    ArgumentWord args[4];
  };

  // Invoked by _indirect_penter_dllmain on entry to a DLL's entry point.
  //
  // This function will initialize a call trace session if none currently
  // exists and will transmit module information to the call trace service.
  // It will then log the entry into the DLL's entry point and, if the
  // module event is a thread or process detach, request that the module
  // and event type be
  // DllMainExitHook (via ::pexit_dllmain) be used on exit.
  //
  // @param entry_frame The entry frame for the module entry point
  // @param function The module entry point
  //
  // @note This function will modify the return addres in the entry frame
  //     such that the invoked function to return to pexit_dllmain, instead
  //     of directly to the original caller.
  static void WINAPI DllMainEntryHook(EntryFrame* entry_frame,
                                      FuncAddr function);

  // Invoked by pexit_dllmain on exit from a DLL's entry point.
  //
  // This function will log the exit from the DLL entry point and request
  // that
  //
  // @param stack The stack pointer prior to entering _pexit.
  // @param retval The return value from the function returning, e.g. the
  //     contents of the eax register.
  //
  // @returns The return address this invocation should have returned to.
  static RetAddr WINAPI DllMainExitHook(const void* stack,
                                         RetValueWord retval);

  // Invoked by _indirect_penter on function entry.
  //
  // @param entry_frame The entry frame for the called function.
  // @param function The called function.
  //
  // @note If function exit tracing is in effect, this function will modify
  //     the return address in the entry frame, which will cause the invoked
  //     function to return to pexit, instead of directly to the original
  //     caller.
  static void WINAPI FunctionEntryHook(EntryFrame* entry_frame,
                                       FuncAddr function);

  // Invoked by pexit on function exit.
  //
  // @param stack The stack pointer prior to entering _pexit.
  // @param retval The return value from the function returning, e.g. the
  //     contents of the eax register.
  // @returns The return address this invocation should have returned to.
  static RetAddr WINAPI FunctionExitHook(const void* stack,
                                         RetValueWord retval);

 private:
  // We keep a structure of this type for each thread.
  class ThreadLocalData;

  inline bool IsEnabled(unsigned long bit_mask) const {
    return (flags_ & bit_mask) != 0;
  }

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

  // Called by ModuleEventHook and, on exit DLL_PROCESS_DETACH from a dll
  // entry point, from FunctionExitHook.
  //
  // This function will initialize a call trace session if none currently
  // exists and the event is DLL_PROCESS_ATTACH. It will then transmit a
  // module event record to the call trace service.
  //
  // @param data the thread local data describing this threads call trace
  //     log buffer.
  // @param entry_frame the entry frame for the module entry point
  // @param function the module entry point
  // @note if function exit tracing is in effect, this function will modify
  //     the return addres in the entry frame, which will cause the invoked
  //     function to return to pexit, instead of to the original caller.
  void LogEvent_ModuleEvent(ThreadLocalData *data,
                            HMODULE module,
                            DWORD reason);

  // Called by FunctionEntryHook and DllMainEntryHook.
  //
  // This function will log the entry into the given function. If function
  // exit tracing is in effect, this function will modify the return address
  // in the entry frame, which will cause the invoked function to return to
  // pexit instead of to the original caller.
  //
  // If module is not NULL and reason is either DLL_THREAD_ATTACH or
  // DLL_PROCESS_ATTACH, the function first logs the module event before
  // logging the function entry. If the reason is DLL_THREAD_DETACH or
  // DLL_PROCESS_DETACH, the function will modify the return address in
  // the entry from to cause the invoked function to return to
  // ::pexit_dllmain instead of the oiginal caller.  This behaviour
  // supercedes the usual exit tracing behaviour.
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

  // Called by FunctionExitHook and DllMainExitHook
  //
  // This function also captures module unload events.
  //
  // @param stack the stack pointer prior to entering _pexit.
  // @param retval the return value from the function returning, e.g. the
  //     contents of the eax register.
  // @returns the return address this invocation should have returned to.
  RetAddr LogEvent_FunctionExit(const void* stack,
                                RetValueWord retval);

  // Wrapper and helper functions for the RPC and shared memory calls made
  // by the call-trace client.
  bool BindRPC();
  bool MapSegmentBuffer(ThreadLocalData* data);
  bool CreateSession();
  bool AllocateBuffer(ThreadLocalData* data);
  bool ExchangeBuffer(ThreadLocalData* data);
  bool ReturnBuffer(ThreadLocalData* data);
  bool CloseSession();
  void FreeSharedMemory();

  struct ReturnStackEntry {
    // The original return address we replaced.
    RetAddr return_address;
    // The function address invoked, from which this stack entry returns.
    FuncAddr function_address;
    // The address of the entry frame associated with this shadow entry.
    EntryFrame* entry_frame;
  };

  typedef std::vector<ReturnStackEntry> ReturnStack;

  struct ModuleEventStackEntry {
    // The module to which the event refers.
    HMODULE module;

    // The nature of the event.
    DWORD reason;
  };

  typedef std::vector<ModuleEventStackEntry> ModuleEventStack;

  // Each entry in the captured data->traces[] that points to pexit
  // is fixed to point to the corresponding trace in stack. This is
  // necessary because when exit tracing is enabled, the return address
  // of each entered function is rewritten to _pexit.
  static void FixupBackTrace(const ReturnStack& stack,
                             RetAddr traces[],
                             size_t num_traces);

  // We track the set of shared memory handles we've mapped into the
  // process. This allows us to avoid mapping a handle twice, as well
  // as letting us know what to clean up on exit. Access to the set
  // of handles must be serialized with a lock.
  typedef std::map<HANDLE, uint8*> SharedMemoryHandleMap;
  base::Lock shared_memory_lock_;
  SharedMemoryHandleMap shared_memory_handles_;

  // TLS index to our thread local data.
  DWORD tls_index_;

  // The call trace RPC binding.
  handle_t rpc_binding_;

  // The handle to the call trace session. Initialization of the session
  // is protected by a lock. This is a seperate lock since we don't seem
  // to have recursive locks in base.
  base::Lock init_lock_;
  SessionHandle session_handle_;

  // The set of trace flags returned by the call trace server. These instruct
  // the client as to which types of events to capture.
  unsigned long flags_;

  // This becomes true if the client fails to attach to a call trace service.
  // This is used to allow the application to run even if no call trace
  // service is available.
  bool is_disabled_;
};

}  // namespace call_trace::client
}  // namespace call_trace

#endif  // SYZYGY_CALL_TRACE_CLIENT_RPC_H_
