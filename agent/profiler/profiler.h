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
// A hierarchical profiler, indended for use with the Syzygy function level
// instrumenter. The Syzygy instrumented provides a function entry hook, and
// this implementation uses a shadow stack with return address swizzling to
// get an exit hook.
// The profiler uses RDTSC as wall clock, which makes it unsuitable for
// profiling on systems with CPUs prior to AMD Barcelona/Phenom, or older
// Intel processors, see e.g. http://en.wikipedia.org/wiki/Time_Stamp_Counter
// for the low down details.

#ifndef SYZYGY_AGENT_PROFILER_PROFILER_H_
#define SYZYGY_AGENT_PROFILER_PROFILER_H_

#include <windows.h>
#include <winnt.h>
#include <vector>

#include "base/hash_tables.h"
#include "base/lazy_instance.h"
#include "base/synchronization/lock.h"
#include "base/threading/thread_local.h"
#include "syzygy/agent/common/entry_frame.h"
#include "syzygy/trace/client/rpc_session.h"

// Assembly instrumentation stubs to handle function entry and exit.
extern "C" void _cdecl _indirect_penter();
extern "C" void _cdecl _indirect_penter_dllmain();
extern "C" void _cdecl _indirect_penter_inside_function();
extern void pexit();

namespace agent {
namespace profiler {

// There's a single instance of this class.
class Profiler {
 public:
  static void WINAPI DllMainEntryHook(EntryFrame* entry_frame,
                                      FuncAddr function,
                                      uint64 cycles);

  static void WINAPI FunctionEntryHook(EntryFrame* entry_frame,
                                       FuncAddr function,
                                       uint64 cycles);

  // Resolves a return address location to a thunk's stashed original
  // location if a thunk is involved.
  // @param pc_location an address on stack where a return address is stored.
  // @returns the address where the profiler stashed the original return address
  //     if *(@p pc_location) refers to a thunk, otherwise @p pc_location.
  // @note this function must be able to resolve through thunks that belong
  //     to other threads, as e.g. V8 will traverse all stacks that are using
  //     V8 during garbage collection.
  RetAddr* ResolveReturnAddressLocation(RetAddr* pc_location);

  // Retrieves the profiler singleton instance.
  static Profiler* Instance();

  // Called when a thread is terminating.
  void OnThreadDetach();

 private:
  // Make sure the LazyInstance can be created.
  friend struct base::DefaultLazyInstanceTraits<Profiler>;

  Profiler();
  ~Profiler();

  // Called form DllMainEntryHook.
  void OnModuleEntry(EntryFrame* entry_frame,
                     FuncAddr function,
                     uint64 cycles);

  // Callbacks from ThreadState.
  void OnPageAdded(const void* page);
  void OnPageRemoved(const void* page);

  // Called on a first chance exception declaring thread name.
  void OnThreadName(const base::StringPiece& thread_name);

  // Scavenges dead thread states, call at opportune times.
  void ScavengeThreadStates();

  // Our vectored exception handler that takes care
  // of capturing thread name debug exceptions.
  static LONG CALLBACK ExceptionHandler(EXCEPTION_POINTERS* ex_info);

  class ThreadState;

  ThreadState* CreateFirstThreadStateAndSession();
  ThreadState* GetOrAllocateThreadState();
  ThreadState* GetOrAllocateThreadStateImpl();
  ThreadState* GetThreadState() const;
  void FreeThreadState();

  // The RPC session we're logging to/through.
  trace::client::RpcSession session_;

  // Protects pages_ and logged_modules_.
  base::Lock lock_;

  // Contains the thunk pages in lexical order.
  typedef std::vector<const void*> PageVector;
  PageVector pages_;  // Under lock_.

  // Contains the set of modules we've seen and logged.
  typedef base::hash_set<HMODULE> ModuleSet;
  ModuleSet logged_modules_;  // Under lock_.

  // A doubly-linked list of all thread states whose thread
  // has not yet seen a thread detach notification.
  LIST_ENTRY thread_states_;  // Under lock_.

  // A doubly-linked list of thread states whole thread
  // has seen a thread detach notification.
  LIST_ENTRY death_row_;  // Under lock_.

  // Stores our vectored exception handler registration handle.
  void* handler_registration_;

  // This points to our per-thread state.
  mutable base::ThreadLocalPointer<ThreadState> tls_;
};

}  // namespace profiler
}  // namespace agent

#endif  // SYZYGY_AGENT_PROFILER_PROFILER_H_
