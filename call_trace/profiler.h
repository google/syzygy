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

#ifndef SYZYGY_CALL_TRACE_PROFILER_H_
#define SYZYGY_CALL_TRACE_PROFILER_H_

#include "base/lazy_instance.h"
#include "base/threading/thread_local.h"
#include "syzygy/call_trace/rpc_session.h"
#include "syzygy/call_trace/shadow_stack.h"

// Assembly instrumentation stubs to handle function entry and exit.
extern "C" void _cdecl _indirect_penter();
extern "C" void _cdecl _indirect_penter_dllmain();
extern "C" void _cdecl _indirect_penter_inside_function();
extern void pexit();

namespace call_trace {
namespace client {

// There's a single instance of this class.
class Profiler {
 public:
  static void WINAPI DllMainEntryHook(EntryFrame* entry_frame,
                                      FuncAddr function,
                                      uint64 cycles);

  static void WINAPI FunctionEntryHook(EntryFrame* entry_frame,
                                       FuncAddr function,
                                       uint64 cycles);

  void OnDetach();

  static Profiler* Instance();

 private:
  // Make sure the LazyInstance can be created.
  friend struct base::DefaultLazyInstanceTraits<Profiler>;

  Profiler();
  ~Profiler();

  class ThreadState;

  ThreadState* CreateFirstThreadStateAndSession();
  ThreadState* GetOrAllocateThreadState();
  ThreadState* GetOrAllocateThreadStateImpl();
  ThreadState* GetThreadState() const;
  void FreeThreadState();

  // The RPC session we're logging to/through.
  call_trace::client::RpcSession session_;

  // This points to our per-thread state.
  mutable base::ThreadLocalPointer<ThreadState> tls_;
};

}  // namespace call_trace::client
}  // namespace call_trace

#endif  // SYZYGY_CALL_TRACE_PROFILER_H_
