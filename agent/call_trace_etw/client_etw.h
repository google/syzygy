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

#ifndef SYZYGY_AGENT_CALL_TRACE_ETW_CLIENT_ETW_H_
#define SYZYGY_AGENT_CALL_TRACE_ETW_CLIENT_ETW_H_

#include <atlbase.h>

#include <utility>
#include <vector>

#include "base/synchronization/lock.h"
#include "base/win/event_trace_provider.h"
#include "base/win/scoped_handle.h"
#include "syzygy/agent/call_trace_etw/dlist.h"
#include "syzygy/agent/common/shadow_stack.h"
#include "syzygy/trace/protocol/call_trace_defs.h"

// Assembly stubs to convert calling conventions on function entry and
// exit. These respetively invoke TracerModule::TraceEntry and
// TracerModule::TraceExit.
extern "C" void _cdecl _penter();
extern "C" void _cdecl _indirect_penter();
extern void pexit();
extern bool wait_til_enabled();
extern bool wait_til_disabled();

class TracerModule: public base::win::EtwTraceProvider {
 public:
  TracerModule();
  ~TracerModule();

  BOOL WINAPI DllMain(DWORD reason, LPVOID reserved);

 protected:
  typedef agent::EntryFrame EntryFrame;
  friend void _penter();
  friend void pexit();
  friend bool wait_til_enabled();
  friend bool wait_til_disabled();

  // Invoked on function entry.
  // @param entry_frame the entry frame for the called function.
  // @param function the called function.
  // @note if function exit tracing is in effect, this function will modify
  //    the return addres in the entry frame, which will cause the invoked
  //    function to return to pexit, instead of to the original caller.
  static void WINAPI TraceEntry(EntryFrame *entry_frame, FuncAddr function);

  // Invoked on function exit.
  // @param stack the stack pointer prior to entering _pexit.
  // @param retval the return value from the function returning, e.g. the
  //    contents of the eax register.
  // @returns the return address this invocation should have returned to.
  static RetAddr WINAPI TraceExit(const void* stack, RetValueWord retval);

  // Overrides from ETWTraceProvider.
  virtual void OnEventsEnabled();
  virtual void OnEventsDisabled();

  bool WaitTilEnabled();
  bool WaitTilDisabled();

 private:
  void OnProcessAttach();
  void OnProcessDetach();
  void OnThreadAttach();
  void OnThreadDetach();

  void UpdateEvents(bool is_tracing);
  bool IsTracing();
  bool IsTracing(TraceEventFlags flags);
  void TraceModule(ModuleAddr base,
                   size_t size,
                   const wchar_t *name,
                   const wchar_t *exe);
  void TraceEvent(TraceEventType type);
  void TraceEnterExit(TraceEventType type,
                      const TraceEnterExitEventData& data);
  void TraceBatchEnter(FuncAddr function);

  struct StackEntry : public agent::StackEntryBase {
    // The function address invoked, from which this stack entry returns.
    FuncAddr function_address;
  };

  typedef agent::ShadowStackImpl<StackEntry> ShadowStack;

  // The number of trace entries we log in a batch. There is a maximal
  // event size which appears to be inclusive of the trace header and
  // some amount of overhead, which is ~124 bytes on Windows Vista.
  // We leave a size slop of 256 bytes in case other Windowsen
  // have slightly higher overhead.
  static const size_t kBatchEntriesBufferSize =
      (TRACE_MESSAGE_MAXIMUM_SIZE - 256);
  static const size_t kNumBatchTraceEntries =
      kBatchEntriesBufferSize / sizeof(FuncCall);

  // We keep a structure of this type for each thread.
  class ThreadLocalData;
  friend ThreadLocalData;

  // Flushes the batch entry traces in data to the ETW log.
  void FlushBatchEntryTraces(ThreadLocalData* data);

  // Each entry in the captured data->traces[] that points to pexit
  // is fixed to point to the corresponding trace in stack. This is
  // necessary because when exit tracing is enabled, the return address
  // of each entered function is rewritten to _pexit.
  static void FixupBackTrace(const ShadowStack& stack,
                             TraceEnterExitEventData *data);

  ThreadLocalData *GetThreadData();
  ThreadLocalData *GetOrAllocateThreadData();

  base::win::ScopedHandle enabled_event_;
  base::win::ScopedHandle disabled_event_;

  bool SetThreadLocalData(ThreadLocalData *data);
  void FreeThreadLocalData();

  // Protects our thread local data list.
  base::Lock lock_;
  // We keep all thread local data blocks in a double linked list,
  // to allow us to clean up and log dangling data on process exit.
  LIST_ENTRY thread_data_list_head_;  // Under lock_

  // TLS index to our thread local data.
  DWORD tls_index_;
};

#endif  // SYZYGY_AGENT_CALL_TRACE_ETW_CLIENT_ETW_H_
