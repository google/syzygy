// Copyright 2010 Google Inc.
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
#ifndef SAWBUCK_CALL_TRACE_CALL_TRACE_MAIN_H_
#define SAWBUCK_CALL_TRACE_CALL_TRACE_MAIN_H_

#include <atlbase.h>
#include <vector>
#include "base/event_trace_provider_win.h"
#include "base/lock.h"
#include "sawbuck/call_trace/call_trace_defs.h"
#include "sawbuck/call_trace/dlist.h"


// Assembly stubs to convert calling conventions on function entry and
// exit. These respetively invoke TracerModule::TraceEntry and
// TracerModule::TraceExit.
extern "C" void _cdecl _penter();
extern void pexit();

class TracerModule: public EtwTraceProvider {
 public:
  TracerModule();
  ~TracerModule();

  BOOL WINAPI DllMain(DWORD reason, LPVOID reserved);

 protected:
  friend void _penter();
  friend void pexit();

  // This structure is overlaid on the entry frame to access and modify it.
  struct EntryFrame {
    RetAddr retaddr;
    ArgumentWord args[4];
  };

  // Invoked on function entry.
  // @param entry_frame the entry frame for the called function.
  // @param function the called function.
  // @note if function exit tracing is in effect, this function will modify
  //    the return addres in the entry frame, which will cause the invoked
  //    function to return to pexit, instead of to the original caller.
  static void WINAPI TraceEntry(EntryFrame *entry_frame, FuncAddr function);

  // Invoked on function exit.
  // @param retval the return value from the function returning, e.g. the
  //    contents of the eax register.
  // @returns the return address this invocation should have returned to.
  static RetAddr WINAPI TraceExit(RetValueWord retval);

  // Overrides from ETWTraceProvider.
  virtual void OnEventsEnabled();
  virtual void OnEventsDisabled();

 private:
  void OnProcessAttach();
  void OnProcessDetach();
  void OnThreadAttach();
  void OnThreadDetach();

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

  typedef std::vector<std::pair<RetAddr, FuncAddr> > ReturnStack;

  // The number of trace entries we log in a batch. There is a maximal
  // event size which appears to be inclusive of the trace header and
  // some amount of overhead, which is ~124 bytes on Windows Vista.
  // We leave a size slop of 256 bytes in case other Windowsen
  // have slightly higher overhead.
  static const size_t kBatchEntriesBufferSize =
      (TRACE_MESSAGE_MAXIMUM_SIZE - 256);
  static const size_t kNumBatchTraceEntries =
      kBatchEntriesBufferSize / sizeof(FuncAddr);

  // We keep a structure of this type for each thread.
  class ThreadLocalData;
  friend ThreadLocalData;

  // Flushes the batch entry traces in data to the ETW log.
  void FlushBatchEntryTraces(ThreadLocalData* data);

  // Each entry in the captured data->traces[] that points to pexit
  // is fixed to point to the corresponding trace in stack. This is
  // necessary because when exit tracing is enabled, the return address
  // of each entered function is rewritten to penter.
  static void FixupBackTrace(const ReturnStack& stack,
                             TraceEnterExitEventData *data);

  ThreadLocalData *GetThreadData();
  ThreadLocalData *GetOrAllocateThreadData();

  bool SetThreadLocalData(ThreadLocalData *data);
  void FreeThreadLocalData();

  // Protects our thread local data list.
  Lock lock_;
  // We keep all thread local data blocks in a double linked list,
  // to allow us to clean up and log dangling data on process exit.
  LIST_ENTRY thread_data_list_head_;  // Under lock_

  // TLS index to our thread local data.
  DWORD tls_index_;
};

#endif  // SAWBUCK_CALL_TRACE_CALL_TRACE_MAIN_H_
