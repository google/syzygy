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
//
// Implementation of the CallTrace call tracing DLL.

#include "syzygy/call_trace/call_trace_client.h"

#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include "base/at_exit.h"
#include "base/logging.h"
#include "base/logging_win.h"
#include "syzygy/call_trace/call_trace_defs.h"
#include "syzygy/call_trace/call_trace_rpc.h"
#include "syzygy/call_trace/dlist.h"

namespace {

void CompileAsserts() {
  TraceModuleData data;
  MODULEENTRY32 module;
  // Make sure we have the correct size for the module name field.
  C_ASSERT(ARRAYSIZE(data.module_name) == ARRAYSIZE(module.szModule));
}

void CopyArguments(ArgumentWord *dst, const ArgumentWord *src, size_t num) {
  // Copy the arguments under an SEH handler so
  // we don't crash by underrunning the stack.
  __try {
    for (size_t i = 0; i < num; ++i)
      *dst++ = *src++;
  } __except(EXCEPTION_EXECUTE_HANDLER) {
  }
}

}  // namespace

// Our AtExit manager required by base.
base::AtExitManager at_exit;

// All tracing runs through this object.
CallTraceClient call_trace_client;


void __declspec(naked) pexit_hook() {
  __asm {
    // Stash the volatile registers.
    push eax
    push ecx
    push edx
    pushfd

    // Push the function return value.
    push eax
    call CallTraceClient::ExitHook

    popfd
    pop edx
    pop ecx

    // The return value from TraceExit is the real return value.
    // Swap it for the stashed EAX on stack and return to it.
    xchg eax, DWORD PTR[esp]
    ret
  }
}

extern "C" void __declspec(naked) _cdecl _pentry_hook() {
  __asm {
    // Stash volatile registers.
    push eax
    push ecx
    push edx
    pushfd

    // Retrieve our return address, and adjust it to the beginning of
    // the function we're entering. The compiler inserts an absolute jmp
    // to _penter at the start of each function, so adjusting by five
    // points us to the start of the function.
    mov eax, DWORD PTR[esp + 0x10]
    sub eax, 5
    push eax

    // Calculate the position of the return address on stack, and
    // push it. This becomes the EntryFrame argument.
    lea eax, DWORD PTR[esp + 0x18]
    push eax
    call CallTraceClient::EntryHook

    // Restore volatile registers and return.
    popfd
    pop edx
    pop ecx
    pop eax
    ret
  }
}

// The calling convention to this function is non-conventional.
// This function is invoked by a generated stub that does
// push <original function>
// jmp _indirect_penter
// This function will trace the entry to <original function>,
// and then on exit, will organize to jump to that function
// to execute it.
extern "C" void __declspec(naked) _cdecl _indirect_pentry_hook() {
  __asm {
    // Stash volatile registers.
    push eax
    push ecx
    push edx
    pushfd

    // Retrieve the address pushed by our caller.
    mov eax, DWORD PTR[esp + 0x10]
    push eax

    // Calculate the position of the return address on stack, and
    // push it. This becomes the EntryFrame argument.
    lea eax, DWORD PTR[esp + 0x18]
    push eax
    call CallTraceClient::EntryHook

    // Restore volatile registers.
    popfd
    pop edx
    pop ecx
    pop eax

    // Return to the address pushed by our caller.
    ret
  }
}

class CallTraceClient::ThreadLocalData {
 public:
  explicit ThreadLocalData(CallTraceClient* ctc);
  ~ThreadLocalData();

  bool SufficientSpace(size_t num_bytes) {
    return buffer_info_.buffer_size >= buffer_info_.bytes_written + num_bytes;
  }

  // We keep our thread local data entries in a doubly-linked list
  // to allow us to flush and cleanup on process detach notification
  // in the process exit case.
  LIST_ENTRY thread_data_list_;
  CallTraceClient* call_trace_client_;

  // The call trace buffer info and pointer.
  CallTraceBufferInfo buffer_info_;
  uint8 * buffer_ptr_;

  // The shadow return stack we use when function exit is traced.
  ReturnStack return_stack_;
};

CallTraceClient::CallTraceClient()
    : tls_index_(::TlsAlloc()),
      enabled_event_(NULL) {
  InitializeListHead(&thread_data_list_head_);
}

CallTraceClient::~CallTraceClient() {
  if (TLS_OUT_OF_INDEXES != tls_index_)
    ::TlsFree(tls_index_);

  DCHECK(IsListEmpty(&thread_data_list_head_));
}

BOOL WINAPI CallTraceClient::DllMain(DWORD reason, LPVOID reserved) {
  switch (reason) {
    case DLL_PROCESS_ATTACH:
      OnProcessAttach();
      break;
    case DLL_PROCESS_DETACH:
      OnProcessDetach();
      break;
    case DLL_THREAD_ATTACH:
      OnThreadAttach();
      break;
    case DLL_THREAD_DETACH:
      OnThreadDetach();
      break;
  }

  return TRUE;
}

void CallTraceClient::OnEventsEnabled() {
  if (IsTracing(TRACE_FLAG_LOAD_EVENTS)) {
    CHandle snap(::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,
                 ::GetCurrentProcessId()));

    if (NULL != snap.m_h) {
      MODULEENTRY32 module = { sizeof(module) };

      if (!Module32First(snap, &module))
        return;

      do {
        TraceModule(module.modBaseAddr, module.modBaseSize,
                    module.szModule,
                    module.szExePath);
      } while (::Module32Next(snap, &module));
    }
  }

  UpdateEvents(IsTracing(TRACE_FLAG_BATCH_ENTER));
}

void CallTraceClient::UpdateEvents(bool is_tracing) {
  if (is_tracing) {
    if (enabled_event_ != NULL)
      ::SetEvent(enabled_event_);
    if (disabled_event_ != NULL)
      ::ResetEvent(disabled_event_);
  } else {
    if (enabled_event_ != NULL)
      ::ResetEvent(enabled_event_);
    if (disabled_event_ != NULL)
      ::SetEvent(disabled_event_);
  }
}

void CallTraceClient::OnEventsDisabled() {
  {
    base::AutoLock lock(lock_);
    // Last gasp logging for this session.
    // While we do all of the below under a lock, this is still racy,
    // in that the other threads in the process will still be running,
    // and may be adding data to the buffers and/or trying to unqueue
    // them as we go.
    if (!IsListEmpty(&thread_data_list_head_)) {
      ThreadLocalData* data = CONTAINING_RECORD(thread_data_list_head_.Flink,
                                                ThreadLocalData,
                                                thread_data_list_);

      while (true) {
        if (data->data_.num_calls != 0) {
          FlushBatchEntryTraces(data);
          DCHECK_EQ(0U, data->data_.num_calls);
        }

        // Bail the loop if we're at the end of the list.
        if (data->thread_data_list_.Flink == &thread_data_list_head_)
          break;

        // Walk forward.
        data = CONTAINING_RECORD(data->thread_data_list_.Flink,
                                 ThreadLocalData,
                                 thread_data_list_);
      }
    }
  }

  UpdateEvents(false);
}

void CallTraceClient::OnProcessAttach() {
  ConnectToServer();

  if (IsTracing(TRACE_FLAG_LOAD_EVENTS))
    TraceEvent(TRACE_PROCESS_ATTACH_EVENT);

  UpdateEvents(IsTracing(TRACE_FLAG_BATCH_ENTER));
}

void CallTraceClient::OnProcessDetach() {
  if (IsTracing(TRACE_FLAG_LOAD_EVENTS))
    TraceEvent(TRACE_PROCESS_DETACH_EVENT);

  OnThreadDetach();

  // Last gasp logging. If the process is exiting, then other threads
  // may have been terminated, so it falls to us to log their buffers.
  while (true) {
    ThreadLocalData* data = NULL;

    // Get next remaining buffer under the lock, if any.
    {
      base::AutoLock lock(lock_);
      if (IsListEmpty(&thread_data_list_head_)) {
        // We're done, break out of the loop.
        break;
      }

      // Get the front of the list.
      data = CONTAINING_RECORD(thread_data_list_head_.Flink,
                               ThreadLocalData,
                               thread_data_list_);

      RemoveHeadList(&thread_data_list_head_);
    }

    if (data->data_.num_calls != 0)
      FlushBatchEntryTraces(data);

    // Clear the list so the destructor won't mess up.
    InitializeListHead(&data->thread_data_list_);
    delete data;
  }

  DisconnectFromServer();
}

void CallTraceClient::OnThreadAttach() {
  if (IsTracing(TRACE_FLAG_THREAD_EVENTS))
    TraceEvent(TRACE_THREAD_ATTACH_EVENT);
}

void CallTraceClient::OnThreadDetach() {
  if (IsTracing(TRACE_FLAG_THREAD_EVENTS))
    TraceEvent(TRACE_THREAD_DETACH_EVENT);

  FreeThreadLocalData();
}

bool CallTraceClient::IsTracing() {
  return enable_level() >= CALL_TRACE_LEVEL;
}

bool CallTraceClient::IsTracing(TraceEventFlags flag) {
  return enable_level() >= CALL_TRACE_LEVEL && 0 != (enable_flags() & flag);
}

void CallTraceClient::TraceEnterExit(TraceEventType type,
                                  const TraceEnterExitEventData& data) {
  base::win::EtwMofEvent<1> event(kCallTraceEventClass, type, CALL_TRACE_LEVEL);
  size_t data_len = offsetof(TraceEnterExitEventData, traces) +
      data.num_traces * sizeof(void *);

  event.SetField(0, data_len, &data);
  Log(event.get());
}

void CallTraceClient::TraceModule(ModuleAddr base, size_t size,
    const wchar_t *name, const wchar_t *exe) {
# if 0
  // TODO(siggi): Trace using the NT Kernel trace event format.
  base::win::EtwMofEvent<2> event(kCallTraceEventClass,
                                  TRACE_MODULE_EVENT,
                                  CALL_TRACE_LEVEL);
  TraceModuleData data = { base, size };
  wcsncpy_s(data.module_name, name, ARRAYSIZE(data.module_name));
  event.SetField(0, offsetof(TraceModuleData, module_exe), &data);
  event.SetField(1, (1 + wcslen(exe)) * sizeof(wchar_t), exe);
  Log(event.get());
#endif
}

void CallTraceClient::TraceEvent(TraceEventType flag) {
  base::win::EtwMofEvent<1> event(kCallTraceEventClass, flag, CALL_TRACE_LEVEL);
  Log(event.get());
}

/* static */
void CallTraceClient::EntryHook(EntryFrame *entry_frame, FuncAddr function) {
  // Stash the last error for restoring on return.
  DWORD err = ::GetLastError();

  // Bail if we're not tracing entry in full.
  if (call_trace_client.IsTracing(TRACE_FLAG_ENTER)) {
    ThreadLocalData *data = call_trace_client.GetOrAllocateThreadData();
    CHECK(data != NULL);
    void * write_ptr = data->GetWritePtr();
    CHECK(write_ptr != NULL);

    // Placement new the record prefix into the write buffer.
    RecordPrefix* prefix = new (write_ptr) RecordPrefix(
        TRACE_ENTER_EVENT, sizeof(TraceEnterExitEventData));
    write_ptr += sizeof(*prefix);

    // Placement new the event data into the write buffer.
    TraceEnterExitEventData* event = new (write_ptr) TraceEnterExitEventData(
        function, call_trace_client.IsTracing(TRACE_FLAG_ENTER_STACK_TRACE
    event_data.depth = (NULL == data) ? 0 : data->return_stack_.size();
    event_data.function = function;
    CopyArguments(event_data.args,
                  entry_frame->args,
                  ARRAYSIZE(event_data.args));
    // TODO(siggi): It might make sense to optimize this, and not do a stack
    //    trace capture when we're being entered directly from another function
    //    we captured. It's a little difficult to distinguish this from e.g.
    //    entry through a function we didn't capture in the same module, or
    //    entry indirectly through e.g. a callback, so leaving as a possible
    //    later time optimization.
    if (module.enable_flags() & TRACE_FLAG_STACK_TRACES) {
      event_data.num_traces =
          ::RtlCaptureStackBackTrace(2,
                                     arraysize(event_data.traces),
                                     const_cast<PVOID*>(event_data.traces),
                                     NULL);
      if (data != NULL)
        FixupBackTrace(data->return_stack_, &event_data);
    } else {
      event_data.num_traces = 0;
    }

    module.TraceEnterExit(TRACE_ENTER_EVENT, event_data);

    // Divert function return to pexit if we're tracing function exit.
    if (NULL != data && module.IsTracing(TRACE_FLAG_EXIT)) {
      // Save the old return address.
      data->return_stack_.push_back(
          std::make_pair(entry_frame->retaddr, function));
      // And modify the return address in our frame.
      entry_frame->retaddr = reinterpret_cast<RetAddr>(pexit);
    }
  }

  ::SetLastError(err);
}

/* static */
RetAddr CallTraceClient::ExitHook(RetValueWord retval) {
  // Stash the last error for restoring on return.
  DWORD err = ::GetLastError();

  ThreadLocalData *data = call_trace_client.GetThreadData();
  if (NULL == data || data->return_stack_.empty()) {
    // Ouch, someone's returning one too many times. There's no recovery
    // possible, so we bugcheck.
    CHECK(FALSE) << "Shadow stack out of whack!";
  }

  // Get the top of the stack, we don't pop it yet, because
  // the fixup function needs to see our entry to fixup correctly.
  std::pair<RetAddr, FuncAddr>& top = data->return_stack_.back();

  if (module.IsTracing(TRACE_FLAG_EXIT)) {
    DCHECK(data->buffer_ptr_ != NULL);
    if (!data->
    size_t bytes_required = \
        sizeof(RecordHeader) + sizeof(TraceEnterExitEventData);
    if (data->buffer_info.buffer_size <= data->buffer_info.buffer_size + bytes_required) {
      CallTraceClientExchangeBuffers(call_trace_client.binding,
                                     &call_trace_client.buffer_info).
    }
    data->
    TraceEnterExitEventData event_data;
    event_data.depth = data->return_stack_.size();
    event_data.function = top.second;
    event_data.retval = retval;
    if (module.enable_flags() & TRACE_FLAG_STACK_TRACES) {
      event_data.num_traces = ::RtlCaptureStackBackTrace(
          2, kMaxTraceDepth, const_cast<PVOID*>(event_data.traces), NULL);
      FixupBackTrace(data->return_stack_, &event_data);
    } else {
      event_data.num_traces = 0;
    }
    module.TraceEnterExit(TRACE_EXIT_EVENT, event_data);
  }

  RetAddr return_address = top.first;

  // Pop the stack.
  data->return_stack_.pop_back();

  // Restore last error as very last thing.
  ::SetLastError(err);

  // And return the original return address.
  return return_address;
}

void CallTraceClient::TraceBatchEnter(FuncAddr function) {
  ThreadLocalData* data = GetOrAllocateThreadData();
  if (data == NULL)
    return;

  DCHECK(data->data_.num_calls < kNumBatchTraceEntries);
  data->data_.calls[data->data_.num_calls].function = function;
  data->data_.calls[data->data_.num_calls].tick_count = ::GetTickCount();
  ++data->data_.num_calls;

  if (data->data_.num_calls == kNumBatchTraceEntries)
    FlushBatchEntryTraces(data);
}

void CallTraceClient::FlushBatchEntryTraces(ThreadLocalData* data) {
  DCHECK(data != NULL);

  if (data->data_.num_calls == 0) {
    return;
  }

  // The logged call times are relative to the current time.
  // This makes life easier on the user, who can use the event
  // time as the base time for all entries.
  DWORD current_tick_count = ::GetTickCount();
  for (size_t i = 0; i < data->data_.num_calls; ++i) {
    data->data_.calls[i].ticks_ago =
        current_tick_count - data->data_.calls[i].tick_count;
  }

  base::win::EtwMofEvent<1> batch_event(kCallTraceEventClass,
                                        TRACE_BATCH_ENTER,
                                        CALL_TRACE_LEVEL);

  size_t len = FIELD_OFFSET(TraceBatchEnterData, calls) +
        sizeof(data->data_.calls[0]) * data->data_.num_calls;
  batch_event.SetField(0, len, &data->data_);

  Log(batch_event.get());

  data->data_.num_calls = 0;
}

void CallTraceClient::FixupBackTrace(const ReturnStack& stack,
                                  TraceEnterExitEventData *data) {
  ReturnStack::const_reverse_iterator it(stack.rbegin()), end(stack.rend());
  for (size_t i = 0; i < data->num_traces && it != end; ++i) {
    if (pexit == data->traces[i]) {
      data->traces[i] = it->first;
      ++it;
    }
  }
}

CallTraceClient::ThreadLocalData *CallTraceClient::GetThreadData() {
  if (TLS_OUT_OF_INDEXES == tls_index_)
    return NULL;

  return reinterpret_cast<ThreadLocalData*>(::TlsGetValue(tls_index_));
}

CallTraceClient::ThreadLocalData *CallTraceClient::GetOrAllocateThreadData() {
  if (TLS_OUT_OF_INDEXES == tls_index_)
    return NULL;

  ThreadLocalData *data=
      reinterpret_cast<ThreadLocalData*>(::TlsGetValue(tls_index_));
  if (data)
    return data;

  data = new ThreadLocalData(this);
  if (data == NULL) {
    LOG(ERROR) << "Unable to allocate per-thread data";
    return NULL;
  }

  if (!::TlsSetValue(tls_index_, data)) {
    LOG(ERROR) << "Unable to set per-thread data";

    delete data;
    return NULL;
  }

  return data;
}

void CallTraceClient::FreeThreadLocalData() {
  // Free the thread local data if it's been created.
  ThreadLocalData *data = GetThreadData();

  if (data == NULL)
    return;

  if (data->data_.num_calls)
    FlushBatchEntryTraces(data);

  delete data;
  ::TlsSetValue(tls_index_, NULL);
}

void CallTraceClient::CreateSession() {
  base::AutoLock scoped_lock(lock_);

}

void CallTraceClient::CloseSession() {
  if (session_handle_ != NULL)
    return;

  RpcTryExcept
  {
    if (!CallTraceClientCloseSession(&session_handle_))
      LOG(ERROR) << "Failed to close call-trace session!";
  }
  RpcExcept(1)
  {
    LOG(ERROR) << "RPC error closing call-trace session!";
  }
  RpcEndExcept;

  *session_handle_ == NULL;
}

void CallTraceClient::ExchangeBuffers() {
  if (session_handle_ != NULL)
    return;

  boolean rc;

  RpcTryExcept
  {
    result = CallTraceClientExchangeBuffers(&session_handle_,
                                            &call_trace_buffer_))
      LOG(ERROR) << "Failed to exchange call-trace buffers!"
  }
  RpcExcept(1)
  {
    LOG(ERROR) << "RPC error exchanging call-trace buffers.";
  }
  RpcEndExcept;
}

void CallTraceClient::ReturnBuffer() {
}


CallTraceClient::ThreadLocalData::ThreadLocalData(CallTraceClient* module)
    : module_(module), buffer_ptr_(NULL) {
  data_.thread_id = ::GetCurrentThreadId();
  data_.num_calls = 0;

  base::AutoLock lock(module_->lock_);
  InsertTailList(&module->thread_data_list_head_, &thread_data_list_);
}

CallTraceClient::ThreadLocalData::~ThreadLocalData() {
  base::AutoLock lock(module_->lock_);
  RemoveEntryList(&thread_data_list_);
}
