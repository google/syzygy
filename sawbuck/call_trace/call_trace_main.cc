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
#include "sawbuck/call_trace/call_trace_main.h"
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include "base/at_exit.h"
#include "base/logging.h"
#include "base/logging_win.h"
#include "sawbuck/call_trace/call_trace_defs.h"
#include "sawbuck/call_trace/dlist.h"


namespace {

// {3D7926F7-6F59-4635-AAFD-0E95710FF60D}
const GUID kCallTraceLogProvider =
    { 0x3d7926f7, 0x6f59, 0x4635,
        { 0xaa, 0xfd, 0xe, 0x95, 0x71, 0xf, 0xf6, 0xd } };

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
TracerModule module;


void __declspec(naked) pexit() {
  __asm {
    // Stash the volatile registers.
    push eax
    push ecx
    push edx

    // Push the function return value.
    push eax
    call TracerModule::TraceExit
    pop edx
    pop ecx

    // The return value from TraceExit is the real return value.
    // Swap it for the stashed EAX on stack and return to it.
    xchg eax, DWORD PTR[esp]
    ret
  }
}

extern "C" void __declspec(naked) _cdecl _penter() {
  __asm {
    // Stash volatile registers.
    push eax
    push ecx
    push edx
    // Retrieve our return address, and adjust it to the beginning of
    // the function we're entering. The compiler inserts an absolute jmp
    // to _penter at the start of each function, so adjusting by five
    // points us to the start of the function.
    mov eax, DWORD PTR[esp + 0x0C]
    sub eax, 5
    push eax
    // Calculate the position of the return address on stack, and
    // push it. This becomes the EntryFrame argument.
    lea eax, DWORD PTR[esp + 0x14]
    push eax
    call TracerModule::TraceEntry

    // Restore volatile registers and return.
    pop edx
    pop ecx
    pop eax
    ret
  }
}

class TracerModule::ThreadLocalData {
 public:
  explicit ThreadLocalData(TracerModule* module);
  ~ThreadLocalData();

  // We keep our thread local data entries in a doubly-linked list
  // to allow us to flush and cleanup on process detach notification
  // in the process exit case.
  LIST_ENTRY thread_data_list_;
  TracerModule* module_;

  // The batch call traces are kept here, aliased to a sufficiently large
  // buffer to store kNumBatchTraceEntries.
  union {
    TraceBatchEnterData data_;
    char buf_[FIELD_OFFSET(TraceBatchEnterData, functions) +
              kBatchEntriesBufferSize];
  };

  // The shadow return stack we use when function exit is traced.
  ReturnStack return_stack_;
};

TracerModule::TracerModule()
    : EtwTraceProvider(kCallTraceProvider),
      tls_index_(::TlsAlloc()) {
  // Initialize ETW logging for ourselves.
  logging::LogEventProvider::Initialize(kCallTraceLogProvider);

  InitializeListHead(&thread_data_list_head_);
}

TracerModule::~TracerModule() {
  if (TLS_OUT_OF_INDEXES != tls_index_)
    ::TlsFree(tls_index_);

  DCHECK(IsListEmpty(&thread_data_list_head_));
}

BOOL WINAPI TracerModule::DllMain(DWORD reason, LPVOID reserved) {
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

BOOL WINAPI DllMain(HMODULE instance, DWORD reason, LPVOID reserved) {
  return module.DllMain(reason, reserved);
}

void TracerModule::OnEventsEnabled() {
  if (!IsTracing(TRACE_FLAG_LOAD_EVENTS))
    return;

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

void TracerModule::OnEventsDisabled() {
}

void TracerModule::OnProcessAttach() {
  Register();
  if (IsTracing(TRACE_FLAG_LOAD_EVENTS))
    TraceEvent(TRACE_PROCESS_ATTACH_EVENT);
}

void TracerModule::OnProcessDetach() {
  if (IsTracing(TRACE_FLAG_LOAD_EVENTS))
    TraceEvent(TRACE_PROCESS_DETACH_EVENT);

  OnThreadDetach();

  // Last gasp logging. If the process is exiting, then other threads
  // may have been terminated, so it falls to us to log their buffers.
  while (true) {
    ThreadLocalData* data = NULL;

    // Get next remaining buffer under the lock, if any.
    {
      AutoLock lock(lock_);
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

    if (data->data_.num_functions != 0)
      FlushBatchEntryTraces(data);

    // Clear the list so the destructor won't mess up.
    InitializeListHead(&data->thread_data_list_);
    delete data;
  }

  Unregister();
}

void TracerModule::OnThreadAttach() {
  if (IsTracing(TRACE_FLAG_THREAD_EVENTS))
    TraceEvent(TRACE_THREAD_ATTACH_EVENT);
}

void TracerModule::OnThreadDetach() {
  if (IsTracing(TRACE_FLAG_THREAD_EVENTS))
    TraceEvent(TRACE_THREAD_DETACH_EVENT);

  FreeThreadLocalData();
}

bool TracerModule::IsTracing() {
  return enable_level() >= CALL_TRACE_LEVEL;
}

bool TracerModule::IsTracing(TraceEventFlags flag) {
  return enable_level() >= CALL_TRACE_LEVEL && 0 != (enable_flags() & flag);
}

void TracerModule::TraceEnterExit(TraceEventType type,
                                  const TraceEnterExitEventData& data) {
  EtwMofEvent<1> event(kCallTraceEventClass, type, CALL_TRACE_LEVEL);
  size_t data_len = offsetof(TraceEnterExitEventData, traces) +
      data.num_traces * sizeof(void *);

  event.SetField(0, data_len, &data);
  Log(event.get());
}

void TracerModule::TraceModule(ModuleAddr base, size_t size,
    const wchar_t *name, const wchar_t *exe) {
  // TODO(siggi): Trace using the NT Kernel trace event format.
  EtwMofEvent<2> event(kCallTraceEventClass,
                       TRACE_MODULE_EVENT,
                       CALL_TRACE_LEVEL);
  TraceModuleData data = { base, size };
  wcsncpy_s(data.module_name, name, ARRAYSIZE(data.module_name));
  event.SetField(0, offsetof(TraceModuleData, module_exe), &data);
  event.SetField(1, (1 + wcslen(exe)) * sizeof(wchar_t), exe);
  Log(event.get());
}

void TracerModule::TraceEvent(TraceEventType flag) {
  EtwMofEvent<1> event(kCallTraceEventClass, flag, CALL_TRACE_LEVEL);
  Log(event.get());
}

void TracerModule::TraceEntry(EntryFrame *entry_frame, FuncAddr function) {
  // Stash the last error for restoring on return.
  DWORD err = ::GetLastError();

  if (module.IsTracing(TRACE_FLAG_BATCH_ENTER))
    module.TraceBatchEnter(function);

  // Bail if we're not tracing entry in full.
  if (module.IsTracing(TRACE_FLAG_ENTER)) {
    ThreadLocalData *data = module.GetOrAllocateThreadData();

    TraceEnterExitEventData event_data = {};
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

RetAddr TracerModule::TraceExit(RetValueWord retval) {
  // Stash the last error for restoring on return.
  DWORD err = ::GetLastError();

  ThreadLocalData *data = module.GetThreadData();
  if (NULL == data || data->return_stack_.empty()) {
    // Ouch, someone's returning one too many times. There's no recovery
    // possible, so we bugcheck.
    CHECK(FALSE) << "Shadow stack out of whack!";
  }

  // Get the top of the stack, we don't pop it yet, because
  // the fixup function needs to see our entry to fixup correctly.
  std::pair<RetAddr, FuncAddr> top(data->return_stack_.back());

  if (module.IsTracing(TRACE_FLAG_EXIT)) {
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

  // Pop the stack.
  data->return_stack_.pop_back();

  // Restore last error as very last thing.
  ::SetLastError(err);

  // And return the original return address.
  return top.first;
}

void TracerModule::TraceBatchEnter(FuncAddr function) {
  ThreadLocalData* data = GetOrAllocateThreadData();
  if (data == NULL)
    return;

  DCHECK(data->data_.num_functions < kNumBatchTraceEntries);
  data->data_.functions[data->data_.num_functions++] = function;

  if (data->data_.num_functions == kNumBatchTraceEntries)
    FlushBatchEntryTraces(data);
}

void TracerModule::FlushBatchEntryTraces(ThreadLocalData* data) {
  DCHECK(data != NULL);

  EtwMofEvent<1> batch_event(kCallTraceEventClass,
                             TRACE_BATCH_ENTER,
                             CALL_TRACE_LEVEL);

  size_t len = FIELD_OFFSET(TraceBatchEnterData, functions) +
        sizeof(data->data_.functions[0]) * data->data_.num_functions;
  batch_event.SetField(0, len, &data->data_);

  Log(batch_event.get());

  data->data_.num_functions = 0;
}

void TracerModule::FixupBackTrace(const ReturnStack& stack,
                                  TraceEnterExitEventData *data) {
  ReturnStack::const_reverse_iterator it(stack.rbegin()), end(stack.rend());
  for (size_t i = 0; i < data->num_traces && it != end; ++i) {
    if (pexit == data->traces[i]) {
      data->traces[i] = it->first;
      ++it;
    }
  }
}

TracerModule::ThreadLocalData *TracerModule::GetThreadData() {
  if (TLS_OUT_OF_INDEXES == tls_index_)
    return NULL;

  return reinterpret_cast<ThreadLocalData*>(::TlsGetValue(tls_index_));
}

TracerModule::ThreadLocalData *TracerModule::GetOrAllocateThreadData() {
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

void TracerModule::FreeThreadLocalData() {
  // Free the thread local data if it's been created.
  ThreadLocalData *data = GetThreadData();

  if (data == NULL)
    return;

  delete data;
  ::TlsSetValue(tls_index_, NULL);
}

TracerModule::ThreadLocalData::ThreadLocalData(TracerModule* module)
    : module_(module) {
  AutoLock lock(module_->lock_);
  data_.thread_id = ::GetCurrentThreadId();
  data_.num_functions = 0;
  InsertTailList(&module->thread_data_list_head_, &thread_data_list_);
}

TracerModule::ThreadLocalData::~ThreadLocalData() {
  AutoLock lock(module_->lock_);

  RemoveEntryList(&thread_data_list_);
}
