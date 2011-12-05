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
// Implementation of the Call Trace Client DLL.

#include "syzygy/call_trace/client_rpc.h"

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <vector>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/lazy_instance.h"
#include "base/logging.h"
#include "base/logging_win.h"
#include "base/win/pe_image.h"
#include "sawbuck/common/com_utils.h"
#include "syzygy/call_trace/client_utils.h"
#include "syzygy/call_trace/call_trace_defs.h"
#include "syzygy/call_trace/rpc_helpers.h"

using call_trace::client::Client;

namespace {

// Our AtExit manager required by base.
base::AtExitManager at_exit;

// All tracing runs through this object.
base::LazyInstance<Client> static_client_instance(base::LINKER_INITIALIZED);

// Copies the arguments under an SEH handler so we don't crash by under-running
// the stack.
void CopyArguments(ArgumentWord *dst, const ArgumentWord *src, size_t num) {
  __try {
    for (size_t i = 0; i < num; ++i)
      *dst++ = *src++;
  } __except(EXCEPTION_EXECUTE_HANDLER) {
  }
}

// Helper structure to capture and restore the current threads last win32
// error-code value.
struct ScopedLastErrorKeeper {
  ScopedLastErrorKeeper() : last_error(::GetLastError()) {
  }

  ~ScopedLastErrorKeeper() {
    ::SetLastError(last_error);
  }

  DWORD last_error;
};

}  // namespace

BOOL WINAPI DllMain(HMODULE instance, DWORD reason, LPVOID reserved) {
  return Client::Instance()->DllMain(instance, reason, reserved);
}

// This instrumentation hook is used for all function calls except for
// calls to a DLL entry point.
//
// Note that the calling convention to this function is non-conventional.
// This function is invoked by a generated stub that does:
//
//     push <original function>
//     jmp _indirect_penter
//
// This function will trace the entry to <original function>, and then on
// exit, will arrange for execution to jump to <original function>. If
// required, it will also arrange for the return from <original function>
// to be captured.
extern "C" void __declspec(naked) _cdecl _indirect_penter() {
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
    call Client::FunctionEntryHook

    // Restore volatile registers.
    popfd
    pop edx
    pop ecx
    pop eax

    // Return to the address pushed by our caller.
    ret
  }
}

// This instrumentation hook is used for calls to a DLL's entry point.
//
// Note that the calling convention to this function is non-conventional.
// This function is invoked by a generated stub that does:
//
//     push <original dllmain>
//     jmp _indirect_penter_dllmain
//
// This function will trace the entry to <original dllmain>, capture the
// nature of the module event being generated, and then on exit, will
// arrange for execution to jump to <original dllmain>. If required,
// it will also arrange for the return from <original dllmain> to be
// captured.
extern "C" void __declspec(naked) _cdecl _indirect_penter_dllmain() {
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
    call Client::DllMainEntryHook

    // Restore volatile registers.
    popfd
    pop edx
    pop ecx
    pop eax

    // Return to the address pushed by our caller.
    ret
  }
}

// This instrumentation hook is used on return from a function (unless
// the function is a DLL entry-point).
//
// Note that the invocation pattern by which this function is executed
// is unusual. As required, the instrumentation code hanging off of
// _indirect_penter will arrange to replace the return address for the
// function about to be invoked such that the function returns to this
// hook instead.
//
// This is required when exit tracing is enabled.
void __declspec(naked) pexit() {
  __asm {
    // Stash the volatile registers.
    push eax
    push ecx
    push edx
    pushfd

    // Push the function return value.
    push eax
    // Calculate the stack pointer prior to our entry.
    lea eax, DWORD PTR[esp + 20]
    push eax
    call Client::FunctionExitHook

    popfd
    pop edx
    pop ecx

    // The return value from Client::FunctionExitHook is the real return
    // value. Swap it for the stashed EAX on stack and return to it.
    xchg eax, DWORD PTR[esp]
    ret
  }
}

// This instrumentation hook is used on return from a DLL's entry-point.
//
// Note that the invocation pattern by which this function is executed is
// unusual. The instrumentation code hanging off of _indirect_penter_dllmain
// will arrange to replace the return address for the function about to be
// invoked such that the function returns to this hook instead.
//
// This allows module and thread detachment events to be captured correctly.
void __declspec(naked) pexit_dllmain() {
  __asm {
    // Stash the volatile registers.
    push eax
    push ecx
    push edx
    pushfd

    // Push the function return value.
    push eax
    // Calculate the stack pointer prior to our entry.
    lea eax, DWORD PTR[esp + 20]
    push eax
    call Client::DllMainExitHook

    popfd
    pop edx
    pop ecx

    // The return value from Client::DllMainExitHook is the real return
    // value. Swap it for the stashed EAX on stack and return to it.
    xchg eax, DWORD PTR[esp]
    ret
  }
}

namespace call_trace {
namespace client {

class Client::ThreadLocalData {
 public:
  explicit ThreadLocalData(Client* module);

  bool IsInitialized() const {
    return segment.header != NULL;
  }

  // Allocates a new FuncCall.
  FuncCall* AllocateFuncCall();

  // Flushes the current trace file segment.
  bool FlushSegment();

  // The call trace client to which this data belongs.
  // TODO(rogerm): This field isn't necessary, it's only used in DCHECKs.
  Client* const client;

  // The owning thread's current trace-file segment, if any.
  TraceFileSegment segment;

  // The current batch record we're extending, if any.
  // This will point into the associated trace file segment's buffer.
  TraceBatchEnterData* batch;

  // The shadow return stack we use when function exit is traced.
  ShadowStack shadow_stack;

  // A placeholder for a pending module event (DLL_THREAD_DETACH or
  // DLL_PROCESS_DETACH) that will be processed by ::pexit_dllmain.
  // TODO(rogerm): is it possible to have more than one pending?
  ModuleEventStack module_event_stack;
};

Client::Client()
    : tls_index_(::TlsAlloc()) {
}

Client::~Client() {
  if (TLS_OUT_OF_INDEXES != tls_index_)
    ::TlsFree(tls_index_);
}

Client* Client::Instance() {
  return static_client_instance.Pointer();
}

BOOL Client::DllMain(HMODULE /* module */,
                     DWORD reason,
                     LPVOID /* reserved */) {
  switch (reason) {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
      // Session creation and thread-local data allocation are performed
      // just-in-time when the first instrumented entry point is invoked.
      break;

    case DLL_PROCESS_DETACH:
      OnClientProcessDetach();
      break;

    case DLL_THREAD_DETACH:
      OnClientThreadDetach();
      break;

    default:
      NOTREACHED() << "Unrecognized reason in DllMain: " << reason << ".";
  }

  return TRUE;
}

void Client::OnClientProcessDetach() {
  if (!session_.IsTracing())
    return;

  session_.CloseSession();
  FreeThreadData();
  session_.FreeSharedMemory();
}

void Client::OnClientThreadDetach() {
  if (!session_.IsTracing())
    return;

  // Get the thread data. If this thread has never called an instrumented
  // function, no thread local call trace data will be associated with it.
  ThreadLocalData* data = GetThreadData();
  if (data != NULL) {
    session_.ReturnBuffer(&data->segment);
    FreeThreadData(data);
  }
}

void Client::DllMainEntryHook(EntryFrame *entry_frame, FuncAddr function) {
  ScopedLastErrorKeeper save_and_restore_last_error;

  Client* client = Instance();
  CHECK(client != NULL) << "Failed to get call trace client instance.";

  if (client->session_.IsDisabled())
    return;

  HMODULE module = reinterpret_cast<HMODULE>(entry_frame->args[0]);
  DWORD reason = entry_frame->args[1];

  client->LogEvent_FunctionEntry(entry_frame, function, module, reason);
}

void Client::FunctionEntryHook(EntryFrame *entry_frame, FuncAddr function) {
  ScopedLastErrorKeeper save_and_restore_last_error;

  Client* client = Instance();
  CHECK(client != NULL) << "Failed to get call trace client instance.";

  if (client->session_.IsDisabled())
    return;

  client->LogEvent_FunctionEntry(entry_frame, function, NULL, -1);
}

RetAddr Client::FunctionExitHook(const void* stack_pointer,
                                 RetValueWord retval) {
  ScopedLastErrorKeeper save_and_restore_last_error;

  Client* client = Instance();
  CHECK(client != NULL) << "Failed to get call trace client instance.";
  DCHECK(!client->session_.IsDisabled());
  DCHECK(client->session_.IsTracing());

  return client->LogEvent_FunctionExit(stack_pointer, retval);
}

RetAddr Client::DllMainExitHook(const void* stack_pointer,
                                RetValueWord retval) {
  ScopedLastErrorKeeper save_and_restore_last_error;

  Client* client = Instance();
  CHECK(client != NULL) << "Failed to get call trace client instance.";
  DCHECK(!client->session_.IsDisabled());
  DCHECK(client->session_.IsTracing());

  RetAddr value = client->LogEvent_FunctionExit(stack_pointer, retval);

  // Pop the module event stack.
  ThreadLocalData* data = client->GetThreadData();
  CHECK(data != NULL) << "Failed to get thread local data.";
  DCHECK(!data->module_event_stack.empty());

  const ModuleEventStackEntry& module_event = data->module_event_stack.back();
  client->LogEvent_ModuleEvent(data, module_event.module, module_event.reason);
  data->module_event_stack.pop_back();

  return value;
}

void Client::LogEvent_ModuleEvent(ThreadLocalData *data,
                                  HMODULE module,
                                  DWORD reason) {
  DCHECK(data != NULL);
  DCHECK(module != NULL);
  DCHECK(session_.IsTracing());

  // Perform a sanity check.
  switch (reason) {
    case DLL_PROCESS_ATTACH:
    case DLL_PROCESS_DETACH:
      break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
      if (!session_.IsEnabled(TRACE_FLAG_THREAD_EVENTS))
        return;
      break;

    default:
      LOG(WARNING) << "Unrecognized module event: " << reason << ".";
      return;
  }

  // Make sure the event we're about to write will fit.
  if (!data->segment.CanAllocate(sizeof(TraceModuleData))) {
    session_.ExchangeBuffer(&data->segment);
  }

  // Allocate a record in the log.
  TraceModuleData* module_event = reinterpret_cast<TraceModuleData*>(
      data->segment.AllocateTraceRecordImpl(ReasonToEventType(reason),
                                            sizeof(TraceModuleData)));
  DCHECK(module_event!= NULL);

  // Populate the log record.
  base::win::PEImage image(module);
  module_event->module_base_addr = module;
  module_event->module_base_size =
      image.GetNTHeaders()->OptionalHeader.SizeOfImage;
  module_event->module_checksum = image.GetNTHeaders()->OptionalHeader.CheckSum;
  module_event->module_time_date_stamp =
      image.GetNTHeaders()->FileHeader.TimeDateStamp;
  if (::GetMappedFileName(::GetCurrentProcess(), module,
                          &module_event->module_name[0],
                          arraysize(module_event->module_name)) == 0) {
      DWORD error = ::GetLastError();
      LOG(ERROR) << "Failed to get module name: " << com::LogWe(error) << ".";
  }
  // TODO(rogerm): get rid of the module_exe field of TraceModuleData?
#ifdef NDEBUG
  module_event->module_exe[0] = L'\0';
#else
  ZeroMemory(&module_event->module_exe[0], sizeof(module_event->module_exe));
#endif

  // We need to flush module events right away, so that the module is
  // defined in the trace file before events using that module start to
  // occur (in another thread).
  //
  // TODO(rogerm): We don't really need to flush right away for detach
  //     events. We could be a little more efficient here.
  session_.ExchangeBuffer(&data->segment);
}


void Client::LogEvent_FunctionEntry(EntryFrame *entry_frame,
                                    FuncAddr function,
                                    HMODULE module,
                                    DWORD reason ) {
  // TODO(rogerm): Split this up so that we don't have to pass unused
  //     module and reason paramters on every call. This is really
  //     sub-optimal, so address it ASAP.

  // If we're not currently tracing then this is (one of) the first calls
  // to an instrumented function. We attempt to initialize a session. If
  // we're not able to initialize a session, we disable the call trace
  // client.
  ThreadLocalData *data = GetOrAllocateThreadData();
  CHECK(data != NULL) << "Failed to get call trace thread context.";

  if (!session_.IsTracing()) {
    base::AutoLock scoped_lock(init_lock_);
    if (session_.IsDisabled())
      return;

    if (!session_.IsTracing() && !session_.CreateSession(&data->segment)) {
      return;
    }
  }

  DCHECK(!session_.IsDisabled());
  DCHECK(session_.IsTracing());

  if (!data->IsInitialized()) {
    CHECK(session_.AllocateBuffer(&data->segment))
        << "Failed to allocate trace buffer.";
  }

  if ((module != NULL) &&
      (reason == DLL_PROCESS_ATTACH || reason == DLL_THREAD_ATTACH)) {
    LogEvent_ModuleEvent(data, module, reason);
  }

  // If we're in batch mode, just capture the basic call info and timestamp.
  if (session_.IsEnabled(TRACE_FLAG_BATCH_ENTER)) {
    DCHECK_EQ(session_.flags() & (session_.flags() - 1), 0u)
        << "Batch mode isn't compatible with any other flags; "
           "no other bits should be set.";

    FuncCall* call_info = data->AllocateFuncCall();
    if (call_info != NULL) {
      call_info->function = function;
      call_info->tick_count = ::GetTickCount();
    }
  }

  // If we're tracing detailed function entries, capture the function details.
  if (session_.IsEnabled(TRACE_FLAG_ENTER)) {
    if (!data->segment.CanAllocate(sizeof(TraceEnterEventData))) {
      session_.ExchangeBuffer(&data->segment);
    }

    TraceEnterEventData* event_data =
        data->segment.AllocateTraceRecord<TraceEnterEventData>();

    event_data->depth = (NULL == data) ? 0 : data->shadow_stack.size();
    event_data->function = function;
    CopyArguments(event_data->args,
                  entry_frame->args,
                  ARRAYSIZE(event_data->args));

    // TODO(siggi): It might make sense to optimize this, and not do a stack
    //     trace capture when we enter directly from another captured function
    //     It's a little difficult to distinguish this from entry through, for
    //     example, a function we didn't capture in the same module, or entry
    //     indirectly through a callback, so leaving as a possible future
    //     optimization.
    if (session_.IsEnabled(TRACE_FLAG_STACK_TRACES)) {
      event_data->num_traces = ::RtlCaptureStackBackTrace(
          3, kMaxTraceDepth, const_cast<PVOID*>(event_data->traces), NULL);
      FixupBackTrace(data->shadow_stack, event_data->traces,
                     event_data->num_traces);
    } else {
      event_data->num_traces = 0;
    }
  }

  bool is_detach_event = (module != NULL) && (reason == DLL_THREAD_DETACH ||
                                              reason == DLL_PROCESS_DETACH);

  // If we're tracing function exits, or we need to capture the end of a
  // module unload event, we need to write the appropriate exit hook into
  // the call stack.
  if (session_.IsEnabled(TRACE_FLAG_EXIT) || is_detach_event) {
    // Make sure we trim orphaned shadow stack entries before pushing
    // a new one. On entry, any shadow stack entry whose entry frame pointer
    // is less than the current entry frame is orphaned.
    ShadowStack& stack = data->shadow_stack;
    stack.TrimOrphansOnEntry(entry_frame);

    // Save the old return address.
    StackEntry entry = stack.Push(entry_frame);
    entry.function_address = function;

    // Modify the return address in our frame. If this is a module event,
    // stash the event details and return to ::pexit_dllmain; otherwise,
    // return to ::pexit.
    if (is_detach_event) {
      ModuleEventStackEntry module_event = { module, reason };
      data->module_event_stack.push_back(module_event);
      entry_frame->retaddr = ::pexit_dllmain;
    } else {
      entry_frame->retaddr = ::pexit;
    }

  }
}

RetAddr Client::LogEvent_FunctionExit(const void* stack_pointer,
                                      RetValueWord retval) {
  DCHECK(session_.IsTracing());  // Otherwise we wouldn't get here.

  ThreadLocalData *data = GetThreadData();
  CHECK(NULL != data) << "Shadow stack missing in action";

  ShadowStack& stack = data->shadow_stack;
  stack.TrimOrphansOnExit(stack_pointer);

  // Get the top of the stack, we don't pop it yet, because
  // the fixup function needs to see our entry to fixup correctly.
  StackEntry top = stack.Peek();

  // Trace the exit if required.
  if (session_.IsEnabled(TRACE_FLAG_EXIT)) {
    if (!data->segment.CanAllocate(sizeof(TraceExitEventData))) {
      session_.ExchangeBuffer(&data->segment);
    }
    TraceExitEventData* event_data =
        data->segment.AllocateTraceRecord<TraceExitEventData>();
    event_data->depth = data->shadow_stack.size();
    event_data->function = top.function_address;
    event_data->retval = retval;
    if (session_.IsEnabled(TRACE_FLAG_STACK_TRACES)) {
      event_data->num_traces = ::RtlCaptureStackBackTrace(
          3, kMaxTraceDepth, const_cast<PVOID*>(event_data->traces), NULL);
      FixupBackTrace(data->shadow_stack, event_data->traces,
                     event_data->num_traces);
    } else {
      event_data->num_traces = 0;
    }
  }

  // Pop the stack.
  stack.Pop();

  // And return the original return address.
  return top.return_address;
}

void Client::FixupBackTrace(const ShadowStack& stack, RetAddr traces[],
                            size_t num_traces) {
  static const RetAddr kExitFns[] = { ::pexit, ::pexit_dllmain };
  stack.FixBackTrace(arraysize(kExitFns), kExitFns, num_traces, traces);
}

Client::ThreadLocalData* Client::GetThreadData() {
  if (TLS_OUT_OF_INDEXES == tls_index_)
    return NULL;

  return reinterpret_cast<ThreadLocalData*>(::TlsGetValue(tls_index_));
}

Client::ThreadLocalData* Client::GetOrAllocateThreadData() {
  if (TLS_OUT_OF_INDEXES == tls_index_)
    return NULL;

  ThreadLocalData *data=
      reinterpret_cast<ThreadLocalData*>(::TlsGetValue(tls_index_));
  if (data != NULL)
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

void Client::FreeThreadData(ThreadLocalData *data) {
  DCHECK(data != NULL);

  delete data;
  ::TlsSetValue(tls_index_, NULL);
}

void Client::FreeThreadData() {
  ThreadLocalData* data = GetThreadData();
  if (data != NULL)
    FreeThreadData(data);
}

Client::ThreadLocalData::ThreadLocalData(Client* c) : client(c), batch(NULL) {
}

FuncCall* Client::ThreadLocalData::AllocateFuncCall() {
  // Do we have a batch record that we can grow?
  if (batch != NULL && segment.CanAllocateRaw(sizeof(FuncCall))) {
    FuncCall* call_info = reinterpret_cast<FuncCall*>(segment.write_ptr);
    DCHECK(call_info == batch->calls + batch->num_calls);
    batch->num_calls += 1;
    RecordPrefix* prefix = GetRecordPrefix(batch);
    prefix->size += sizeof(FuncCall);

    // Update the book-keeping.
    segment.write_ptr += sizeof(FuncCall);
    segment.header->segment_length += sizeof(FuncCall);

    return call_info;
  }

  // Do we need to scarf a new buffer?
  if (batch != NULL || !segment.CanAllocate(sizeof(TraceBatchEnterData))) {
    if (!client->session_.ExchangeBuffer(&segment)) {
      return NULL;
    }
  }

  batch = segment.AllocateTraceRecord<TraceBatchEnterData>();
  batch->thread_id = segment.header->thread_id;
  batch->num_calls = 1;

  return &batch->calls[0];
}

bool Client::ThreadLocalData::FlushSegment() {
  DCHECK(IsInitialized());

  batch = NULL;
  return client->session_.ExchangeBuffer(&segment);
}

}  // namespace call_trace::client
}  // namespace call_trace
