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
//
// A note on the exit hook:
//
// The exit hook is implemented by swizzling return addresses on the machine
// stack while maintaining a per-thread shadow stack of return addresses.
// If exit logging is requested on entry to a function, the shadow stack is
// pushed with the current return address, and the return address on the machine
// stack is replaced with the address of _pexit. On subsequent return to _pexit,
// the exit event will be recorded, the shadow stack popped, and _pexit will
// return to the address from the shadow stack.
//
// This simple implementation works fine in the absence of nonlocal gotos,
// exceptions and the like. However, on such events, some portion of the machine
// stack is discarded, which puts the shadow stack out of synchronization with
// the machine stack. This in turn will cause a subsequent return to _pexit
// to pop the wrong entry off the shadow stack, and a return to the wrong
// address.
//
// To avoid this, we note that:
//
// * On exit, the stack pointer must be strictly greater than the entry frame
//   that the shadow stack entry was created from (as the return address as well
//   as the arguments - in the case of __stdcall - have been popped off the
//   stack in preparation for the return).
//   Also, the second non-orphaned shadow stack entry's entry frame pointer must
//   be equal or greater than the stack pointer (and its return address must be
//   pexit or pexit_dllmain).
//
// * An exception to the above is multiple entries with the same entry address,
//   which occur in the cases of tail call & recursion elimination.
//
// * On entry, any shadow stack entry whose entry frame pointer is less than
//   the current entry frame is orphaned. Note that equal entry frame pointers
//   occur in the case of tail call & recursion elimination.
//
// By discarding orphaned shadow stack entries on entry and exit, we can ensure
// that we never return to an orphaned entry.

#include "syzygy/call_trace/client.h"

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

  // The call trace client to which this data belongs.
  // TODO(rogerm): This field isn't necessary, it's only used in DCHECKs.
  Client* const client;

  // The owning thread's current trace-file segment.
  TraceFileSegment segment;

  // The shadow return stack we use when function exit is traced.
  ReturnStack return_stack;

  // A placeholder for a pending module event (DLL_THREAD_DETACH or
  // DLL_PROCESS_DETACH) that will be processed by ::pexit_dllmain.
  // TODO(rogerm): is it possible to have more than one pending?
  ModuleEventStack module_event_stack;
};

Client::Client()
    : tls_index_(::TlsAlloc()),
      session_handle_(NULL),
      is_disabled_(false) {
}

Client::~Client() {
  if (TLS_OUT_OF_INDEXES != tls_index_)
    ::TlsFree(tls_index_);
  FreeSharedMemory();
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
  if (!IsTracing())
    return;

  CloseSession();
  FreeThreadData();
  FreeSharedMemory();
}

void Client::OnClientThreadDetach() {
  if (!IsTracing())
    return;

  // Get the thread data. If this thread has never called an instrumented
  // function, no thread local call trace data will be associated with it.
  ThreadLocalData* data = GetThreadData();
  if (data != NULL) {
    ReturnBuffer(data);
    FreeThreadData(data);
  }
}

bool Client::BindRPC() {
  DCHECK(rpc_binding_ == 0);

  RPC_WSTR string_binding = NULL;
  std::wstring protocol(kCallTraceRpcProtocol);
  std::wstring endpoint(kCallTraceRpcEndpoint);

  RPC_STATUS status = RPC_S_OK;

  status = ::RpcStringBindingCompose(
      NULL, // UUID.
      reinterpret_cast<RPC_WSTR>(&protocol[0]),
      NULL,  // Address.
      reinterpret_cast<RPC_WSTR>(&endpoint[0]),
      NULL, // Options.
      &string_binding);
  if (status != RPC_S_OK) {
    LOG(ERROR) << "Can't compose RPC binding " << com::LogWe(status) << ".";
    return false;
  }

  status = ::RpcBindingFromStringBinding(string_binding, &rpc_binding_);

  ignore_result(::RpcStringFree(&string_binding));

  if (status != RPC_S_OK) {
    LOG(ERROR) << "Can't create RPC binding " << com::LogWe(status) << ".";
    return false;
  }

  return true;
}

bool Client::MapSegmentBuffer(ThreadLocalData* data) {
  DCHECK(data != NULL);
  DCHECK(data->client == this);

  HANDLE mem_handle =
      reinterpret_cast<HANDLE>(data->segment.buffer_info.shared_memory_handle);

  // Get (or set) the mapping between the handle we've received and the
  // corresponding mapped base pointer. Note that the shared_memory_handles_
  // map is shared across threads, so we need to hold the shared_memory_lock_
  // when we access/update it.  This should be the only synchronization point
  // in the call trace client library (other then the initial creation of the
  // client object, of course).
  {
    base::AutoLock scoped_lock(shared_memory_lock_);

    uint8*& base_ptr = shared_memory_handles_[mem_handle];
    if (base_ptr == NULL) {
      base_ptr = reinterpret_cast<uint8*>(
          ::MapViewOfFile(mem_handle, FILE_MAP_WRITE, 0, 0,
                          data->segment.buffer_info.mapping_size));
      if (base_ptr == NULL) {
        DWORD error = ::GetLastError();
        LOG(ERROR) << "Failed to map view of shared memory "
            << com::LogWe(error) << ".";
        ignore_result(::CloseHandle(mem_handle));
        shared_memory_handles_.erase(mem_handle);
        return false;
      }
    }

    data->segment.base_ptr =
        base_ptr + data->segment.buffer_info.buffer_offset;
  }

  data->segment.header = NULL;
  data->segment.write_ptr = data->segment.base_ptr;
  data->segment.end_ptr =
      data->segment.base_ptr + data->segment.buffer_info.buffer_size;
  WriteSegmentHeader(session_handle_, &data->segment);

  DCHECK(data->segment.header != NULL);

  if (IsEnabled(TRACE_FLAG_BATCH_ENTER)) {
    CHECK(CanAllocate(&data->segment, sizeof(TraceBatchEnterData)));

    TraceBatchEnterData* batch_header =
        AllocateTraceRecord<TraceBatchEnterData>(&data->segment);

    DCHECK(batch_header == GetTraceBatchHeader(&data->segment));

    batch_header->thread_id = data->segment.header->thread_id;
    batch_header->num_calls = 0;

    // Correct for the first FuncCall entry having already been
    // allocated.
    RecordPrefix* batch_prefix = GetTraceBatchPrefix(&data->segment);
    batch_prefix->size -= sizeof(FuncCall);
    data->segment.write_ptr -= sizeof(FuncCall);
    data->segment.header->segment_length -= sizeof(FuncCall);

    DCHECK_EQ(reinterpret_cast<FuncCall*>(data->segment.write_ptr),
              batch_header->calls + batch_header->num_calls);
  }

  return true;
}

bool Client::CreateSession() {
  DCHECK(session_handle_ == NULL);

  if (!BindRPC())
    return false;

  DCHECK(rpc_binding_ != 0);

  ThreadLocalData* data = GetOrAllocateThreadData();
  CHECK(data != NULL);

  DCHECK(data->client == this);

  bool succeeded = InvokeRpc(CallTraceClient_CreateSession,
                             rpc_binding_,
                             ::GetCommandLineW(),
                             &session_handle_,
                             &data->segment.buffer_info,
                             &flags_).succeeded();

  if (!succeeded) {
    LOG(ERROR) << "Failed to create call trace session!";
    return false;
  }

  if ((flags_ & TRACE_FLAG_BATCH_ENTER) != 0) {
    // Batch mode is mutually exclusive of all other flags.
    flags_ = TRACE_FLAG_BATCH_ENTER;
  }

  return MapSegmentBuffer(data);
}

bool Client::AllocateBuffer(ThreadLocalData* data) {
  DCHECK(IsTracing());
  DCHECK(data != NULL);
  DCHECK(data->client == this);

  bool succeeded = InvokeRpc(CallTraceClient_AllocateBuffer,
                             session_handle_,
                             &data->segment.buffer_info).succeeded();

  return succeeded ? MapSegmentBuffer(data) : false;
}

bool Client::ExchangeBuffer(ThreadLocalData* data) {
  DCHECK(IsTracing());
  DCHECK(data != NULL);
  DCHECK(data->client == this);

  bool succeeded = InvokeRpc(CallTraceClient_ExchangeBuffer,
                             session_handle_,
                             &data->segment.buffer_info).succeeded();

  return succeeded ? MapSegmentBuffer(data) : false;
}

bool Client::ReturnBuffer(ThreadLocalData* data) {
  DCHECK(IsTracing());
  DCHECK(data != NULL);
  DCHECK(data->client == this);

  return InvokeRpc(CallTraceClient_ReturnBuffer,
                   session_handle_,
                   &data->segment.buffer_info).succeeded();
}

bool Client::CloseSession() {
  DCHECK(IsTracing());

  bool succeeded = InvokeRpc(CallTraceClient_CloseSession,
                             &session_handle_).succeeded();

  ignore_result(::RpcBindingFree(&rpc_binding_));
  rpc_binding_ = NULL;

  return succeeded;
}

void Client::FreeSharedMemory() {
  base::AutoLock scoped_lock_(shared_memory_lock_);

  if (shared_memory_handles_.empty())
    return;

  SharedMemoryHandleMap::iterator it = shared_memory_handles_.begin();
  for (; it != shared_memory_handles_.end(); ++it) {
    DCHECK(it->second != NULL);
    if (::UnmapViewOfFile(it->second) == 0) {
      DWORD error = ::GetLastError();
      LOG(WARNING) << "Failed to unmap memory handle " << com::LogWe(error);
    }

    if (::CloseHandle(it->first) == 0) {
      DWORD error = ::GetLastError();
      LOG(WARNING) << "Failed to close memory handle " << com::LogWe(error);
    }
  }

  shared_memory_handles_.clear();
}

void Client::DllMainEntryHook(EntryFrame *entry_frame, FuncAddr function) {
  ScopedLastErrorKeeper save_and_restore_last_error;

  Client* client = Instance();
  CHECK(client != NULL) << "Failed to get call trace client instance.";

  if (client->IsDisabled())
    return;

  HMODULE module = reinterpret_cast<HMODULE>(entry_frame->args[0]);
  DWORD reason = entry_frame->args[1];

  client->LogEvent_FunctionEntry(entry_frame, function, module, reason);
}

void Client::FunctionEntryHook(EntryFrame *entry_frame, FuncAddr function) {
  ScopedLastErrorKeeper save_and_restore_last_error;

  Client* client = Instance();
  CHECK(client != NULL) << "Failed to get call trace client instance.";

  if (client->IsDisabled())
    return;

  client->LogEvent_FunctionEntry(entry_frame, function, NULL, -1);
}

RetAddr Client::FunctionExitHook(const void* stack_pointer,
                                 RetValueWord retval) {
  ScopedLastErrorKeeper save_and_restore_last_error;

  Client* client = Instance();
  CHECK(client != NULL) << "Failed to get call trace client instance.";
  DCHECK(!client->IsDisabled());
  DCHECK(client->IsTracing());

  return client->LogEvent_FunctionExit(stack_pointer, retval);
}

RetAddr Client::DllMainExitHook(const void* stack_pointer,
                                RetValueWord retval) {
  ScopedLastErrorKeeper save_and_restore_last_error;

  Client* client = Instance();
  CHECK(client != NULL) << "Failed to get call trace client instance.";
  DCHECK(!client->IsDisabled());
  DCHECK(client->IsTracing());

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
  DCHECK(IsTracing());

  // Perform a sanity check.
  switch (reason) {
    case DLL_PROCESS_ATTACH:
    case DLL_PROCESS_DETACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
      break;

    default:
      LOG(WARNING) << "Unrecognized module event: " << reason << ".";
      return;
  }

  // Make sure the event we're about to write will fit.
  if (!CanAllocate(&data->segment, sizeof(TraceModuleData))) {
    ExchangeBuffer(data);
  }

  // Allocate a record in the log.
  TraceModuleData* module_event = reinterpret_cast<TraceModuleData*>(
      AllocateTraceRecordImpl(&data->segment,
                              ReasonToEventType(reason),
                              sizeof(TraceModuleData)));
  DCHECK(module_event!= NULL);

  // Populate the log record.
  base::win::PEImage image(module);
  module_event->module_base_addr = module;
  module_event->module_base_size =
      image.GetNTHeaders()->OptionalHeader.SizeOfImage;
  if (::GetMappedFileName(::GetCurrentProcess(), module,
                          &module_event->module_name[0],
                          arraysize(module_event->module_name)) == 0) {
      DWORD error = ::GetLastError();
      LOG(ERROR) << "Failed to get module name " << com::LogWe(error) << ".";
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
  ExchangeBuffer(data);
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
  if (!IsTracing()) {
    base::AutoLock scoped_lock(init_lock_);
    if (IsDisabled())
      return;
    if (!IsTracing() && !CreateSession()) {
      is_disabled_ = true;
      return;
    }
  }

  DCHECK(!IsDisabled());
  DCHECK(IsTracing());

  ThreadLocalData *data = GetOrAllocateThreadData();
  CHECK(data != NULL) << "Failed to get call trace thread context.";

  if (!data->IsInitialized()) {
    CHECK(AllocateBuffer(data)) << "Failed to allocate trace buffer.";
  }

  if ((module != NULL) &&
      (reason == DLL_PROCESS_ATTACH || reason == DLL_THREAD_ATTACH)) {
    LogEvent_ModuleEvent(data, module, reason);
  }

  // If we're in batch mode, just capture the basic call info and timestamp.
  if (IsEnabled(TRACE_FLAG_BATCH_ENTER)) {
    DCHECK_EQ(flags_ & (flags_ - 1), 0u)
        << "Batch mode isn't compatible with any other flags; "
           "no other bits should be set.";

    // Make sure we have space for the batch entry.
    if (!CanAllocateRaw(&data->segment, sizeof(FuncCall))) {
      ExchangeBuffer(data);
    }

    // Add the batch entry for this call.
    // TODO(rogerm): use ::QueryPerformanceCounter intead of ::GetTickCount()?
    RecordPrefix* batch_prefix = GetTraceBatchPrefix(&data->segment);
    TraceBatchEnterData* batch_header = GetTraceBatchHeader(&data->segment);
    FuncCall* call_info = reinterpret_cast<FuncCall*>(data->segment.write_ptr);
    DCHECK(call_info == batch_header->calls + batch_header->num_calls);
    call_info->function = function;
    call_info->tick_count = ::GetTickCount();
    batch_header->num_calls += 1;
    batch_prefix->size += sizeof(FuncCall);

    // Update the book-keeping
    data->segment.write_ptr += sizeof(FuncCall);
    data->segment.header->segment_length += sizeof(FuncCall);
  }

  // If we're tracing detailed function entries, capture the function details.
  if (IsEnabled(TRACE_FLAG_ENTER)) {
    if (!CanAllocate(&data->segment, sizeof(TraceEnterEventData))) {
      ExchangeBuffer(data);
    }

    TraceEnterEventData* event_data =
        AllocateTraceRecord<TraceEnterEventData>(&data->segment);

    event_data->depth = (NULL == data) ? 0 : data->return_stack.size();
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
    if (IsEnabled(TRACE_FLAG_STACK_TRACES)) {
      event_data->num_traces = ::RtlCaptureStackBackTrace(
          3, kMaxTraceDepth, const_cast<PVOID*>(event_data->traces), NULL);
      FixupBackTrace(data->return_stack, event_data->traces,
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
  if (IsEnabled(TRACE_FLAG_EXIT) || is_detach_event) {
    // Make sure we trim orphaned shadow stack entries before pushing
    // a new one. On entry, any shadow stack entry whose entry frame pointer
    // is less than the current entry frame is orphaned.
    ReturnStack& stack = data->return_stack;
    while (!stack.empty() &&
           reinterpret_cast<const byte*>(stack.back().entry_frame) <
           reinterpret_cast<const byte*>(entry_frame)) {
      stack.pop_back();
    }

    // Save the old return address.
    ReturnStackEntry entry = { entry_frame->retaddr, function, entry_frame };
    stack.push_back(entry);

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
  DCHECK(IsTracing());  // Otherwise we wouldn't get here.

  ThreadLocalData *data = GetThreadData();
  CHECK(NULL != data) << "Shadow stack missing in action";

  // On exit, the stack pointer must be strictly greater than the entry
  // frame that the shadow stack entry was created from. Also, the second
  // non-orphaned shadow stack entry's entry frame pointer must be equal
  // or greater than the stack pointer (and its return address must be
  // ::pexit or ::pexit_dllmain). An exception to the above is multiple
  // entries with the same entry address, which occur in the cases of
  // tail call & recursion elimination.
  ReturnStack& stack = data->return_stack;
  CHECK(!stack.empty()) << "Shadow stack out of whack!";
  CHECK(reinterpret_cast<const byte*>(stack_pointer) >
        reinterpret_cast<const byte*>(stack.back().entry_frame))
      << "Invalid entry on shadow stack";

  // Find the first entry (if any) that has an entry pointer greater or equal
  // to the stack pointer. This entry is the second non-orphaned entry on the
  // stack, or the Nth entry behind N-1 entries with identical entry_frames in
  // case of tail call & recursion.
  ReturnStack::reverse_iterator it(stack.rbegin());
  ReturnStack::reverse_iterator end(stack.rend());
  for (; it != end; ++it) {
    if (reinterpret_cast<const byte*>(it->entry_frame) >=
        reinterpret_cast<const byte*>(stack_pointer)) {
      break;
    }
  }

  // Now "it" points to the entry preceding the entry to pop, or the first of
  // many entries with identical entry_frame pointers.
  ReturnStack::reverse_iterator begin(stack.rbegin());
  --it;
  EntryFrame* entry_frame = it->entry_frame;
  for (; it != begin; --it) {
    if (it->entry_frame != entry_frame) {
      // Slice the extra entries off the shadow stack.
      stack.resize(end - it - 1);
      break;
    }
  }

  // Get the top of the stack, we don't pop it yet, because
  // the fixup function needs to see our entry to fixup correctly.
  ReturnStackEntry top = stack.back();

  // Trace the exit if required.
  if (IsEnabled(TRACE_FLAG_EXIT)) {
    if (!CanAllocate(&data->segment, sizeof(TraceExitEventData))) {
      ExchangeBuffer(data);
    }
    TraceExitEventData* event_data =
        AllocateTraceRecord<TraceExitEventData>(&data->segment);
    event_data->depth = data->return_stack.size();
    event_data->function = top.function_address;
    event_data->retval = retval;
    if (IsEnabled(TRACE_FLAG_STACK_TRACES)) {
      event_data->num_traces = ::RtlCaptureStackBackTrace(
          3, kMaxTraceDepth, const_cast<PVOID*>(event_data->traces), NULL);
      FixupBackTrace(data->return_stack, event_data->traces,
                     event_data->num_traces);
    } else {
      event_data->num_traces = 0;
    }
  }

  // Pop the stack.
  stack.pop_back();

  // And return the original return address.
  return top.return_address;
}

void Client::FixupBackTrace(const ReturnStack& stack, RetAddr traces[],
                            size_t num_traces) {
  ReturnStack::const_reverse_iterator it(stack.rbegin()), end(stack.rend());
  for (size_t i = 0; i < num_traces && it != end; ++i) {
    if (::pexit == traces[i] || ::pexit_dllmain == traces[i]) {
      traces[i] = it->return_address;
      ++it;
    }
  }
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

Client::ThreadLocalData::ThreadLocalData(Client* c) : client(c) {
  ZeroMemory(&segment, sizeof(segment));
}

}  // namespace call_trace::client
}  // namespace call_trace
