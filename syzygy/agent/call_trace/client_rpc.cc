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
// Implementation of the Call Trace Client DLL.

#include "syzygy/agent/call_trace/client_rpc.h"

#include <windows.h>  // NOLINT
#include <psapi.h>
#include <tlhelp32.h>
#include <vector>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/environment.h"
#include "base/lazy_instance.h"
#include "base/logging.h"
#include "base/utf_string_conversions.h"
#include "base/win/pe_image.h"
#include "syzygy/agent/common/process_utils.h"
#include "syzygy/agent/common/scoped_last_error_keeper.h"
#include "syzygy/common/com_utils.h"
#include "syzygy/common/logging.h"
#include "syzygy/common/path_util.h"
#include "syzygy/trace/client/client_utils.h"
#include "syzygy/trace/protocol/call_trace_defs.h"
#include "syzygy/trace/rpc/rpc_helpers.h"

using agent::client::Client;
using agent::common::ScopedLastErrorKeeper;

namespace {

// All tracing runs through this object.
base::LazyInstance<Client> static_client_instance = LAZY_INSTANCE_INITIALIZER;

// Copies the arguments under an SEH handler so we don't crash by under-running
// the stack.
void CopyArguments(ArgumentWord *dst, const ArgumentWord *src, size_t num) {
  __try {
    for (size_t i = 0; i < num; ++i)
      *dst++ = *src++;
  } __except(EXCEPTION_EXECUTE_HANDLER) {
  }
}

}  // namespace

BOOL WINAPI DllMain(HMODULE instance, DWORD reason, LPVOID reserved) {
  // Our AtExit manager required by base.
  static base::AtExitManager* at_exit = NULL;

  if (reason == DLL_PROCESS_ATTACH) {
    DCHECK(at_exit == NULL);
    at_exit = new base::AtExitManager();
  }

  BOOL ret = Client::Instance()->DllMain(instance, reason, reserved);

  if (reason == DLL_PROCESS_DETACH) {
    CommandLine::Reset();
    DCHECK(at_exit != NULL);
    delete at_exit;
    at_exit = NULL;
  }

  return ret;
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

namespace agent {
namespace client {

class Client::ThreadLocalData {
 public:
  explicit ThreadLocalData(Client* module);

  bool IsInitialized() const {
    return segment.header != NULL;
  }

  // Allocates a new enter event.
  TraceEnterEventData* AllocateEnterEvent();

  // Flushes the current trace file segment.
  bool FlushSegment();

  // The call trace client to which this data belongs.
  // TODO(rogerm): This field isn't necessary, it's only used in DCHECKs.
  Client* const client;

  // The owning thread's current trace-file segment, if any.
  trace::client::TraceFileSegment segment;

  // The current batch record we're extending, if any.
  // This will point into the associated trace file segment's buffer.
  TraceBatchEnterData* batch;
};

Client::Client() {
}

Client::~Client() {
}

Client* Client::Instance() {
  return static_client_instance.Pointer();
}

BOOL Client::DllMain(HMODULE /* module */,
                     DWORD reason,
                     LPVOID /* reserved */) {
  switch (reason) {
    case DLL_PROCESS_ATTACH:
      // Initialize logging ASAP.
      CommandLine::Init(0, NULL);
      ::common::InitLoggingForDll(L"call_trace");
      break;

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
      // We don't log these.
      return;
      break;

    default:
      LOG(WARNING) << "Unrecognized module event: " << reason << ".";
      return;
  }

  // This already logs verbosely.
  if (!agent::common::LogModule(module, &session_, &data->segment))
    return;

  // We need to flush module events right away, so that the module is
  // defined in the trace file before events using that module start to
  // occur (in another thread).
  if (reason == DLL_PROCESS_ATTACH)
    data->FlushSegment();
}


void Client::LogEvent_FunctionEntry(EntryFrame *entry_frame,
                                    FuncAddr function,
                                    HMODULE module,
                                    DWORD reason ) {
  // TODO(rogerm): Split this up so that we don't have to pass unused
  //     module and reason parameters on every call. This is really
  //     sub-optimal, so address it ASAP.

  // If we're not currently tracing then this is (one of) the first calls
  // to an instrumented function. We attempt to initialize a session. If
  // we're not able to initialize a session, we disable the call trace
  // client.
  ThreadLocalData *data = GetOrAllocateThreadData();
  CHECK(data != NULL) << "Failed to get call trace thread context.";

  if (!session_.IsTracing() && !session_.IsDisabled()) {
    base::AutoLock scoped_lock(init_lock_);
    if (session_.IsDisabled())
      return;

    if (!session_.IsTracing()) {
      if (!trace::client::InitializeRpcSession(&session_, &data->segment))
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

  // TODO(chrisha): Add buffer flushing to permit some kind of guarantee on
  //     the accuracy of the time for batch entry events. Do this before adding
  //     this event to the buffer in order to guarantee precision.

  // Capture the basic call info and timestamp.
  TraceEnterEventData* enter = data->AllocateEnterEvent();
  if (enter != NULL) {
    enter->retaddr = entry_frame->retaddr;
    enter->function = function;
  }
}

Client::ThreadLocalData* Client::GetThreadData() {
  return tls_.Get();
}

Client::ThreadLocalData* Client::GetOrAllocateThreadData() {
  ThreadLocalData *data = tls_.Get();
  if (data != NULL)
    return data;

  data = new ThreadLocalData(this);
  if (data == NULL) {
    LOG(ERROR) << "Unable to allocate per-thread data";
    return NULL;
  }

  tls_.Set(data);
  return data;
}

void Client::FreeThreadData(ThreadLocalData *data) {
  DCHECK(data != NULL);

  delete data;
  tls_.Set(NULL);
}

void Client::FreeThreadData() {
  ThreadLocalData* data = GetThreadData();
  if (data != NULL)
    FreeThreadData(data);
}

Client::ThreadLocalData::ThreadLocalData(Client* c) : client(c), batch(NULL) {
}

TraceEnterEventData* Client::ThreadLocalData::AllocateEnterEvent() {
  // Do we have a batch record that we can grow?
  if (batch != NULL && segment.CanAllocateRaw(sizeof(TraceEnterEventData))) {
    TraceEnterEventData* enter =
        reinterpret_cast<TraceEnterEventData*>(segment.write_ptr);
    // The order of operations from here is pretty important. The issue is that
    // threads can be terminated at any point, and this happens as a matter of
    // fact at process exit, for any other threads than the one calling
    // ExitProcess. We want our shared memory buffers to be in a self-consistent
    // state at all times, so we proceed here by:
    // - allocating and initializing a new record first.
    // - then update the bookkeeping for the enclosures from the outermost,
    //   inward. E.g. first we grow the file segment, then the record enclosure,
    //   and lastly update the record itself.

    // Initialize the new record.
    memset(enter, 0, sizeof(*enter));

    // Update the file segment size.
    segment.write_ptr += sizeof(TraceEnterEventData);
    segment.header->segment_length += sizeof(TraceEnterEventData);

    // Extend the record enclosure.
    RecordPrefix* prefix = trace::client::GetRecordPrefix(batch);
    prefix->size += sizeof(TraceEnterEventData);

    // And lastly update the inner counter.
    DCHECK(enter == batch->calls + batch->num_calls);
    batch->num_calls += 1;

    return enter;
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

}  // namespace client
}  // namespace agent
