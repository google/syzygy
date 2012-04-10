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
// Implementation of the profiler DLL.
#include "syzygy/agent/profiler/profiler.h"

#include <psapi.h>
#include <windows.h>
#include <algorithm>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/file_path.h"
#include "base/lazy_instance.h"
#include "base/logging.h"
#include "base/win/pe_image.h"
#include "sawbuck/common/com_utils.h"
#include "syzygy/agent/common/process_utils.h"
#include "syzygy/agent/profiler/return_thunk_factory.h"
#include "syzygy/agent/profiler/scoped_last_error_keeper.h"
#include "syzygy/common/logging.h"
#include "syzygy/common/path_util.h"
#include "syzygy/trace/client/client_utils.h"
#include "syzygy/trace/protocol/call_trace_defs.h"

namespace {

// Our AtExit manager required by base.
base::AtExitManager at_exit;

// All tracing runs through this object.
base::LazyInstance<agent::profiler::Profiler> static_profiler_instance =
    LAZY_INSTANCE_INITIALIZER;

typedef std::pair<RetAddr, FuncAddr> InvocationKey;

class HashInvocationKey {
 public:
  static const size_t bucket_size = 4;
  static const size_t min_buckets = 8;

  size_t operator()(const InvocationKey& key) const {
    return reinterpret_cast<size_t>(key.first) ^
        reinterpret_cast<size_t>(key.second);
  }

  bool operator()(const InvocationKey& a, const InvocationKey& b) const {
    return a < b;
  }
};
typedef base::hash_map<
    InvocationKey, InvocationInfo*, HashInvocationKey> InvocationMap;

// Accessing a module acquired from process iteration calls is inherently racy,
// as we don't hold any kind of reference to the module, and so the module
// could be unloaded while we're accessing it. In practice this shouldn't
// happen to us, as we'll be running under the loader's lock in all cases.
bool CaptureModuleInformation(const base::win::PEImage& image,
                              TraceModuleData* module_event) {
  __try {
    // Populate the log record.
    module_event->module_base_size =
        image.GetNTHeaders()->OptionalHeader.SizeOfImage;
    module_event->module_checksum =
        image.GetNTHeaders()->OptionalHeader.CheckSum;
    module_event->module_time_date_stamp =
        image.GetNTHeaders()->FileHeader.TimeDateStamp;
  } __except(EXCEPTION_EXECUTE_HANDLER) {
    return false;
  }

  return true;
}

}  // namespace

// See client.cc for a description of the unconventional
// calling conventions for this function.
extern "C" void __declspec(naked) _indirect_penter() {
  __asm {
    // Stash volatile registers.
    push eax
    push edx

    // Get the current cycle time ASAP.
    rdtsc

    push ecx
    pushfd

    // Push the cycle time arg.
    push edx
    push eax

    // Retrieve the original function address, pushed by our caller.
    mov eax, DWORD PTR[esp + 0x18]
    push eax

    // Calculate the position of the return address on stack, and
    // push it. This becomes the EntryFrame argument.
    lea eax, DWORD PTR[esp + 0x20]
    push eax
    call agent::profiler::Profiler::FunctionEntryHook

    // Restore volatile registers.
    popfd
    pop ecx
    pop edx
    pop eax

    // Return to the address pushed by our caller.
    ret
  }
}

extern "C" void __declspec(naked) _indirect_penter_dllmain() {
  __asm {
    // Stash volatile registers.
    push eax
    push edx

    // Get the current cycle time ASAP.
    rdtsc

    push ecx
    pushfd

    // Push the cycle time arg.
    push edx
    push eax

    // Retrieve the address pushed by our caller.
    mov eax, DWORD PTR[esp + 0x18]
    push eax

    // Calculate the position of the return address on stack, and
    // push it. This becomes the EntryFrame argument.
    lea eax, DWORD PTR[esp + 0x20]
    push eax
    call agent::profiler::Profiler::DllMainEntryHook

    // Restore volatile registers.
    popfd
    pop ecx
    pop edx
    pop eax

    // Return to the address pushed by our caller.
    ret
  }
}

// On entry, pc_location should point to a location on our own stack.
extern "C" uintptr_t __cdecl ResolveReturnAddressLocation(
    uintptr_t pc_location) {
  using agent::profiler::Profiler;
  Profiler* profiler = Profiler::Instance();
  return reinterpret_cast<uintptr_t>(
      profiler->ResolveReturnAddressLocation(
          reinterpret_cast<RetAddr*>(pc_location)));
}

BOOL WINAPI DllMain(HMODULE instance, DWORD reason, LPVOID reserved) {
  using agent::profiler::Profiler;

  switch (reason) {
    case DLL_PROCESS_ATTACH:
      CommandLine::Init(0, NULL);
      common::InitLoggingForDll(L"profiler");
      break;

    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
      Profiler::Instance()->OnDetach();
      break;

    default:
      break;
  }

  return TRUE;
}

namespace agent {
namespace profiler {

class Profiler::ThreadState : public ReturnThunkFactory::Delegate {
 public:
  explicit ThreadState(Profiler* profiler)
        : profiler_(profiler),
          cycles_overhead_(0LL),
          thunk_factory_(this),
          batch_(NULL) {
  }

  // Logs @p module and all other modules in the process, then flushes
  // the current trace buffer.
  void LogAllModules(HMODULE module);

  // Logs @p module.
  void LogModule(HMODULE module);

  // Processes a single function entry.
  void OnFunctionEntry(EntryFrame* entry_frame,
                       FuncAddr function,
                       uint64 cycles);

  // @name ReturnThunkFactory::Delegate implementation.
  // @{
  virtual void OnFunctionExit(const ReturnThunkFactory::Thunk* thunk,
                              uint64 cycles_exit) OVERRIDE;
  virtual void OnPageAdded(const void* page) OVERRIDE;
  virtual void OnPageRemoved(const void* page) OVERRIDE;
  // @}

  trace::client::TraceFileSegment* segment() { return &segment_; }

 private:
  void RecordInvocation(RetAddr caller,
                        FuncAddr function,
                        uint64 cycles);

  void UpdateOverhead(uint64 entry_cycles);
  InvocationInfo* AllocateInvocationInfo();
  bool FlushSegment();

  // The profiler we're attached to.
  Profiler* profiler_;

  // We keep a running tally of the rough amount of wall clock cycles spent
  // inside the profiler. We then subtract the profiler's overhead from the
  // wall clock cycle timer on each measurement. This results in a timer that
  // measures time exclusive of profiling overhead.
  uint64 cycles_overhead_;

  ReturnThunkFactory thunk_factory_;

  // The invocations we've recorded in our buffer.
  InvocationMap invocations_;

  // The trace file segment we're recording to.
  trace::client::TraceFileSegment segment_;

  // The current batch record we're writing to, if any.
  TraceBatchInvocationInfo* batch_;

  // The set of modules we've logged.
  ModuleSet logged_modules_;
};

void Profiler::ThreadState::LogAllModules(HMODULE module) {
  // Bail early if we're disabled.
  if (profiler_->session_.IsDisabled())
    return;

  agent::common::ModuleVector modules;
  agent::common::GetProcessModules(&modules);

  // Our module should be in the process modules.
  DCHECK(std::find(modules.begin(), modules.end(), module) != modules.end());

  for (size_t i = 0; i < modules.size(); ++i) {
    DCHECK(modules[i] != NULL);
    LogModule(modules[i]);
  }

  // We need to flush module events right away, so that the module is
  // defined in the trace file before events using that module start to
  // occur (in another thread).
  FlushSegment();
}

void Profiler::ThreadState::LogModule(HMODULE module) {
  // Make sure the event we're about to write will fit.
  if (!segment_.CanAllocate(sizeof(TraceModuleData)) || !FlushSegment()) {
    // Failed to allocate a new segment.
    return;
  }

  DCHECK(segment_.CanAllocate(sizeof(TraceModuleData)));

  // Allocate a record in the log.
  TraceModuleData* module_event = reinterpret_cast<TraceModuleData*>(
      segment_.AllocateTraceRecordImpl(
          TRACE_PROCESS_ATTACH_EVENT, sizeof(TraceModuleData)));
  DCHECK(module_event != NULL);

  // Populate the log record.
  base::win::PEImage image(module);
  module_event->module_base_addr = module;
  if (!CaptureModuleInformation(image, module_event)) {
    LOG(ERROR) << "Failed to capture module information.";
  }

  wchar_t module_name[MAX_PATH] = { 0 };
  if (::GetMappedFileName(::GetCurrentProcess(), module,
                          module_name, arraysize(module_name)) == 0) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to get module name: " << com::LogWe(error) << ".";
  }
  FilePath device_path(module_name);
  FilePath drive_path;
  if (!::common::ConvertDevicePathToDrivePath(device_path, &drive_path)) {
    LOG(ERROR) << "ConvertDevicePathToDrivePath failed.";
  }
  ::wcsncpy(module_event->module_name, drive_path.value().c_str(),
            arraysize(module_event->module_name));

  module_event->module_exe[0] = L'\0';
}

void Profiler::ThreadState::OnFunctionEntry(EntryFrame* entry_frame,
                                            FuncAddr function,
                                            uint64 cycles) {
  if (profiler_->session_.IsDisabled())
    return;

  // Record the details of the entry.
  // Note that on tail-recursion and tail-call elimination, the caller recorded
  // here will be a thunk. We cater for this case on exit as best we can.
  ReturnThunkFactory::Thunk* thunk =
      thunk_factory_.MakeThunk(entry_frame->retaddr);
  DCHECK(thunk != NULL);
  thunk->caller = entry_frame->retaddr;
  thunk->function = function;
  thunk->cycles_entry = cycles - cycles_overhead_;

  entry_frame->retaddr = thunk;

  UpdateOverhead(cycles);
}

void Profiler::ThreadState::OnFunctionExit(
    const ReturnThunkFactory::Thunk* thunk,
    uint64 cycles_exit) {
  // Calculate the number of cycles in the invocation, exclusive our overhead.
  uint64 cycles_executed = cycles_exit - cycles_overhead_ - thunk->cycles_entry;

  // See if the return address resolves to a thunk, which indicates
  // tail recursion or tail call elimination. In that case we record the
  // calling function as caller, which isn't totally accurate as that'll
  // attribute the cost to the first line of the calling function. In the
  // absence of more information, it's the best we can do, however.
  ReturnThunkFactory::Thunk* ret_thunk =
      thunk_factory_.CastToThunk(thunk->caller);
  if (ret_thunk == NULL) {
    RecordInvocation(thunk->caller, thunk->function, cycles_executed);
  } else {
    RecordInvocation(ret_thunk->function, thunk->function, cycles_executed);
  }

  UpdateOverhead(cycles_exit);
}

void Profiler::ThreadState::OnPageAdded(const void* page) {
  profiler_->OnPageAdded(page);
}

void Profiler::ThreadState::OnPageRemoved(const void* page) {
  profiler_->OnPageRemoved(page);
}

void Profiler::ThreadState::RecordInvocation(RetAddr caller,
                                             FuncAddr function,
                                             uint64 duration_cycles) {
  // See whether we've already recorded an entry for this function.
  InvocationKey key(caller, function);
  InvocationMap::iterator it = invocations_.find(key);
  if (it != invocations_.end()) {
    // Yup, we already have an entry. Tally the new data.
    InvocationInfo* info = it->second;
    ++(info->num_calls);
    info->cycles_sum += duration_cycles;
    if (duration_cycles < info->cycles_min) {
      info->cycles_min = duration_cycles;
    } else if (duration_cycles > info->cycles_max) {
      info->cycles_max = duration_cycles;
    }
  } else {
    // Nopes, allocate a new entry for this invocation.
    InvocationInfo* info = AllocateInvocationInfo();
    if (info != NULL) {
      invocations_[key] = info;
      info->caller = caller;
      info->function = function;
      info->num_calls = 1;
      info->cycles_min = info->cycles_max = info->cycles_sum = duration_cycles;
    }
  }
}

void Profiler::ThreadState::UpdateOverhead(uint64 entry_cycles) {
  // TODO(siggi): Measure the fixed overhead on setup,
  //     then add it on every update.
  cycles_overhead_ += (__rdtsc() - entry_cycles);
}

InvocationInfo* Profiler::ThreadState::AllocateInvocationInfo() {
  // This is kind of self-evident for the moment, as an invocation info batch
  // contains at least one invocation info as currently declared.
  // If this fails, please recondsider your implementation, or else revisit
  // the allocation code below.
  COMPILE_ASSERT(sizeof(TraceBatchInvocationInfo) >= sizeof(InvocationInfo),
                 invocation_info_batch_must_be_larger_than_invocation_info);

  // Do we have a record that we can grow?
  if (batch_ != NULL && segment_.CanAllocateRaw(sizeof(InvocationInfo))) {
    InvocationInfo* invocation_info =
        reinterpret_cast<InvocationInfo*>(segment_.write_ptr);
    RecordPrefix* prefix = trace::client::GetRecordPrefix(batch_);
    prefix->size += sizeof(InvocationInfo);

    // Update the book-keeping.
    segment_.write_ptr += sizeof(InvocationInfo);
    segment_.header->segment_length += sizeof(InvocationInfo);

    return invocation_info;
  }

  // Do we need to scarf a new buffer?
  if (!segment_.CanAllocate(sizeof(TraceBatchInvocationInfo)) &&
      !FlushSegment()) {
    // We failed to allocate a new buffer.
    return NULL;
  }

  DCHECK(segment_.header != NULL);

  batch_ = segment_.AllocateTraceRecord<TraceBatchInvocationInfo>();
  return &batch_->invocations[0];
}

bool Profiler::ThreadState::FlushSegment() {
  batch_ = NULL;
  invocations_.clear();

  return profiler_->session_.ExchangeBuffer(&segment_);
}

void Profiler::OnDetach() {
  FreeThreadState();
}

RetAddr* Profiler::ResolveReturnAddressLocation(RetAddr* pc_location) {
  base::AutoLock lock(lock_);

  // In case of tail-call and tail recursion elimination, we can get chained
  // thunks, so we loop around here until we resolve to a non-thunk.
  while (true) {
    // See whether the return address is one of our thunks.
    RetAddr ret_addr = *pc_location;

    // Compute the page this return address lives in.
    const void* page = reinterpret_cast<const void*>(
        reinterpret_cast<uintptr_t>(ret_addr) & ~0xFFF);
    if (!std::binary_search(pages_.begin(), pages_.end(), page))
      return pc_location;

    // It's one of our own, redirect to the thunk's stash.
    ReturnThunkFactory::Thunk* thunk =
        reinterpret_cast<ReturnThunkFactory::Thunk*>(
            const_cast<void*>(ret_addr));

    // Update the PC location and go around again, in case this
    // thunk links to another one.
    pc_location = &thunk->caller;
  }
}

void Profiler::OnModuleEntry(EntryFrame* entry_frame,
                             FuncAddr function,
                             uint64 cycles) {
  // The function invoked has a DllMain-like signature.
  // Get the module and reason from its invocation record.
  HMODULE module = reinterpret_cast<HMODULE>(entry_frame->args[0]);
  DWORD reason = entry_frame->args[1];

  // Only log module additions.
  bool should_log_module = false;
  switch (reason) {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
      should_log_module = true;
      break;

    case DLL_PROCESS_DETACH:
    case DLL_THREAD_DETACH:
      break;

    default:
      LOG(WARNING) << "Unrecognized module event: " << reason << ".";
      break;
  }

  // Make sure we only log each module once per process.
  bool is_new_module = false;
  if (should_log_module) {
    base::AutoLock lock(lock_);

    is_new_module = logged_modules_.insert(module).second;
  }

  ThreadState* data = GetOrAllocateThreadState();
  DCHECK(data != NULL);
  if (data == NULL)
    return;

  if (is_new_module) {
    // Delegate the logging to our per-thread data.
    data->LogAllModules(module);
  }

  // Handle the function entry.
  data->OnFunctionEntry(entry_frame, function, cycles);
}

void Profiler::OnPageAdded(const void* page) {
  base::AutoLock lock(lock_);

  PageVector::iterator it =
      std::lower_bound(pages_.begin(), pages_.end(), page);
  DCHECK(it == pages_.end() || *it != page);
  pages_.insert(it, page);
}

void Profiler::OnPageRemoved(const void* page) {
  base::AutoLock lock(lock_);

  PageVector::iterator it =
      std::lower_bound(pages_.begin(), pages_.end(), page);
  // The page must be in our list.
  DCHECK(it != pages_.end());
  DCHECK_EQ(page, *it);
  pages_.erase(it);
}

Profiler* Profiler::Instance() {
  return static_profiler_instance.Pointer();
}

Profiler::Profiler() {
  // Create our RPC session and allocate our initial trace segment on first use.
  ThreadState* data = CreateFirstThreadStateAndSession();
  CHECK(data != NULL) << "Failed to allocate thread local state.";
}

Profiler::~Profiler() {
}

Profiler::ThreadState* Profiler::CreateFirstThreadStateAndSession() {
  Profiler::ThreadState* data = GetOrAllocateThreadStateImpl();

  // Create the session (and allocate the first segment).
  session_.CreateSession(data->segment());

  return data;
}

Profiler::ThreadState* Profiler::GetOrAllocateThreadState() {
  Profiler::ThreadState* data = GetOrAllocateThreadStateImpl();
  if (!data->segment()->write_ptr && session_.IsTracing()) {
    session_.AllocateBuffer(data->segment());
  }
  return data;
}

Profiler::ThreadState* Profiler::GetOrAllocateThreadStateImpl() {
  ThreadState *data = tls_.Get();
  if (data != NULL)
    return data;

  data = new ThreadState(this);
  if (data == NULL) {
    LOG(ERROR) << "Unable to allocate per-thread data";
    return NULL;
  }
  tls_.Set(data);

  return data;
}

Profiler::ThreadState* Profiler::GetThreadState() const {
  return tls_.Get();
}

void Profiler::FreeThreadState() {
  ThreadState *data = tls_.Get();
  if (data != NULL) {
    delete data;
    tls_.Set(NULL);
  }
}

void WINAPI Profiler::DllMainEntryHook(EntryFrame* entry_frame,
                                       FuncAddr function,
                                       uint64 cycles) {
  ScopedLastErrorKeeper keep_last_error;

  Profiler* profiler = Profiler::Instance();
  profiler->OnModuleEntry(entry_frame, function, cycles);
}

void WINAPI Profiler::FunctionEntryHook(EntryFrame* entry_frame,
                                        FuncAddr function,
                                        uint64 cycles) {
  ScopedLastErrorKeeper keep_last_error;

  Profiler* profiler = Profiler::Instance();
  ThreadState* data = profiler->GetOrAllocateThreadState();
  DCHECK(data != NULL);
  if (data != NULL)
    data->OnFunctionEntry(entry_frame, function, cycles);
}

}  // namespace profiler
}  // namespace agent
