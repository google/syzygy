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
// Implementation of the profiler DLL.
#include "syzygy/agent/profiler/profiler.h"

#include <windows.h>
#include <algorithm>

#include "base/at_exit.h"
#include "base/bind.h"
#include "base/command_line.h"
#include "base/environment.h"
#include "base/logging.h"
#include "base/memory/scoped_ptr.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "base/win/pe_image.h"
#include "base/win/scoped_handle.h"
#include "syzygy/agent/common/agent.h"
#include "syzygy/agent/common/dlist.h"
#include "syzygy/agent/common/process_utils.h"
#include "syzygy/agent/common/scoped_last_error_keeper.h"
#include "syzygy/agent/profiler/return_thunk_factory.h"
#include "syzygy/common/logging.h"
#include "syzygy/trace/client/client_utils.h"
#include "syzygy/trace/protocol/call_trace_defs.h"

namespace {

using agent::common::ScopedLastErrorKeeper;

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

using agent::profiler::SymbolMap;

struct InvocationValue {
  // This invocation entry's caller's dynamic symbol, if any.
  scoped_refptr<SymbolMap::Symbol> caller_symbol;
  // The last observed move count for caller_symbol.
  int32 caller_move_count;

  // This invocation entry's callee's dynamic symbol, if any.
  scoped_refptr<SymbolMap::Symbol> function_symbol;
  // The last observed move count for function_symbol.
  int32 function_move_count;

  // Points to the trace buffer entry for the respective function.
  InvocationInfo* info;
};

typedef base::hash_map<
    InvocationKey, InvocationValue, HashInvocationKey> InvocationMap;


// The information on how to set the thread name comes from
// a MSDN article: http://msdn2.microsoft.com/en-us/library/xcb2z8hs.aspx
const DWORD kVCThreadNameException = 0x406D1388;

typedef struct tagTHREADNAME_INFO {
  DWORD dwType;  // Must be 0x1000.
  LPCSTR szName;  // Pointer to name (in user addr space).
  DWORD dwThreadID;  // Thread ID (-1=caller thread).
  DWORD dwFlags;  // Reserved for future use, must be zero.
} THREADNAME_INFO;

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

    // Save the value of eax for later, we need the register to stash the flags.
    push ecx
    mov ecx, eax

    // Save the low byte of the flags into AH.
    lahf
    // Save the overflow flag into AL.
    seto al

    // Stash the flags to stack.
    push eax

    // Push the cycle time arg.
    push edx
    push ecx

    // Retrieve the original function address, pushed by our caller.
    mov eax, DWORD PTR[esp + 0x18]
    push eax

    // Calculate the position of the return address on stack, and
    // push it. This becomes the EntryFrame argument.
    lea eax, DWORD PTR[esp + 0x20]
    push eax
    call agent::profiler::Profiler::FunctionEntryHook

    // Restore volatile registers.
    pop eax
    // AL is set to 1 if the overflow flag was set before the call to
    // our hook, 0 otherwise. We add 0x7f to it so it'll restore the
    // flag.
    add al, 0x7f
    // Restore the low byte of the flags.
    sahf

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

    // Save the value of eax for later, we need the register to stash the flags.
    push ecx
    mov ecx, eax

    // Save the low byte of the flags into AH.
    lahf
    // Save the overflow flag into AL.
    seto al

    // Stash the flags to stack.
    push eax

    // Push the cycle time arg.
    push edx
    push ecx

    // Retrieve the original function address, pushed by our caller.
    mov eax, DWORD PTR[esp + 0x18]
    push eax

    // Calculate the position of the return address on stack, and
    // push it. This becomes the EntryFrame argument.
    lea eax, DWORD PTR[esp + 0x20]
    push eax
    call agent::profiler::Profiler::DllMainEntryHook

    // Restore volatile registers.
    pop eax
    // AL is set to 1 if the overflow flag was set before the call to
    // our hook, 0 otherwise. We add 0x7f to it so it'll restore the
    // flag.
    add al, 0x7f
    // Restore the low byte of the flags.
    sahf

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
  return reinterpret_cast<uintptr_t>(
      Profiler::instance().ResolveReturnAddressLocation(
          reinterpret_cast<RetAddr*>(pc_location)));
}

// This function needs to match the declaration of FunctionEntryHook in the V8
// API. See http://v8.googlecode.com/svn/trunk/include/v8.h.
extern "C" __declspec(naked) void __cdecl OnDynamicFunctionEntry(
    uintptr_t function, uintptr_t return_addr_location) {
  __asm {
    // Grab the current time ASAP.
    rdtsc

    // Push the cycle time arg.
    push edx
    push eax

    // Duplicate the function and return_addr_location arguments.
    push DWORD PTR[esp + 0x10]
    push DWORD PTR[esp + 0x10]

    call agent::profiler::Profiler::OnV8FunctionEntry

    ret
  }
}

BOOL WINAPI DllMain(HMODULE instance, DWORD reason, LPVOID reserved) {
  using agent::profiler::Profiler;

  // Our AtExit manager required by base.
  static base::AtExitManager* at_exit = NULL;

  agent::common::InitializeCrt();

  switch (reason) {
    case DLL_PROCESS_ATTACH:
      DCHECK(at_exit == NULL);
      at_exit = new base::AtExitManager();

      CommandLine::Init(0, NULL);
      common::InitLoggingForDll(L"profiler");
      break;

    case DLL_THREAD_DETACH:
      Profiler::instance().OnThreadDetach();
      break;

    case DLL_PROCESS_DETACH:
      CommandLine::Reset();
      DCHECK(at_exit != NULL);
      delete at_exit;
      at_exit = NULL;
      break;

    default:
      break;
  }

  return TRUE;
}

void __cdecl AddDynamicSymbol(const void* address, size_t length,
                              const char* name, size_t name_len) {
  using agent::profiler::Profiler;

  Profiler::instance().AddSymbol(address, length, name, name_len);
}

void __cdecl MoveDynamicSymbol(const void* old_address,
                               const void* new_address) {
  using agent::profiler::Profiler;

  Profiler::instance().MoveSymbol(old_address, new_address);
}

namespace agent {
namespace profiler {

// All tracing runs through this object.
agent::profiler::Profiler Profiler::instance_;

class Profiler::ThreadState
    : public ReturnThunkFactoryImpl<Profiler::ThreadState>,
      public agent::common::ThreadStateBase {
 public:
  explicit ThreadState(Profiler* profiler);
  ~ThreadState();

  // Logs @p module and all other modules in the process, then flushes
  // the current trace buffer.
  void LogAllModules(HMODULE module);

  // Logs @p module.
  void LogModule(HMODULE module);

  // Logs @p thread_name as the current thread's name.
  void LogThreadName(const base::StringPiece& thread_name);

  // Logs @p symbol into the trace.
  void LogSymbol(SymbolMap::Symbol* symbol);

  // Processes a single function entry.
  void OnFunctionEntry(EntryFrame* entry_frame,
                       FuncAddr function,
                       uint64 cycles);

  // Processes a single V8 function entry.
  void OnV8FunctionEntry(FuncAddr function,
                         RetAddr* return_address_location,
                         uint64 cycles);

  // @name Callback notification implementation.
  // @{
  virtual void OnPageAdded(const void* page) OVERRIDE;
  virtual void OnPageRemoved(const void* page) OVERRIDE;
  // @}

  // Function exit hook.
  void OnFunctionExit(const ThunkData* data, uint64 cycles_exit);

  trace::client::TraceFileSegment* segment() { return &segment_; }

 private:
  friend class Profiler;

  void RecordInvocation(RetAddr caller,
                        FuncAddr function,
                        uint64 cycles);

  void UpdateOverhead(uint64 entry_cycles);
  InvocationInfo* AllocateInvocationInfo();
  void ClearCache();
  bool FlushSegment();

  // The profiler we're attached to.
  Profiler* profiler_;

  // We keep a running tally of the rough amount of wall clock cycles spent
  // inside the profiler. We then subtract the profiler's overhead from the
  // wall clock cycle timer on each measurement. This results in a timer that
  // measures time exclusive of profiling overhead.
  uint64 cycles_overhead_;

  // The invocations we've recorded in our buffer.
  InvocationMap invocations_;

  // The trace file segment we're recording to.
  trace::client::TraceFileSegment segment_;

  // The current batch record we're writing to, if any.
  TraceBatchInvocationInfo* batch_;

  // The set of modules we've logged.
  ModuleSet logged_modules_;
};

Profiler::ThreadState::ThreadState(Profiler* profiler)
    : profiler_(profiler),
      cycles_overhead_(0LL),
      batch_(NULL) {
  Initialize();
}

Profiler::ThreadState::~ThreadState() {
  ClearCache();

  // If we have an outstanding buffer, let's deallocate it now.
  if (segment_.write_ptr != NULL)
    profiler_->session_.ReturnBuffer(&segment_);

  Uninitialize();
}

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
  // This may flush our buffer, so let's clear our cache.
  ClearCache();
  agent::common::LogModule(module, &profiler_->session_, &segment_);
}

void Profiler::ThreadState::LogThreadName(
    const base::StringPiece& thread_name) {
  if (thread_name.empty())
    return;

  // Make sure the event we're about to write will fit.
  if (!segment_.CanAllocate(thread_name.size() + 1) || !FlushSegment()) {
    // Failed to allocate a new segment.
    return;
  }

  DCHECK(segment_.CanAllocate(thread_name.size() + 1));
  batch_ = NULL;

  // Allocate a record in the log.
  TraceThreadNameInfo* thread_name_event =
      reinterpret_cast<TraceThreadNameInfo*>(
        segment_.AllocateTraceRecordImpl(
            TRACE_THREAD_NAME, thread_name.size() + 1));
  DCHECK(thread_name_event != NULL);
  base::strlcpy(thread_name_event->thread_name,
                thread_name.data(), thread_name.size() + 1);
}

void Profiler::ThreadState::LogSymbol(SymbolMap::Symbol* symbol) {
  DCHECK(symbol != NULL);
  DCHECK_NE(0, symbol->id());

  size_t symbol_size =
      FIELD_OFFSET(TraceDynamicSymbol, symbol_name) + symbol->name().size() + 1;

  if (!segment_.CanAllocate(symbol_size) || !FlushSegment()) {
    // Failed to allocate the symbol record.
    return;
  }

  DCHECK(segment_.CanAllocate(symbol_size));
  batch_ = NULL;

  // Allocate a record in the log.
  TraceDynamicSymbol* dynamic_symbol_event =
      reinterpret_cast<TraceDynamicSymbol*>(
          segment_.AllocateTraceRecordImpl(
              TRACE_DYNAMIC_SYMBOL, symbol_size));
  DCHECK(dynamic_symbol_event != NULL);
  dynamic_symbol_event->symbol_id = symbol->id();
  base::strlcpy(dynamic_symbol_event->symbol_name,
                symbol->name().data(), symbol->name().size() + 1);
}

void Profiler::ThreadState::OnFunctionEntry(EntryFrame* entry_frame,
                                            FuncAddr function,
                                            uint64 cycles) {
  if (profiler_->session_.IsDisabled())
    return;

  // Record the details of the entry.
  // Note that on tail-recursion and tail-call elimination, the caller recorded
  // here will be a thunk. We cater for this case on exit as best we can.
  ThunkData* data = MakeThunk(entry_frame->retaddr);
  DCHECK(data != NULL);
  data->caller = entry_frame->retaddr;
  data->function = function;
  data->cycles_entry = cycles - cycles_overhead_;

  entry_frame->retaddr = data->thunk;

  UpdateOverhead(cycles);
}

void Profiler::ThreadState::OnV8FunctionEntry(FuncAddr function,
                                              RetAddr* return_address_location,
                                              uint64 cycles) {
  if (profiler_->session_.IsDisabled())
    return;

  // Record the details of the entry.

  // TODO(siggi): Note that we want to do different exit processing here,
  //    as we know "function" is a dynamic symbol - it might be better to
  //    record the fact here than to force a lookup on RecordInvocation.

  // Note that on tail-recursion and tail-call elimination, the caller recorded
  // here will be a thunk. We cater for this case on exit as best we can.
  ThunkData* data = MakeThunk(*return_address_location);
  DCHECK(data != NULL);
  data->caller = *return_address_location;
  data->function = function;
  data->cycles_entry = cycles - cycles_overhead_;

  *return_address_location = data->thunk;

  UpdateOverhead(cycles);
}

void Profiler::ThreadState::OnFunctionExit(const ThunkData* data,
                                           uint64 cycles_exit) {
  // Calculate the number of cycles in the invocation, exclusive our overhead.
  uint64 cycles_executed = cycles_exit - cycles_overhead_ - data->cycles_entry;

  // See if the return address resolves to a thunk, which indicates
  // tail recursion or tail call elimination. In that case we record the
  // calling function as caller, which isn't totally accurate as that'll
  // attribute the cost to the first line of the calling function. In the
  // absence of more information, it's the best we can do, however.
  // TODO(siggi): Move this into RecordInvocation, as we can elide the lookup
  //     on a cache hit.
  Thunk* ret_thunk = CastToThunk(data->caller);
  if (ret_thunk == NULL) {
    RecordInvocation(data->caller, data->function, cycles_executed);
  } else {
    ThunkData* ret_data = DataFromThunk(ret_thunk);
    RecordInvocation(ret_data->function, data->function, cycles_executed);
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
    // Yup, we already have an entry, validate it.
    InvocationValue& value = it->second;

    if ((value.caller_symbol == NULL ||
         value.caller_symbol->move_count() == value.caller_move_count) &&
        (value.function_symbol == NULL ||
         value.function_symbol->move_count() == value.function_move_count)) {
      // The entry is still good, tally the new data.
      ++(value.info->num_calls);
      value.info->cycles_sum += duration_cycles;
      if (duration_cycles < value.info->cycles_min) {
        value.info->cycles_min = duration_cycles;
      } else if (duration_cycles > value.info->cycles_max) {
        value.info->cycles_max = duration_cycles;
      }

      // Early out on success.
      return;
    } else {
      // The entry is not valid any more, discard it.
      DCHECK(value.caller_symbol != NULL || value.function_symbol != NULL);

      invocations_.erase(it);
    }
  }
  DCHECK(invocations_.find(key) == invocations_.end());

  // We don't have an entry, allocate a new one for this invocation.
  // The code below may touch last error.
  ScopedLastErrorKeeper keep_last_error;

  scoped_refptr<SymbolMap::Symbol> caller_symbol =
      profiler_->symbol_map_.FindSymbol(caller);

  // TODO(siggi): This can perhaps be optimized by keeping track of which
  //     entry hook was invoked. This will however require setting an extra
  //     bool on every entry, so will require measurement to see whether it's
  //     a win.
  scoped_refptr<SymbolMap::Symbol> function_symbol =
      profiler_->symbol_map_.FindSymbol(function);

  // Trace the symbols if this is the first time either one is observed.
  if (caller_symbol != NULL && caller_symbol->EnsureHasId()) {
    // TODO(siggi): It might lead to worst-case behavior to log symbols into
    //    the same trace buffer as we store invocations, as we're likely to
    //    alternate symbols and single-entry invocation batches. Fixme.
    LogSymbol(caller_symbol);
  }
  if (function_symbol != NULL && function_symbol->EnsureHasId()) {
    // TODO(siggi): See above.
    LogSymbol(function_symbol);
  }

  InvocationInfo* info = AllocateInvocationInfo();
  if (info != NULL) {
    InvocationValue& value = invocations_[key];
    value.info = info;
    value.caller_symbol = caller_symbol;
    if (caller_symbol != NULL)
      value.caller_move_count = caller_symbol->move_count();
    else
      value.caller_move_count = 0;

    value.function_symbol = function_symbol;
    if (function_symbol != NULL)
      value.function_move_count = function_symbol->move_count();
    else
      value.function_move_count = 0;

    if (function_symbol == NULL) {
      // We're not in a dynamic function, record the (conventional) function.
      info->function = function;
      info->flags = 0;
    } else {
      // We're in a dynamic function symbol, record the details.
      DCHECK_NE(function_symbol->id(), 0);

      info->function_symbol_id = function_symbol->id();
      info->flags = kFunctionIsSymbol;
    }

    if (caller_symbol == NULL) {
      // We're not in a dynamic caller_symbol, record the (conventional) caller.
      info->caller = caller;
      info->caller_offset = 0;
    } else {
      // We're in a dynamic caller_symbol, record the details.
      DCHECK_NE(caller_symbol->id(), 0);

      info->caller_symbol_id = caller_symbol->id();
      info->flags |= kCallerIsSymbol;
      info->caller_offset = reinterpret_cast<const uint8*>(caller) -
          reinterpret_cast<const uint8*>(caller_symbol->address());
    }

    info->num_calls = 1;
    info->cycles_min = info->cycles_max = info->cycles_sum = duration_cycles;
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
  // If this fails, please reconsider your implementation, or else revisit
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
  ClearCache();
  return profiler_->session_.ExchangeBuffer(&segment_);
}

void Profiler::ThreadState::ClearCache() {
  batch_ = NULL;
  invocations_.clear();
}

void Profiler::OnThreadDetach() {
  ThreadState* state = GetThreadState();
  if (state != NULL)
    thread_state_manager_.MarkForDeath(state);
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
    ThreadState::Thunk* thunk =
        reinterpret_cast<ThreadState::Thunk*>(const_cast<void*>(ret_addr));

    ThreadState::ThunkData* data = ThreadState::DataFromThunk(thunk);

    // Update the PC location and go around again, in case this
    // thunk links to another one.
    pc_location = &data->caller;
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

void Profiler::OnThreadName(const base::StringPiece& thread_name) {
  ThreadState* state = GetOrAllocateThreadState();
  if (state != NULL)
    state->LogThreadName(thread_name);
}

LONG CALLBACK Profiler::ExceptionHandler(EXCEPTION_POINTERS* ex_info) {
  // Log the thread if this is the VC thread name exception.
  if (ex_info->ExceptionRecord->ExceptionCode == kVCThreadNameException &&
      ex_info->ExceptionRecord->NumberParameters ==
          sizeof(THREADNAME_INFO)/sizeof(DWORD)) {
    const THREADNAME_INFO* info =
        reinterpret_cast<const THREADNAME_INFO*>(
            &ex_info->ExceptionRecord->ExceptionInformation);

    if (info->dwType == 0x1000) {
      instance_.OnThreadName(info->szName);
    } else {
      LOG(WARNING) << "Unrecognized event type " << info->dwType;
    }
  }

  return EXCEPTION_CONTINUE_SEARCH;
}

void Profiler::OnDllEvent(agent::common::DllNotificationWatcher::EventType type,
                          HMODULE module,
                          size_t module_size,
                          const base::StringPiece16& dll_path,
                          const base::StringPiece16& dll_base_name) {
  if (type == agent::common::DllNotificationWatcher::kDllLoaded) {
    // Bail early if there's no session.
    if (session_.IsDisabled())
      return;

    // Trace the load event.
    ThreadState* state = GetOrAllocateThreadState();
    if (state != NULL)
      state->LogModule(module);
  }
}

Profiler::Profiler() : handler_registration_(NULL) {
  // Create our RPC session and allocate our initial trace segment on creation,
  // aka at load time.
  ThreadState* data = CreateFirstThreadStateAndSession();
  CHECK(data != NULL) << "Failed to allocate thread local state.";

  handler_registration_ = ::AddVectoredExceptionHandler(TRUE, ExceptionHandler);

  dll_watcher_.Init(base::Bind(&Profiler::OnDllEvent, base::Unretained(this)));
}

Profiler::~Profiler() {
  // Since the DLL notification callback depends on thread and session state,
  // let's tear it down first. Note that this grabs the loader's lock,
  // so there's deadlock potential here, but no other thread will get a DLL
  // notification after this call returns.
  dll_watcher_.Reset();

  // Typically, this will happen on the last thread in the process. We must
  // explicitly clean up this thread's state as it will otherwise leak.
  FreeThreadState();

  // Unregister our VEH.
  if (handler_registration_ != NULL) {
    ::RemoveVectoredExceptionHandler(handler_registration_);
    handler_registration_ = NULL;
  }
}

Profiler::ThreadState* Profiler::CreateFirstThreadStateAndSession() {
  Profiler::ThreadState* data = GetOrAllocateThreadStateImpl();

  // Create the session (and allocate the first segment).
  trace::client::InitializeRpcSession(&session_, data->segment());

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

  thread_state_manager_.Register(data);
  tls_.Set(data);

  return data;
}

Profiler::ThreadState* Profiler::GetThreadState() const {
  return tls_.Get();
}

void Profiler::FreeThreadState() {
  ThreadState *data = GetThreadState();
  if (data != NULL) {
    tls_.Set(NULL);
    thread_state_manager_.Unregister(data);
    delete data;
  }
}

void WINAPI Profiler::DllMainEntryHook(EntryFrame* entry_frame,
                                       FuncAddr function,
                                       uint64 cycles) {
  ScopedLastErrorKeeper keep_last_error;

  instance_.OnModuleEntry(entry_frame, function, cycles);
}

void WINAPI Profiler::FunctionEntryHook(EntryFrame* entry_frame,
                                        FuncAddr function,
                                        uint64 cycles) {
  ScopedLastErrorKeeper keep_last_error;

  ThreadState* data = instance_.GetOrAllocateThreadState();
  DCHECK(data != NULL);
  if (data != NULL)
    data->OnFunctionEntry(entry_frame, function, cycles);
}

void WINAPI Profiler::OnV8FunctionEntry(FuncAddr function,
                                        RetAddr* return_addr_location,
                                        uint64 cycles) {
  ScopedLastErrorKeeper keep_last_error;

  ThreadState* data = instance_.GetOrAllocateThreadState();
  if (data != NULL)
    data->OnV8FunctionEntry(function, return_addr_location, cycles);
}

void Profiler::AddSymbol(const void* address, size_t length,
                         const char* name, size_t name_len) {
  symbol_map_.AddSymbol(address, length, base::StringPiece(name, name_len));
}

void Profiler::MoveSymbol(const void* old_address, const void* new_address) {
  symbol_map_.MoveSymbol(old_address, new_address);
}

}  // namespace profiler
}  // namespace agent
