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
// Implementation of the basic-block entry counting agent library.

#include "syzygy/agent/basic_block_entry/basic_block_entry.h"

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/environment.h"
#include "base/file_path.h"
#include "base/lazy_instance.h"
#include "base/stringprintf.h"
#include "base/utf_string_conversions.h"
#include "base/memory/scoped_ptr.h"
#include "sawbuck/common/com_utils.h"
#include "syzygy/agent/common/process_utils.h"
#include "syzygy/agent/common/scoped_last_error_keeper.h"
#include "syzygy/common/logging.h"
#include "syzygy/trace/protocol/call_trace_defs.h"

extern "C" void __declspec(naked) _basic_block_enter() {
  __asm {
    // This is expected to be called via instrumentation that looks like:
    //    push bb_id
    //    push module_data
    //    call [_basic_block_enter]
    //
    // Stack: ... bb_id, module_data, ret_addr.

    // Stash volatile registers.
    push eax
    push ecx
    push edx
    pushfd

    // Stack: ... bb_id, module_data, ret_addr, eax, ecx, edx, fd.

    // Push the original esp value onto the stack as the entry-hook data.
    // This gives the entry-hook a pointer to ret_addr, module_data and bb_id.
    lea eax, DWORD PTR[esp + 0x10]
    push eax

    // Stack: ..., bb_id, module_data, ret_addr, eax, ecx, edx, fd, &ret_addr.
    call agent::basic_block_entry::BasicBlockEntry::BasicBlockEntryHook

    // Stack: ... bb_id, module_data, ret_addr, eax, ecx, edx, fd.

    // Restore volatile registers.
    popfd
    pop edx
    pop ecx
    pop eax

    // Stack: ... bb_id, module_data, ret_addr.

    // Return to the address pushed by our caller, popping off the bb_id and
    // module_data values from the stack.
    ret 8

    // Stack: ...
  }
}

extern "C" void __declspec(naked) _indirect_penter_dllmain() {
  __asm {
    // This is expected to be called via a thunk that looks like:
    //    push module_data
    //    push function
    //    jmp [_indirect_penter_dllmain]
    //
    // Stack: ... reserved, reason, module, ret_addr, module_data, function.

    // Stash volatile registers.
    push eax
    push ecx
    push edx
    pushfd

    // Stack: ... reserved, reason, module, ret_addr, module_data, function,
    //        eax, ecx, edx, fd.

    // Push the original esp value onto the stack as the entry-hook data.
    // This gives the entry-hook a pointer to function, module_data, ret_addr,
    // module and reason.
    lea eax, DWORD PTR[esp + 0x10]
    push eax

    // Stack: ... reserved, reason, module, ret_addr, module_data, function,
    //        eax, ecx, edx, fd, &function.

    call agent::basic_block_entry::BasicBlockEntry::DllMainEntryHook

    // Stack: ... reserved, reason, module, ret_addr, module_data, function,
    //        eax, ecx, edx, fd.

    // Restore volatile registers.
    popfd
    pop edx
    pop ecx
    pop eax

    // Stack: ... reserved, reason, module, ret_addr, module_data, function.

    // Return to the thunked function, popping module_data off the stack as
    // we go.
    ret 4

    // Stack: ... reserved, reason, module, ret_addr.
  }
}

BOOL WINAPI DllMain(HMODULE instance, DWORD reason, LPVOID reserved) {
  // Our AtExit manager required by base.
  static base::AtExitManager* at_exit = NULL;

  switch (reason) {
    case DLL_PROCESS_ATTACH:
      DCHECK(at_exit == NULL);
      at_exit = new base::AtExitManager();

      CommandLine::Init(0, NULL);
      common::InitLoggingForDll(L"basic_block_entry");
      LOG(INFO) << "Initialized basic-block entry counting agent library.";
      break;

    case DLL_THREAD_ATTACH:
      break;

    case DLL_THREAD_DETACH:
      break;

    case DLL_PROCESS_DETACH:
      DCHECK(at_exit != NULL);
      delete at_exit;
      at_exit = NULL;
      break;

    default:
      NOTREACHED();
      break;
  }

  return TRUE;
}

namespace agent {
namespace basic_block_entry {

namespace {

using ::common::BasicBlockFrequencyData;
using agent::common::ScopedLastErrorKeeper;
using trace::client::TraceFileSegment;

// All tracing runs through this object.
base::LazyInstance<BasicBlockEntry> static_coverage_instance =
    LAZY_INSTANCE_INITIALIZER;

// Get the address of the module containing @p addr. We do this by querying
// for the allocation that contains @p addr. This must lie within the
// instrumented module, and be part of the single allocation in  which the
// image of the module lies. The base of the module will be the base address
// of the allocation.
// TODO(rogerm): Move to agent::common.
HMODULE GetModuleForAddr(const void* addr) {
  MEMORY_BASIC_INFORMATION mem_info = {};

  // Lookup up the allocation in which addr is located.
  if (::VirtualQuery(addr, &mem_info, sizeof(mem_info)) == 0) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "VirtualQuery failed: " << com::LogWe(error) << ".";
    return NULL;
  }

  // Check that the allocation base has a valid PE header magic number.
  base::win::PEImage image(reinterpret_cast<HMODULE>(mem_info.AllocationBase));
  if (!image.VerifyMagic()) {
    LOG(ERROR) << "Invalid module found for "
               << base::StringPrintf("0x%08X", addr) << ".";
    return NULL;
  }

  // Then it's a module.
  return image.module();
}

}  // namespace

// The basic-block entry hook parameters.
struct BasicBlockEntry::BasicBlockEntryFrame {
  const void* ret_addr;
  BasicBlockFrequencyData* module_data;
  uint32 basic_block_id;
};

// The dllmain entry hook parameters.
struct BasicBlockEntry::DllMainEntryFrame {
  FuncAddr function;
  BasicBlockFrequencyData* module_data;
  const void* ret_addr;
  HMODULE module;
  DWORD reason;
  DWORD reserved;
};

namespace {

COMPILE_ASSERT(sizeof(BasicBlockEntry::BasicBlockEntryFrame) == 12,
               BasicBlockEntry_BasicBlockEntryFrame_is_not_the_right_size);

COMPILE_ASSERT(sizeof(BasicBlockEntry::DllMainEntryFrame) == 24,
               BasicBlockEntry_DllMainEntryFrame_is_not_the_right_size);

}

// The per-thread-per-instrumented-module state managed by this agent.
class BasicBlockEntry::ThreadState : public agent::common::ThreadStateBase {
 public:
  // Initialize a ThreadState instance.
  ThreadState(BasicBlockEntry* agent, void* buffer);

  // Destroy a ThreadState instance.
  ~ThreadState();

  // @name Accessors.
  // @{
  uint32* frequency_data() { return frequency_data_; }
  TraceFileSegment* segment() { return &segment_; }
  TraceBasicBlockFrequencyData* trace_data() { return trace_data_; }
  // @}

  // @name Mutators.
  // @{
  void set_frequency_data(void* buffer);
  void set_trace_data(TraceBasicBlockFrequencyData* trace_data);
  // @}

  // A helper to return a ThreadState pointer given a TLS index.
  static ThreadState* Get(DWORD tls_index);

  // A helper to assign a ThreadState pointer to a TLS index.
  void Assign(DWORD tls_index);

  // Saturation increment the frequency record for @p basic_block_id. Note
  // that in Release mode, no range checking is performed on basic_block_id.
  void Increment(uint32 basic_block_id);

 protected:
  // As a shortcut, this points to the beginning of the array of basic-block
  // entry frequency values. With tracing enabled, this is equivalent to:
  //     reinterpret_cast<uint32*>(this->trace_data->frequency_data)
  // If tracing is not enabled, this will be set to point to a static
  // allocation of BasicBlockFrequencyData::frequency_data.
  uint32* frequency_data_;

  // The basic-block entry agent this tread state belongs to.
  BasicBlockEntry* agent_;

  // The thread's current trace-file segment, if any.
  trace::client::TraceFileSegment segment_;

  // The basic-block frequency record we're populating. This will point into
  // the associated trace file segment's buffer.
  TraceBasicBlockFrequencyData* trace_data_;

 private:
  DISALLOW_COPY_AND_ASSIGN(ThreadState);
};

BasicBlockEntry::ThreadState::ThreadState(BasicBlockEntry* agent, void* buffer)
    : agent_(agent),
      frequency_data_(static_cast<uint32*>(buffer)),
      trace_data_(NULL) {
  DCHECK(agent != NULL);
  DCHECK(buffer != NULL);
}

BasicBlockEntry::ThreadState::~ThreadState() {
  // If we have an outstanding buffer, let's deallocate it now.
  if (segment_.write_ptr != NULL && !agent_->session_.IsDisabled())
    agent_->session_.ReturnBuffer(&segment_);
}

void BasicBlockEntry::ThreadState::set_frequency_data(void* buffer) {
  DCHECK(buffer != NULL);
  frequency_data_ = static_cast<uint32*>(buffer);
}

void BasicBlockEntry::ThreadState::set_trace_data(
    TraceBasicBlockFrequencyData* trace_data) {
  DCHECK(trace_data != NULL);
  trace_data_ = trace_data;
}

BasicBlockEntry::ThreadState* BasicBlockEntry::ThreadState::Get(
    DWORD tls_index) {
  DCHECK_NE(TLS_OUT_OF_INDEXES, tls_index);
  return static_cast<ThreadState*>(::TlsGetValue(tls_index));
}

void BasicBlockEntry::ThreadState::Assign(DWORD tls_index) {
  DCHECK_NE(TLS_OUT_OF_INDEXES, tls_index);
  ::TlsSetValue(tls_index, this);
}

inline void BasicBlockEntry::ThreadState::Increment(uint32 basic_block_id) {
  DCHECK(frequency_data_ != NULL);
  DCHECK(trace_data_ == NULL || basic_block_id < trace_data_->num_basic_blocks);
  uint32& element = frequency_data_[basic_block_id];
  if (element != ~0U)
    ++element;
}

BasicBlockEntry* BasicBlockEntry::Instance() {
  return static_coverage_instance.Pointer();
}

BasicBlockEntry::BasicBlockEntry() {
  scoped_ptr<base::Environment> env(base::Environment::Create());
  std::string id;
  env->GetVar(::kSyzygyRpcInstanceIdEnvVar, &id);
  session_.set_instance_id(UTF8ToWide(id));

  // Create a session. We immediately return the buffer that gets allocated
  // to us. The client will perform thread-local buffer management on an as-
  // needed basis.
  trace::client::TraceFileSegment dummy_segment;
  if (session_.CreateSession(&dummy_segment)) {
    CHECK(session_.ReturnBuffer(&dummy_segment));
  }
}

BasicBlockEntry::~BasicBlockEntry() {
}

void BasicBlockEntry::BasicBlockEntryHook(BasicBlockEntryFrame* entry_frame) {
  ScopedLastErrorKeeper scoped_last_error_keeper;
  DCHECK(entry_frame != NULL);
  DCHECK(entry_frame->module_data != NULL);
  DCHECK_GT(entry_frame->module_data->num_basic_blocks,
            entry_frame->basic_block_id);

  // TODO(rogerm): Consider extracting a fast path for state != NULL? Inline it
  //     during instrumentation? Move it into the _basic_block_enter function?
  ThreadState* state = ThreadState::Get(entry_frame->module_data->tls_index);
  if (state == NULL)
    state = Instance()->CreateThreadState(entry_frame);
  state->Increment(entry_frame->basic_block_id);
}

void BasicBlockEntry::DllMainEntryHook(DllMainEntryFrame* entry_frame) {
  ScopedLastErrorKeeper scoped_last_error_keeper;
  DCHECK(entry_frame != NULL);
  switch (entry_frame->reason) {
    case DLL_PROCESS_ATTACH:
      Instance()->OnProcessAttach(entry_frame);
      break;

    case DLL_THREAD_ATTACH:
      // We don't handle this event because the thread may never actually
      // call into an instrumented module, so we don't want to allocate
      // resources needlessly. Further, we won't get this event for thread
      // that were created before the agent was loaded. On first use of
      // an instrumented basic-block in a given thread, any thread specific
      // resources will be allocated.
      break;

    case DLL_PROCESS_DETACH:
    case DLL_THREAD_DETACH:
      Instance()->OnThreadDetach(entry_frame);
      break;

    default:
      NOTREACHED();
  }
}

void BasicBlockEntry::RegisterModule(const void* addr) {
  DCHECK(addr != NULL);

  // Allocate a segment for the module information.
  trace::client::TraceFileSegment module_info_segment;
  CHECK(session_.AllocateBuffer(&module_info_segment));

  // Log the module. This is required in order to associate basic-block
  // frequency with a module and PDB file during post-processing.
  HMODULE module = GetModuleForAddr(addr);
  CHECK(module != NULL);
  CHECK(agent::common::LogModule(module, &session_, &module_info_segment));

  // Commit the module information.
  CHECK(session_.ReturnBuffer(&module_info_segment));
}

void BasicBlockEntry::OnProcessAttach(DllMainEntryFrame* entry_frame) {
  DCHECK(entry_frame != NULL);

  // Exit if the magic number does not match.
  CHECK_EQ(::common::kBasicBlockEntryAgentId,
           entry_frame->module_data->agent_id);

  // Exit if the version does not match.
  CHECK_EQ(::common::kBasicBlockFrequencyDataVersion,
           entry_frame->module_data->version);

  // We allow for this hook to be called multiple times. We expect the first
  // time to occur under the loader lock, so we don't need to worry about
  // concurrency for this check.
  if (entry_frame->module_data->initialization_attempted)
    return;

  // Flag the module as initialized.
  entry_frame->module_data->initialization_attempted = 1U;

  // We expect this to be executed exactly once for each module.
  CHECK_EQ(TLS_OUT_OF_INDEXES, entry_frame->module_data->tls_index);
  entry_frame->module_data->tls_index = ::TlsAlloc();
  CHECK_NE(TLS_OUT_OF_INDEXES, entry_frame->module_data->tls_index);

  // Register this module with the call_trace if the session is not disabled.
  if (!session_.IsDisabled())
    RegisterModule(entry_frame->function);
}

void BasicBlockEntry::OnThreadDetach(DllMainEntryFrame* entry_frame) {
  DCHECK(entry_frame != NULL);
  DCHECK_EQ(1U, entry_frame->module_data->initialization_attempted);
  DCHECK_NE(TLS_OUT_OF_INDEXES, entry_frame->module_data->tls_index);

  ThreadState* state = ThreadState::Get(entry_frame->module_data->tls_index);
  if (state != NULL)
    thread_state_manager_.MarkForDeath(state);
}

BasicBlockEntry::ThreadState* BasicBlockEntry::CreateThreadState(
    BasicBlockEntryFrame* entry_frame) {
  DCHECK(entry_frame != NULL);

  // Create the thread-local state for this thread. By default, just point the
  // counter array to the statically allocated fall-back area.
  ThreadState* state = new ThreadState(
      this, entry_frame->module_data->frequency_data);
  CHECK(state != NULL);

  // Associate the thread_state with the current thread.
  state->Assign(entry_frame->module_data->tls_index);

  // Register the thread state with the thread state manager.
  thread_state_manager_.Register(state);

  // If we're not actually tracing, then we're done.
  if (session_.IsDisabled())
    return state;

  // Nothing to allocate? We're done!
  if (entry_frame->module_data->num_basic_blocks == 0) {
    LOG(WARNING) << "Module contains no instrumented basic blocks, not "
                 << "allocating basic-block trace data segment.";
    return state;
  }

  // Determine the size of the basic block frequency table.
  size_t data_size =
      entry_frame->module_data->num_basic_blocks * sizeof(uint32);

  // Determine the size of the basic block frequency record.
  size_t record_size = sizeof(TraceBasicBlockFrequencyData) + data_size - 1;

  // Determine the size of the buffer we need. We need room for the basic block
  // frequency struct plus a single RecordPrefix header.
  size_t segment_size = sizeof(RecordPrefix) + record_size;

  // Allocate the actual segment for the coverage data.
  CHECK(session_.AllocateBuffer(segment_size, state->segment()));

  // Ensure it's big enough to allocate the basic-block frequency data
  // we want. This automatically accounts for the RecordPrefix overhead.
  CHECK(state->segment()->CanAllocate(record_size));

  // Allocate the basic-block frequency data. We will leave this allocated and
  // let it get flushed during tear-down of the call-trace client.
  TraceBasicBlockFrequencyData* trace_data =
      reinterpret_cast<TraceBasicBlockFrequencyData*>(
          state->segment()->AllocateTraceRecordImpl(TRACE_BASIC_BLOCK_FREQUENCY,
                                                    record_size));
  DCHECK(trace_data != NULL);

  // Initialize the basic block frequency data struct.
  HMODULE module = GetModuleForAddr(entry_frame->ret_addr);
  CHECK(module != NULL);
  const base::win::PEImage image(module);
  const IMAGE_NT_HEADERS* nt_headers = image.GetNTHeaders();
  trace_data->module_base_addr = reinterpret_cast<ModuleAddr>(image.module());
  trace_data->module_base_size = nt_headers->OptionalHeader.SizeOfImage;
  trace_data->module_checksum = nt_headers->OptionalHeader.CheckSum;
  trace_data->module_time_date_stamp = nt_headers->FileHeader.TimeDateStamp;
  trace_data->frequency_size = sizeof(uint32);
  trace_data->num_basic_blocks = entry_frame->module_data->num_basic_blocks;

  // Hook up the newly allocated buffer to the call-trace instrumentation.
  state->set_frequency_data(trace_data->frequency_data);

  return state;
}

}  // namespace coverage
}  // namespace agent
