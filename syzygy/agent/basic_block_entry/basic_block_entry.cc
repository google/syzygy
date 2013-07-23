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
// Implementation of the basic-block entry counting agent library.

#include "syzygy/agent/basic_block_entry/basic_block_entry.h"

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/environment.h"
#include "base/lazy_instance.h"
#include "base/stringprintf.h"
#include "base/utf_string_conversions.h"
#include "base/memory/scoped_ptr.h"
#include "sawbuck/common/com_utils.h"
#include "syzygy/agent/common/process_utils.h"
#include "syzygy/agent/common/scoped_last_error_keeper.h"
#include "syzygy/common/indexed_frequency_data.h"
#include "syzygy/common/logging.h"
#include "syzygy/trace/protocol/call_trace_defs.h"

// Save caller-save registers (eax, ecx, edx) and flags (eflags).
#define BBENTRY_SAVE_REGISTERS  \
  __asm push eax  \
  __asm lahf  \
  __asm seto al  \
  __asm push eax  \
  __asm push ecx  \
  __asm push edx

// Restore caller-save registers (eax, ecx, edx) and flags (eflags).
#define BBENTRY_RESTORE_REGISTERS  \
  __asm pop edx  \
  __asm pop ecx  \
  __asm pop eax  \
  __asm add al, 0x7f  \
  __asm sahf  \
  __asm pop eax

#define BBENTRY_REDIRECT_CALL(handler)  \
  {  \
    /* Stash volatile registers. */  \
    BBENTRY_SAVE_REGISTERS  \
    \
    /* Stack: ... index, module_data, ret_addr, [4x register] */  \
    \
    /* Push the original esp value onto the stack as the entry-hook data. */  \
    /* This gives the entry-hook a pointer to ret_addr, module_data and */  \
    /* index. */  \
    __asm lea eax, DWORD PTR[esp + 0x10]  \
    __asm push eax  \
    \
    /* Stack: ..., index, module_data, ret_addr, [4x register], esp, */  \
    /*    &ret_addr. */  \
    __asm call handler  \
    /* Stack: ... index, module_data, ret_addr, [4x register]. */  \
    \
    /* Restore volatile registers. */  \
    BBENTRY_RESTORE_REGISTERS  \
  }

extern "C" uint32* _stdcall GetRawFrequencyData(
    ::common::IndexedFrequencyData* data) {
  DCHECK(data != NULL);
  return agent::basic_block_entry::BasicBlockEntry::GetRawFrequencyData(data);
}

extern "C" void __declspec(naked) _branch_enter() {
  // This is expected to be called via instrumentation that looks like:
  //    push index
  //    push module_data
  //    call [_branch_enter]
  // Stack: ... index, module_data, ret_addr.
  BBENTRY_REDIRECT_CALL(
      agent::basic_block_entry::BasicBlockEntry::BranchEnterHook);
  // Return to the address pushed by our caller, popping off the index and
  // module_data values from the stack.
  __asm ret 8
}

extern "C" void __declspec(naked) _branch_exit() {
  // This is expected to be called via instrumentation that looks like:
  //    push index
  //    push module_data
  //    call [_branch_enter]
  // Stack: ... index, module_data, ret_addr.
  BBENTRY_REDIRECT_CALL(
      agent::basic_block_entry::BasicBlockEntry::BranchExitHook);
  // Return to the address pushed by our caller, popping off the index and
  // module_data values from the stack.
  __asm ret 8
}

extern "C" void __declspec(naked) _increment_indexed_freq_data() {
  // This is expected to be called via instrumentation that looks like:
  //    push index
  //    push module_data
  //    call [_branch_enter]
  // Stack: ... index, module_data, ret_addr.
  BBENTRY_REDIRECT_CALL(
      agent::basic_block_entry::BasicBlockEntry::IncrementIndexedFreqDataHook);
  // Return to the address pushed by our caller, popping off the index and
  // module_data values from the stack.
  __asm ret 8
}

extern "C" void __declspec(naked) _indirect_penter_dllmain() {
  // This is expected to be called via a thunk that looks like:
  //    push module_data
  //    push function
  //    jmp [_indirect_penter_dllmain]
  // Stack: ... reserved, reason, module, ret_addr, module_data, function.
  BBENTRY_REDIRECT_CALL(
      agent::basic_block_entry::BasicBlockEntry::DllMainEntryHook);
  // Return to the thunked function, popping module_data off the stack as we go.
  __asm ret 4
}

extern "C" void __declspec(naked) _indirect_penter_exemain() {
  // This is expected to be called via a thunk that looks like:
  //    push module_data
  //    push function
  //    jmp [_indirect_penter_exe_main]
  //
  // Stack: ... ret_addr, module_data, function.
  BBENTRY_REDIRECT_CALL(
      agent::basic_block_entry::BasicBlockEntry::ExeMainEntryHook);
  // Return to the thunked function, popping module_data off the stack as we go.
  __asm ret 4
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

using ::common::IndexedFrequencyData;
using agent::common::ScopedLastErrorKeeper;
using trace::client::TraceFileSegment;

// The indexed_frequency_data for the branch instrumentation mode has 3 columns.
struct BranchFrequency {
  unsigned int frequency;
  unsigned int branch_taken;
  unsigned int miss_predicted;
};

// All tracing runs through this object.
base::LazyInstance<BasicBlockEntry> static_bbentry_instance =
    LAZY_INSTANCE_INITIALIZER;

// Increment and saturate a 32-bit value.
inline uint32 IncrementAndSaturate(uint32 value) {
  if (value != ~0U)
    ++value;
  return value;
}

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

// Returns true if @p version is the expected version for @p datatype_id.
bool DatatypeVersionIsValid(uint32 datatype_id, uint32 version) {
  if (datatype_id == ::common::IndexedFrequencyData::BASIC_BLOCK_ENTRY)
    return version == ::common::kBasicBlockFrequencyDataVersion;
  else if (datatype_id == ::common::IndexedFrequencyData::BRANCH)
    return version == ::common::kBranchFrequencyDataVersion;
  else if (datatype_id == ::common::IndexedFrequencyData::JUMP_TABLE)
    return version == ::common::kJumpTableFrequencyDataVersion;
  return false;
}

}  // namespace

// The IncrementIndexedFreqDataHook parameters.
struct BasicBlockEntry::IncrementIndexedFreqDataFrame {
  const void* ret_addr;
  IndexedFrequencyData* module_data;
  uint32 index;
};
COMPILE_ASSERT_IS_POD_OF_SIZE(BasicBlockEntry::IncrementIndexedFreqDataFrame,
                              12);

// The DllMainEntryHook parameters.
struct BasicBlockEntry::DllMainEntryFrame {
  FuncAddr function;
  IndexedFrequencyData* module_data;
  const void* ret_addr;
  HMODULE module;
  DWORD reason;
  DWORD reserved;
};
COMPILE_ASSERT_IS_POD_OF_SIZE(BasicBlockEntry::DllMainEntryFrame, 24);

// The ExeMainEntryHook parameters.
struct BasicBlockEntry::ExeMainEntryFrame {
  FuncAddr function;
  IndexedFrequencyData* module_data;
  const void* ret_addr;
};
COMPILE_ASSERT_IS_POD_OF_SIZE(BasicBlockEntry::ExeMainEntryFrame, 12);

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
  TraceIndexedFrequencyData* trace_data() { return trace_data_; }
  // @}

  // @name Mutators.
  // @{
  void set_frequency_data(void* buffer);
  void set_trace_data(TraceIndexedFrequencyData* trace_data);
  // @}

  // Allocate a temporary buffer used by the branch predictor simulator.
  void AllocatePredictorData(size_t size);

  // A helper to return a ThreadState pointer given a TLS index.
  static ThreadState* Get(DWORD tls_index);

  // A helper to assign a ThreadState pointer to a TLS index.
  void Assign(DWORD tls_index);

  // Saturation increment the frequency record for @p index. Note that in
  // Release mode, no range checking is performed on index.
  void Increment(uint32 index);

  // Update state and frequency when a jump enters the basic block @p index.
  void Enter(uint32 index);

  // Update state and frequency when a jump leaves the basic block @p index.
  void Leave(uint32 index);

 protected:
  // As a shortcut, this points to the beginning of the array of basic-block
  // entry frequency values. With tracing enabled, this is equivalent to:
  //     reinterpret_cast<uint32*>(this->trace_data->frequency_data)
  // If tracing is not enabled, this will be set to point to a static
  // allocation of IndexedFrequencyData::frequency_data.
  uint32* frequency_data_;

  // The branch predictor state (2-bit saturating counter).
  uint8* predictor_data_;

  // The basic-block entry agent this thread state belongs to.
  BasicBlockEntry* agent_;

  // The thread's current trace-file segment, if any.
  trace::client::TraceFileSegment segment_;

  // The basic-block frequency record we're populating. This will point into
  // the associated trace file segment's buffer.
  TraceIndexedFrequencyData* trace_data_;

  // The basic block id before the last leaving jump.
  uint32 last_basic_block_id_;

 private:
  DISALLOW_COPY_AND_ASSIGN(ThreadState);
};

BasicBlockEntry::ThreadState::ThreadState(BasicBlockEntry* agent, void* buffer)
    : agent_(agent),
      frequency_data_(static_cast<uint32*>(buffer)),
      predictor_data_(NULL),
      trace_data_(NULL),
      last_basic_block_id_(~0U) {
  DCHECK(agent != NULL);
  DCHECK(buffer != NULL);
}

BasicBlockEntry::ThreadState::~ThreadState() {
  // If we have an outstanding buffer, let's deallocate it now.
  if (segment_.write_ptr != NULL && !agent_->session_.IsDisabled())
    agent_->session_.ReturnBuffer(&segment_);

  // If the predictor space was used, free it.
  if (predictor_data_ != NULL)
    delete [] predictor_data_;
}

void BasicBlockEntry::ThreadState::set_frequency_data(void* buffer) {
  DCHECK(buffer != NULL);
  frequency_data_ = static_cast<uint32*>(buffer);
}

void BasicBlockEntry::ThreadState::set_trace_data(
    TraceIndexedFrequencyData* trace_data) {
  DCHECK(trace_data != NULL);
  trace_data_ = trace_data;
}

void BasicBlockEntry::ThreadState::AllocatePredictorData(size_t size) {
  DCHECK(predictor_data_ == NULL);
  predictor_data_ = new uint8[size];
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

inline void BasicBlockEntry::ThreadState::Increment(uint32 index) {
  DCHECK(frequency_data_ != NULL);
  DCHECK(trace_data_ == NULL || index < trace_data_->num_entries);
  uint32& element = frequency_data_[index];
  element = IncrementAndSaturate(element);
}

inline void BasicBlockEntry::ThreadState::Enter(uint32 basic_block_id) {
  DCHECK(frequency_data_ != NULL);
  DCHECK(trace_data_ == NULL || basic_block_id < trace_data_->num_entries);

  const uint32 kInvalidBasicBlockId = ~0U;

  BranchFrequency* frequencies =
      reinterpret_cast<BranchFrequency*>(frequency_data_);

  uint32 last_basic_block_id = last_basic_block_id_;

  bool taken = false;
  // Check if entering from a jump or something else (call).
  if (last_basic_block_id_ != kInvalidBasicBlockId)
    taken = (basic_block_id != last_basic_block_id_ + 1);
  last_basic_block_id_ = kInvalidBasicBlockId;

  BranchFrequency& current = frequencies[basic_block_id];
  BranchFrequency& previous = frequencies[last_basic_block_id];

  // Count the execution of this basic block.
  if (current.frequency != kInvalidBasicBlockId)
    current.frequency = IncrementAndSaturate(current.frequency);

  // If last jump was taken, count the branch taken in the previous basic block.
  if (taken) {
    if (previous.branch_taken != kInvalidBasicBlockId)
      previous.branch_taken = IncrementAndSaturate(previous.branch_taken);
  }

  // Simulate the branch predictor.
  // see: http://en.wikipedia.org/wiki/Branch_predictor
  // states:
  //    0: Weakly not taken
  //    1: Weakly not taken
  //    2: Weakly taken
  //    3: Weakly taken
  // When session is disabled, predictor_data_ is not allocated and is NULL.
  if (predictor_data_ != NULL && last_basic_block_id != kInvalidBasicBlockId) {
    uint8& state = predictor_data_[last_basic_block_id];
    if (taken) {
      if (state < 2)
        previous.miss_predicted = IncrementAndSaturate(previous.miss_predicted);
      if (state < 3)
        ++state;
    } else {
      if (state > 1)
        previous.miss_predicted = IncrementAndSaturate(previous.miss_predicted);
      if (state != 0)
        --state;
    }
  }
}

inline void BasicBlockEntry::ThreadState::Leave(uint32 basic_block_id) {
  DCHECK(frequency_data_ != NULL);
  DCHECK(trace_data_ == NULL || basic_block_id < trace_data_->num_entries);
  last_basic_block_id_ = basic_block_id;
}

BasicBlockEntry* BasicBlockEntry::Instance() {
  return static_bbentry_instance.Pointer();
}

BasicBlockEntry::BasicBlockEntry() {
  // Create a session. We immediately return the buffer that gets allocated
  // to us. The client will perform thread-local buffer management on an as-
  // needed basis.
  trace::client::TraceFileSegment dummy_segment;
  if (trace::client::InitializeRpcSession(&session_, &dummy_segment))
    CHECK(session_.ReturnBuffer(&dummy_segment));
}

BasicBlockEntry::~BasicBlockEntry() {
}

uint32* BasicBlockEntry::GetRawFrequencyData(IndexedFrequencyData* data) {
  DCHECK(data != NULL);
  ThreadState* state = ThreadState::Get(data->tls_index);
  if (state == NULL)
    state = Instance()->CreateThreadState(data);
  return state->frequency_data();
}

void BasicBlockEntry::IncrementIndexedFreqDataHook(
    IncrementIndexedFreqDataFrame* entry_frame) {
  ScopedLastErrorKeeper scoped_last_error_keeper;
  DCHECK(entry_frame != NULL);
  DCHECK(entry_frame->module_data != NULL);
  DCHECK_GT(entry_frame->module_data->num_entries,
            entry_frame->index);

  // TODO(rogerm): Consider extracting a fast path for state != NULL? Inline it
  //     during instrumentation? Move it into the _increment_indexed_freq_data
  //     function?
  ThreadState* state = ThreadState::Get(entry_frame->module_data->tls_index);
  if (state == NULL)
    state = Instance()->CreateThreadState(entry_frame->module_data);
  state->Increment(entry_frame->index);
}

void BasicBlockEntry::BranchEnterHook(
    IncrementIndexedFreqDataFrame* entry_frame) {
  ScopedLastErrorKeeper scoped_last_error_keeper;
  DCHECK(entry_frame != NULL);
  DCHECK(entry_frame->module_data != NULL);
  DCHECK_GT(entry_frame->module_data->num_entries,
            entry_frame->index);
  ThreadState* state = ThreadState::Get(entry_frame->module_data->tls_index);
  if (state == NULL)
    state = Instance()->CreateThreadState(entry_frame->module_data);
  state->Enter(entry_frame->index);
}

void BasicBlockEntry::BranchExitHook(
    IncrementIndexedFreqDataFrame* entry_frame) {
  ScopedLastErrorKeeper scoped_last_error_keeper;
  DCHECK(entry_frame != NULL);
  DCHECK(entry_frame->module_data != NULL);
  DCHECK_GT(entry_frame->module_data->num_entries,
            entry_frame->index);
  ThreadState* state = ThreadState::Get(entry_frame->module_data->tls_index);
  if (state == NULL)
    state = Instance()->CreateThreadState(entry_frame->module_data);
  state->Leave(entry_frame->index);
}

void BasicBlockEntry::DllMainEntryHook(DllMainEntryFrame* entry_frame) {
  ScopedLastErrorKeeper scoped_last_error_keeper;
  DCHECK(entry_frame != NULL);
  switch (entry_frame->reason) {
    case DLL_PROCESS_ATTACH:
      Instance()->OnProcessAttach(entry_frame->module_data);
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
      Instance()->OnThreadDetach(entry_frame->module_data);
      break;

    default:
      NOTREACHED();
  }
}

void BasicBlockEntry::ExeMainEntryHook(ExeMainEntryFrame* entry_frame) {
  ScopedLastErrorKeeper scoped_last_error_keeper;
  DCHECK(entry_frame != NULL);
  Instance()->OnProcessAttach(entry_frame->module_data);
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

void BasicBlockEntry::OnProcessAttach(IndexedFrequencyData* module_data) {
  DCHECK(module_data != NULL);

  // Exit if the magic number does not match.
  CHECK_EQ(::common::kBasicBlockEntryAgentId, module_data->agent_id);

  // Exit if the version does not match.
  CHECK(DatatypeVersionIsValid(module_data->data_type, module_data->version));

  // We allow for this hook to be called multiple times. We expect the first
  // time to occur under the loader lock, so we don't need to worry about
  // concurrency for this check.
  if (module_data->initialization_attempted)
    return;

  // Flag the module as initialized.
  module_data->initialization_attempted = 1U;

  // We expect this to be executed exactly once for each module.
  CHECK_EQ(TLS_OUT_OF_INDEXES, module_data->tls_index);
  module_data->tls_index = ::TlsAlloc();
  CHECK_NE(TLS_OUT_OF_INDEXES, module_data->tls_index);

  // Register this module with the call_trace if the session is not disabled.
  // Note that we expect module_data to be statically defined within the
  // module of interest, so we can use its address to lookup the module.
  if (!session_.IsDisabled())
    RegisterModule(module_data);
}

void BasicBlockEntry::OnThreadDetach(IndexedFrequencyData* module_data) {
  DCHECK(module_data != NULL);
  DCHECK_EQ(1U, module_data->initialization_attempted);
  DCHECK_NE(TLS_OUT_OF_INDEXES, module_data->tls_index);

  ThreadState* state = ThreadState::Get(module_data->tls_index);
  if (state != NULL)
    thread_state_manager_.MarkForDeath(state);
}

BasicBlockEntry::ThreadState* BasicBlockEntry::CreateThreadState(
    IndexedFrequencyData* module_data) {
  DCHECK(module_data != NULL);
  CHECK_NE(IndexedFrequencyData::INVALID_DATA_TYPE, module_data->data_type);

  // Create the thread-local state for this thread. By default, just point the
  // counter array to the statically allocated fall-back area.
  ThreadState* state = new ThreadState(this, module_data->frequency_data);
  CHECK(state != NULL);

  // Associate the thread_state with the current thread.
  state->Assign(module_data->tls_index);

  // Register the thread state with the thread state manager.
  thread_state_manager_.Register(state);

  // If we're not actually tracing, then we're done.
  if (session_.IsDisabled())
    return state;

  // Nothing to allocate? We're done!
  if (module_data->num_entries == 0) {
    LOG(WARNING) << "Module contains no instrumented basic blocks, not "
                 << "allocating basic-block trace data segment.";
    return state;
  }

  // Determine the size of the basic block frequency table.
  DCHECK_LT(0U, module_data->frequency_size);
  DCHECK_LT(0U, module_data->num_columns);
  size_t data_size = module_data->num_entries * module_data->frequency_size *
      module_data->num_columns;

  // Determine the size of the basic block frequency record.
  size_t record_size = sizeof(TraceIndexedFrequencyData) + data_size - 1;

  // Determine the size of the buffer we need. We need room for the basic block
  // frequency struct plus a single RecordPrefix header.
  size_t segment_size = sizeof(RecordPrefix) + record_size;

  // Allocate the actual segment for the basic block entry data.
  CHECK(session_.AllocateBuffer(segment_size, state->segment()));

  // Ensure it's big enough to allocate the basic-block frequency data
  // we want. This automatically accounts for the RecordPrefix overhead.
  CHECK(state->segment()->CanAllocate(record_size));

  // Allocate the basic-block frequency data. We will leave this allocated and
  // let it get flushed during tear-down of the call-trace client.
  TraceIndexedFrequencyData* trace_data =
      reinterpret_cast<TraceIndexedFrequencyData*>(
          state->segment()->AllocateTraceRecordImpl(TRACE_INDEXED_FREQUENCY,
                                                    record_size));
  DCHECK(trace_data != NULL);

  // Initialize the basic block frequency data struct.
  HMODULE module = GetModuleForAddr(module_data);
  CHECK(module != NULL);
  const base::win::PEImage image(module);
  const IMAGE_NT_HEADERS* nt_headers = image.GetNTHeaders();
  trace_data->data_type = module_data->data_type;
  trace_data->module_base_addr = reinterpret_cast<ModuleAddr>(image.module());
  trace_data->module_base_size = nt_headers->OptionalHeader.SizeOfImage;
  trace_data->module_checksum = nt_headers->OptionalHeader.CheckSum;
  trace_data->module_time_date_stamp = nt_headers->FileHeader.TimeDateStamp;
  trace_data->frequency_size = module_data->frequency_size;
  trace_data->num_entries = module_data->num_entries;
  trace_data->num_columns = module_data->num_columns;

  // Hook up the newly allocated buffer to the call-trace instrumentation.
  state->set_frequency_data(trace_data->frequency_data);

  // The branch agent uses a temporary buffer to simulate the branch predictor.
  if (module_data->data_type == ::common::IndexedFrequencyData::BRANCH)
    state->AllocatePredictorData(module_data->num_entries);

  return state;
}

}  // namespace basic_block_entry
}  // namespace agent
