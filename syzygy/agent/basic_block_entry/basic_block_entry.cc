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
//
// The operation of this module is in two parts: instrumentation and agent.
// Both parts work together to gather metrics on the execution of a module.
//
// * Instrumentation
//    The instrumenter is responsible for injecting probes within the
//    instrumented module to call entry-points in the agent. There are two
//    kinds of supported instrumentation: basic block entry count and branch
//    profiling.
//
//    Instrumentation for basic block entry count:
//      BB1: [code]       --->   BB1: push bb_id
//           call func                push module_data
//           jz BB2                   call [increment_hook]
//                                    [code]
//                                    call func
//                                    jz BB2
//
//    Instrumentation for branch profiling:
//      BB1: [code]       --->   BB1: push bb_id
//           call func                push module_data
//           jz BB2                   call [entry_hook]
//                                    [code]
//                                    call func
//                                    push bb_id
//                                    push module_data
//                                    call [leave_hook]
//                                    jz BB2
//
//    Using the last block id produced by an entry_hook to determine the
//    previous executed basic block won't work. As an example, the call to
//    'func' will move the control flow to another function and modify the last
//    executed basic block. The leave hook must be called at the end the basic
//    block, before following control flow to any other basic blocks.
//
//    The calling convention is callee clean-up. The callee is responsible for
//    cleaning up any values on the stack. This calling convention is chosen
//    to keep the application code size as low as possible.
//
// * Agent
//    The agent is responsible for allocating a trace segment and collecting
//    metrics. The trace segment with be dump to a file for post-processing.
//
//    There are two mechanisms to collect metrics:
//    - Basic mode: In the basic mode, the hook acquires a lock and updates a
//      process-wide segment shared by all threads. In this mode, no events can
//      be lost.
//    - Buffered mode: A per-thread buffer is used to collect execution
//      information. A batch commit is done when the buffer is full. In this
//      mode, under a non-standard execution (crash, force exit, ...) pending
//      events may be lost.
//
//    The agent keeps a ThreadState for each running thread. The thread state
//    is accessible through a TLS mechanism and contains information needed by
//    the hook (pointer to trace segment, buffer, lock, ...).
//
//    There are two mechanisms to keep a reference to the thread state:
//    - TLS: The default mechanism uses the standard windows TLS API to keep
//      a per-thread reference to the thread state. The TLS index is allocated
//      and kept inside the module data information in the instrumented image.
//    - FS-Slot: This mechanism uses application specific slot available through
//      the FS segment (fs:[0x700] Reserved for user application).
//      See: http://en.wikipedia.org/wiki/Win32_Thread_Information_Block.
//      There is no API to check whether another module is using this slot, thus
//      this mechanism must be used in a controlled environment.

#include "syzygy/agent/basic_block_entry/basic_block_entry.h"

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/environment.h"
#include "base/lazy_instance.h"
#include "base/stringprintf.h"
#include "base/utf_string_conversions.h"
#include "base/memory/scoped_ptr.h"
#include "syzygy/agent/common/process_utils.h"
#include "syzygy/agent/common/scoped_last_error_keeper.h"
#include "syzygy/common/com_utils.h"
#include "syzygy/common/indexed_frequency_data.h"
#include "syzygy/common/logging.h"
#include "syzygy/trace/protocol/call_trace_defs.h"

unsigned long __readfsdword(unsigned long);
void __writefsdword(unsigned long, unsigned long);
#pragma intrinsic(__readfsdword, __writefsdword)

// Save caller-save registers (eax, ecx, edx) and flags (eflags).
#define BBPROBE_SAVE_REGISTERS  \
  __asm push eax  \
  __asm lahf  \
  __asm seto al  \
  __asm push eax  \
  __asm push ecx  \
  __asm push edx

// Restore caller-save registers (eax, ecx, edx) and flags (eflags).
#define BBPROBE_RESTORE_REGISTERS  \
  __asm pop edx  \
  __asm pop ecx  \
  __asm pop eax  \
  __asm add al, 0x7f  \
  __asm sahf  \
  __asm pop eax

#define BBPROBE_REDIRECT_CALL(function_name, handler, stack_size)  \
  extern "C" void __declspec(naked) function_name() {  \
    /* Stash volatile registers. */  \
    BBPROBE_SAVE_REGISTERS  \
    \
    /* Stack: ... basic_block_id, module_data, ret_addr, [4x register] */  \
    \
    /* Push the original esp value onto the stack as the entry-hook data. */  \
    /* This gives the entry-hook a pointer to ret_addr, module_data and */  \
    /* basic block id. */  \
    __asm lea eax, DWORD PTR[esp + 0x10]  \
    __asm push eax  \
    \
    /* Stack: ..., basic_block_id, module_data, ret_addr, [4x register], */  \
    /*    esp, &ret_addr. */  \
    __asm call agent::basic_block_entry::BasicBlockEntry::handler  \
    /* Stack: ... basic_block_id, module_data, ret_addr, [4x register]. */  \
    \
    /* Restore volatile registers. */  \
    BBPROBE_RESTORE_REGISTERS  \
    __asm ret stack_size  \
  }

#define BBPROBE_REDIRECT_CALL_SLOT(function_name, handler, type, slot)  \
  static void __fastcall safe ## function_name ## _s ## slot(type index) {  \
    agent::basic_block_entry::BasicBlockEntry::handler<slot>(index);  \
  }  \
  extern "C" void __declspec(naked) function_name ## _s ## slot() {  \
    /* Stash volatile registers. */  \
    BBPROBE_SAVE_REGISTERS  \
    /* Call handler */  \
    __asm mov ecx, DWORD PTR[esp + 0x14]  \
    __asm call safe ## function_name ## _s ## slot  \
    /* Restore volatile registers. */  \
    BBPROBE_RESTORE_REGISTERS  \
    /* Return and remove index from stack. */  \
    __asm ret 4  \
  }

// This is expected to be called via instrumentation that looks like:
//    push basic_block_id
//    push module_data
//    call [function_name]
BBPROBE_REDIRECT_CALL(_branch_enter, BranchEnterHook, 8)
BBPROBE_REDIRECT_CALL(_branch_enter_buffered, BranchEnterBufferedHook, 8)
BBPROBE_REDIRECT_CALL(_branch_exit, BranchExitHook, 8)
BBPROBE_REDIRECT_CALL(_increment_indexed_freq_data,
                      IncrementIndexedFreqDataHook,
                      8)

// This is expected to be called via instrumentation that looks like:
//    push module_data
//    call [function_name]
BBPROBE_REDIRECT_CALL_SLOT(_function_enter,
                           FunctionEnterHookSlot,
                           ::common::IndexedFrequencyData*,
                           1)
BBPROBE_REDIRECT_CALL_SLOT(_function_enter,
                           FunctionEnterHookSlot,
                           ::common::IndexedFrequencyData*,
                           2)
BBPROBE_REDIRECT_CALL_SLOT(_function_enter,
                           FunctionEnterHookSlot,
                           ::common::IndexedFrequencyData*,
                           3)
BBPROBE_REDIRECT_CALL_SLOT(_function_enter,
                           FunctionEnterHookSlot,
                           ::common::IndexedFrequencyData*,
                           4)

// This is expected to be called via instrumentation that looks like:
//    push basic_block_id
//    call [function_name]
BBPROBE_REDIRECT_CALL_SLOT(_branch_enter, BranchEnterHookSlot, DWORD, 1)
BBPROBE_REDIRECT_CALL_SLOT(_branch_enter, BranchEnterHookSlot, DWORD, 2)
BBPROBE_REDIRECT_CALL_SLOT(_branch_enter, BranchEnterHookSlot, DWORD, 3)
BBPROBE_REDIRECT_CALL_SLOT(_branch_enter, BranchEnterHookSlot, DWORD, 4)

BBPROBE_REDIRECT_CALL_SLOT(_branch_enter_buffered,
                           BranchEnterBufferedHookSlot, DWORD, 1)
BBPROBE_REDIRECT_CALL_SLOT(_branch_enter_buffered,
                           BranchEnterBufferedHookSlot, DWORD, 2)
BBPROBE_REDIRECT_CALL_SLOT(_branch_enter_buffered,
                           BranchEnterBufferedHookSlot, DWORD, 3)
BBPROBE_REDIRECT_CALL_SLOT(_branch_enter_buffered,
                           BranchEnterBufferedHookSlot, DWORD, 4)

BBPROBE_REDIRECT_CALL_SLOT(_branch_exit, BranchExitHookSlot, DWORD, 1)
BBPROBE_REDIRECT_CALL_SLOT(_branch_exit, BranchExitHookSlot, DWORD, 2)
BBPROBE_REDIRECT_CALL_SLOT(_branch_exit, BranchExitHookSlot, DWORD, 3)
BBPROBE_REDIRECT_CALL_SLOT(_branch_exit, BranchExitHookSlot, DWORD, 4)

// This is expected to be called via a thunk that looks like:
//    push module_data
//    push function
//    jmp [function_name]
BBPROBE_REDIRECT_CALL(_indirect_penter_dllmain, DllMainEntryHook, 4)
BBPROBE_REDIRECT_CALL(_indirect_penter_exemain, ExeMainEntryHook, 4)

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
      CommandLine::Reset();
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

const uint32 kUserApplicationSlot = 0x700;
const uint32 kNumSlots = 4U;
const uint32 kInvalidBasicBlockId = ~0U;

// The indexed_frequency_data for the bbentry instrumentation mode has 1 column.
struct BBEntryFrequency {
  uint32 frequency;
};

// The indexed_frequency_data for the branch instrumentation mode has 3 columns.
struct BranchFrequency {
  uint32 frequency;
  uint32 branch_taken;
  uint32 mispredicted;
};

// An entry in the basic block id buffer.
struct BranchBufferEntry {
  uint32 basic_block_id;
  uint32 last_basic_block_id;
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
// instrumented module, and be part of the single allocation in which the
// image of the module lies. The base of the module will be the base address
// of the allocation.
// TODO(rogerm): Move to agent::common.
HMODULE GetModuleForAddr(const void* addr) {
  MEMORY_BASIC_INFORMATION mem_info = {};

  // Lookup up the allocation in which addr is located.
  if (::VirtualQuery(addr, &mem_info, sizeof(mem_info)) == 0) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "VirtualQuery failed: " << ::common::LogWe(error) << ".";
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
bool DatatypeVersionIsValid(uint32 data_type,
                            uint32 agent_id,
                            uint32 version,
                            uint32 frequency_size,
                            uint32 num_columns) {
  // We can only handle this if it looks right.
  const size_t kIntSize = sizeof(int);
  if (data_type == IndexedFrequencyData::BRANCH) {
    if (agent_id != ::common::kBasicBlockEntryAgentId ||
        version != ::common::kBranchFrequencyDataVersion ||
        frequency_size != kIntSize ||
        num_columns != 3U) {
      LOG(ERROR) << "Unexpected values in the branch data structures.";
      return false;
    }
  } else if (data_type == IndexedFrequencyData::BASIC_BLOCK_ENTRY) {
    if (agent_id != ::common::kBasicBlockEntryAgentId ||
        version != ::common::kBasicBlockFrequencyDataVersion ||
        frequency_size != kIntSize ||
        num_columns != 1U) {
      LOG(ERROR) << "Unexpected values in the basic block data structures.";
      return false;
    }
  } else {
    LOG(ERROR) << "Unexpected entry kind.";
    return false;
  }

  return true;
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
  // @param module_data Module information injected in the instrumented
  //     application.
  // @param lock Lock associated with the @p frequency_data.
  // @param frequency_data Buffer to commit counters update.
  ThreadState(IndexedFrequencyData* module_data,
              base::Lock* lock,
              void* frequency_data);

  // Destroy a ThreadState instance.
  ~ThreadState();

  // Allocate space to buffer basic block ids.
  void AllocateBasicBlockIdBuffer();

  // Allocate temporary space to simulate a branch predictor.
  void AllocatePredictorCache();

  // Saturation increment the frequency record for @p index. Note that in
  // Release mode, no range checking is performed on index.
  // @param basic_block_id the basic block index.
  void Increment(uint32 basic_block_id);

  // Update state and frequency when a jump enters the basic block @p index
  // coming from the basic block @last.
  // @param basic_block_id the basic block index.
  // @param last_basic_block_id the originating basic block index from which we
  //     enter @p basic_block_id.
  void Enter(uint32 basic_block_id, uint32 last_basic_block_id);

  // Update state and frequency when a jump leaves the basic block @p index.
  // @param basic_block_id the basic block index.
  void Leave(uint32 basic_block_id);

  // Push a basic block id in the basic block ids buffer, to be processed later.
  // @param basic_block_id the basic block index.
  // @returns true when the buffer is full and there is no room for an other
  //     entry, false otherwise.
  bool Push(uint32 basic_block_id);

  // Flush pending values in the basic block ids buffer.
  void Flush();

  // Return the id of the most recent basic block executed.
  uint32 last_basic_block_id() { return last_basic_block_id_; }

  // Reset the most recent basic block executed.
  void reset_last_basic_block_id();

  // Return the lock associated with 'trace_data_' for atomic update.
  base::Lock* trace_lock() { return trace_lock_; }

  // For a given basic block id, returns the corresponding BBEntryFrequency.
  // @param basic_block_id the basic block index.
  // @returns the bbentry frequency entry for a given basic block id.
  BBEntryFrequency& GetBBEntryFrequency(uint32 basic_block_id);

  // For a given basic block id, returns the corresponding BranchFrequency.
  // @param basic_block_id the basic block index.
  // @returns the branch frequency entry for a given basic block id.
  BranchFrequency& GetBranchFrequency(uint32 basic_block_id);

  // Retrieve the indexed_frequency_data specific fields for this agent.
  // @returns a pointer to the specific fields.
  const BasicBlockIndexedFrequencyData* GetBasicBlockData() const {
    return
        reinterpret_cast<const BasicBlockIndexedFrequencyData*>(module_data_);
  }

 protected:
  // As a shortcut, this points to the beginning of the array of basic-block
  // entry frequency values. With tracing enabled, this is equivalent to:
  //     reinterpret_cast<uint32*>(this->trace_data->frequency_data)
  // If tracing is not enabled, this will be set to point to a static
  // allocation of IndexedFrequencyData::frequency_data.
  uint32* frequency_data_;  // Under trace_lock_.

  // Module information this thread state is gathering information on.
  const IndexedFrequencyData* module_data_;

  // Lock corresponding to 'frequency_data_'.
  base::Lock* trace_lock_;

  // Buffer used to queue basic block ids for later processing in batches.
  std::vector<BranchBufferEntry> basic_block_id_buffer_;

  // Current offset of the next available entry in the basic block id buffer.
  uint32 basic_block_id_buffer_offset_;

  // The branch predictor state (2-bit saturating counter).
  std::vector<uint8> predictor_data_;

  // The last basic block id executed.
  uint32 last_basic_block_id_;

 private:
  DISALLOW_COPY_AND_ASSIGN(ThreadState);
};

BasicBlockEntry::ThreadState::ThreadState(IndexedFrequencyData* module_data,
                                          base::Lock* lock,
                                          void* frequency_data)
    : frequency_data_(static_cast<uint32*>(frequency_data)),
      module_data_(module_data),
      trace_lock_(lock),
      basic_block_id_buffer_offset_(0),
      last_basic_block_id_(kInvalidBasicBlockId) {
}

BasicBlockEntry::ThreadState::~ThreadState() {
  if (!basic_block_id_buffer_.empty())
    Flush();

  uint32 slot = GetBasicBlockData()->fs_slot;
  if (slot != 0) {
    uint32 address = kUserApplicationSlot + 4 * (slot - 1);
    __writefsdword(address, 0);
  }
}

void BasicBlockEntry::ThreadState::AllocateBasicBlockIdBuffer() {
  DCHECK(basic_block_id_buffer_.empty());
  basic_block_id_buffer_.resize(kBufferSize * sizeof(BranchBufferEntry));
}

void BasicBlockEntry::ThreadState::AllocatePredictorCache() {
  DCHECK(predictor_data_.empty());
  predictor_data_.resize(kPredictorCacheSize);
}

void BasicBlockEntry::ThreadState::reset_last_basic_block_id() {
  last_basic_block_id_ = kInvalidBasicBlockId;
}

BBEntryFrequency& BasicBlockEntry::ThreadState::GetBBEntryFrequency(
    uint32 basic_block_id) {
  DCHECK(frequency_data_ != NULL);
  BBEntryFrequency* frequencies =
      reinterpret_cast<BBEntryFrequency*>(frequency_data_);
  BBEntryFrequency& entry = frequencies[basic_block_id];
  return entry;
}

BranchFrequency& BasicBlockEntry::ThreadState::GetBranchFrequency(
    uint32 basic_block_id) {
  DCHECK(frequency_data_ != NULL);
  BranchFrequency* frequencies =
      reinterpret_cast<BranchFrequency*>(frequency_data_);
  BranchFrequency& entry = frequencies[basic_block_id];
  return entry;
}

inline void BasicBlockEntry::ThreadState::Increment(uint32 basic_block_id) {
  DCHECK(frequency_data_ != NULL);
  DCHECK(module_data_ != NULL);
  DCHECK_LT(basic_block_id, module_data_->num_entries);

  // Retrieve information for the basic block.
  BBEntryFrequency& entry = GetBBEntryFrequency(basic_block_id);
  entry.frequency = IncrementAndSaturate(entry.frequency);
}

void BasicBlockEntry::ThreadState::Enter(
    uint32 basic_block_id, uint32 last_basic_block_id) {
  DCHECK(frequency_data_ != NULL);
  DCHECK(module_data_ != NULL);
  DCHECK_LT(basic_block_id, module_data_->num_entries);

  // Retrieve information for the current basic block.
  BranchFrequency& current = GetBranchFrequency(basic_block_id);

  // Count the execution of this basic block.
  if (current.frequency != kInvalidBasicBlockId)
    current.frequency = IncrementAndSaturate(current.frequency);

  // Check if entering from a jump or something else (call).
  if (last_basic_block_id == kInvalidBasicBlockId)
    return;

  // Retrieve information for the previous basic block.
  BranchFrequency& previous = GetBranchFrequency(last_basic_block_id);

  // If last jump was taken, count the branch taken in the previous basic block.
  bool taken = (basic_block_id != last_basic_block_id + 1);
  if (taken) {
    if (previous.branch_taken != kInvalidBasicBlockId)
      previous.branch_taken = IncrementAndSaturate(previous.branch_taken);
  }

  // Simulate the branch predictor.
  // see: http://en.wikipedia.org/wiki/Branch_predictor
  // states:
  //    0: Strongly not taken
  //    1: Weakly not taken
  //    2: Weakly taken
  //    3: Strongly taken
  if (predictor_data_.empty())
    return;
  DCHECK(predictor_data_.size() == kPredictorCacheSize);
  if (last_basic_block_id != kInvalidBasicBlockId) {
    size_t offset = last_basic_block_id % kPredictorCacheSize;
    uint8& state = predictor_data_[offset];
    if (taken) {
      if (state < 2)
        previous.mispredicted = IncrementAndSaturate(previous.mispredicted);
      if (state < 3)
        ++state;
    } else {
      if (state > 1)
        previous.mispredicted = IncrementAndSaturate(previous.mispredicted);
      if (state != 0)
        --state;
    }
  }
}

inline void BasicBlockEntry::ThreadState::Leave(uint32 basic_block_id) {
  DCHECK(module_data_ != NULL);
  DCHECK_LT(basic_block_id, module_data_->num_entries);

  last_basic_block_id_ = basic_block_id;
}

bool BasicBlockEntry::ThreadState::Push(uint32 basic_block_id) {
  DCHECK(module_data_ != NULL);
  DCHECK(basic_block_id < module_data_->num_entries);

  uint32 last_offset = basic_block_id_buffer_offset_;
  DCHECK_LT(last_offset, basic_block_id_buffer_.size());

  BranchBufferEntry* entry = &basic_block_id_buffer_[last_offset];
  entry->basic_block_id = basic_block_id;
  entry->last_basic_block_id = last_basic_block_id_;

  ++basic_block_id_buffer_offset_;

  return basic_block_id_buffer_offset_ == kBufferSize;
}

void BasicBlockEntry::ThreadState::Flush() {
  uint32 last_offset = basic_block_id_buffer_offset_;

  for (size_t offset = 0; offset < last_offset; ++offset) {
    BranchBufferEntry* entry = &basic_block_id_buffer_[offset];
    Enter(entry->basic_block_id, entry->last_basic_block_id);
  }

  // Reset buffer.
  basic_block_id_buffer_offset_ = 0;
}

BasicBlockEntry* BasicBlockEntry::Instance() {
  return static_bbentry_instance.Pointer();
}

BasicBlockEntry::BasicBlockEntry() : registered_slots_() {
  // Create a session.
  trace::client::InitializeRpcSession(&session_, &segment_);
}

BasicBlockEntry::~BasicBlockEntry() {
}

bool BasicBlockEntry::InitializeFrequencyData(IndexedFrequencyData* data) {
  DCHECK(data != NULL);

  // Nothing to allocate? We're done!
  if (data->num_entries == 0) {
    LOG(WARNING) << "Module contains no instrumented basic blocks, not "
                 << "allocating data segment.";
    return true;
  }

  // Determine the size of the basic block frequency table.
  DCHECK_LT(0U, data->frequency_size);
  DCHECK_LT(0U, data->num_columns);
  size_t data_size = data->num_entries * data->frequency_size *
      data->num_columns;

  // Determine the size of the basic block frequency record.
  size_t record_size = sizeof(TraceIndexedFrequencyData) + data_size - 1;

  // Determine the size of the buffer we need. We need room for the basic block
  // frequency struct plus a single RecordPrefix header.
  size_t segment_size = sizeof(RecordPrefix) + record_size;

  // Allocate the actual segment for the frequency data.
  if (!session_.AllocateBuffer(segment_size, &segment_)) {
    LOG(ERROR) << "Failed to allocate frequency data segment.";
    return false;
  }

  // Ensure it's big enough to allocate the basic-block frequency data we want.
  // This automatically accounts for the RecordPrefix overhead.
  if (!segment_.CanAllocate(record_size)) {
    LOG(ERROR) << "Returned frequency data segment smaller than expected.";
    return false;
  }

  // Allocate the basic-block frequency data. We will leave this allocated and
  // let it get flushed during tear-down of the call-trace client.
  TraceIndexedFrequencyData* trace_data =
      reinterpret_cast<TraceIndexedFrequencyData*>(
          segment_.AllocateTraceRecordImpl(TRACE_INDEXED_FREQUENCY,
                                           record_size));
  DCHECK(trace_data != NULL);

  // Initialize the basic block frequency data struct.
  HMODULE module = GetModuleForAddr(data);
  CHECK(module != NULL);
  const base::win::PEImage image(module);
  const IMAGE_NT_HEADERS* nt_headers = image.GetNTHeaders();
  trace_data->data_type = data->data_type;
  trace_data->module_base_addr = reinterpret_cast<ModuleAddr>(image.module());
  trace_data->module_base_size = nt_headers->OptionalHeader.SizeOfImage;
  trace_data->module_checksum = nt_headers->OptionalHeader.CheckSum;
  trace_data->module_time_date_stamp = nt_headers->FileHeader.TimeDateStamp;
  trace_data->frequency_size = data->frequency_size;
  trace_data->num_entries = data->num_entries;
  trace_data->num_columns = data->num_columns;

  // Hook up the newly allocated buffer to the call-trace instrumentation.
  data->frequency_data =
      reinterpret_cast<uint32*>(&trace_data->frequency_data[0]);

  return true;
}

BasicBlockEntry::ThreadState* BasicBlockEntry::CreateThreadState(
    IndexedFrequencyData* module_data) {
  DCHECK(module_data != NULL);
  CHECK_NE(IndexedFrequencyData::INVALID_DATA_TYPE, module_data->data_type);

  // Get a pointer to the extended indexed frequency data.
  BasicBlockIndexedFrequencyData* basicblock_data =
      reinterpret_cast<BasicBlockIndexedFrequencyData*>(module_data);

  // Create the thread-local state for this thread. By default, just point the
  // counter array to the statically allocated fall-back area.
  ThreadState* state =
    new ThreadState(module_data, &lock_, module_data->frequency_data);
  CHECK(state != NULL);

  // Register the thread state with the thread state manager.
  thread_state_manager_.Register(state);

  // Store the thread state in the TLS slot.
  DCHECK_NE(TLS_OUT_OF_INDEXES, basicblock_data->tls_index);
  ::TlsSetValue(basicblock_data->tls_index, state);

  // If we're not actually tracing, then we're done.
  if (session_.IsDisabled())
    return state;

  uint32 slot = basicblock_data->fs_slot;
  if (slot != 0) {
    uint32 address = kUserApplicationSlot + 4 * (slot - 1);
    // Sanity check: The slot must be available (not used by an other tool).
    DWORD content = __readfsdword(address);
    CHECK_EQ(content, 0U);
    // Put the current state to the TLS slot.
    __writefsdword(address, reinterpret_cast<unsigned long>(state));
  }

  // Nothing to allocate? We're done!
  if (module_data->num_entries == 0) {
    LOG(WARNING) << "Module contains no instrumented basic blocks.";
    return state;
  }

  // Allocate space used by branch instrumentation.
  if (module_data->data_type == ::common::IndexedFrequencyData::BRANCH)
    state->AllocatePredictorCache();

  // Allocate buffer to which basic block id are pushed before being committed.
  state->AllocateBasicBlockIdBuffer();

  return state;
}

inline BasicBlockEntry::ThreadState* BasicBlockEntry::GetThreadState(
    IndexedFrequencyData* module_data) {
  DCHECK(module_data != NULL);
  ScopedLastErrorKeeper scoped_last_error_keeper;

  // Get a pointer to the extended indexed frequency data.
  BasicBlockIndexedFrequencyData* basicblock_data =
      reinterpret_cast<BasicBlockIndexedFrequencyData*>(module_data);

  DWORD tls_index = basicblock_data->tls_index;
  DCHECK_NE(TLS_OUT_OF_INDEXES, tls_index);
  ThreadState* state = static_cast<ThreadState*>(::TlsGetValue(tls_index));
  return state;
}

template<int S>
inline BasicBlockEntry::ThreadState* BasicBlockEntry::GetThreadStateSlot() {
  uint32 address = kUserApplicationSlot + 4 * (S - 1);
  DWORD content = __readfsdword(address);
  return reinterpret_cast<BasicBlockEntry::ThreadState*>(content);
}

void WINAPI BasicBlockEntry::IncrementIndexedFreqDataHook(
    IncrementIndexedFreqDataFrame* entry_frame) {
  DCHECK(entry_frame != NULL);
  DCHECK(entry_frame->module_data != NULL);
  DCHECK_GT(entry_frame->module_data->num_entries,
            entry_frame->index);

  ThreadState* state = GetThreadState(entry_frame->module_data);
  if (state == NULL) {
    ScopedLastErrorKeeper scoped_last_error_keeper;
    state = Instance()->CreateThreadState(entry_frame->module_data);
  }

  base::AutoLock scoped_lock(*state->trace_lock());
  state->Increment(entry_frame->index);
}

void WINAPI BasicBlockEntry::BranchEnterHook(
    IncrementIndexedFreqDataFrame* entry_frame) {
  DCHECK(entry_frame != NULL);
  DCHECK(entry_frame->module_data != NULL);
  DCHECK_GT(entry_frame->module_data->num_entries,
            entry_frame->index);
  ThreadState* state = GetThreadState(entry_frame->module_data);
  if (state == NULL) {
    ScopedLastErrorKeeper scoped_last_error_keeper;
    state = Instance()->CreateThreadState(entry_frame->module_data);
  }

  base::AutoLock scoped_lock(*state->trace_lock());
  uint32 last_basic_block_id = state->last_basic_block_id();
  state->Enter(entry_frame->index, last_basic_block_id);
  state->reset_last_basic_block_id();
}

void WINAPI BasicBlockEntry::BranchEnterBufferedHook(
    IncrementIndexedFreqDataFrame* entry_frame) {
  DCHECK(entry_frame != NULL);
  DCHECK(entry_frame->module_data != NULL);
  DCHECK_GT(entry_frame->module_data->num_entries,
            entry_frame->index);
  ThreadState* state = GetThreadState(entry_frame->module_data);
  if (state == NULL) {
    ScopedLastErrorKeeper scoped_last_error_keeper;
    state = Instance()->CreateThreadState(entry_frame->module_data);
  }

  if (state->Push(entry_frame->index)) {
    base::AutoLock scoped_lock(*state->trace_lock());
    state->Flush();
  }
  state->reset_last_basic_block_id();
}

template<int S>
void __fastcall BasicBlockEntry::FunctionEnterHookSlot(
    IndexedFrequencyData* module_data) {
  DCHECK(module_data != NULL);

  // Check if ThreadState is already created.
  ThreadState* state = GetThreadStateSlot<S>();
  if (state != NULL)
    return;

  // Get or create the ThreadState.
  state = GetThreadState(module_data);
  if (state == NULL) {
    ScopedLastErrorKeeper scoped_last_error_keeper;
    state = Instance()->CreateThreadState(module_data);
  }
}

template<int S>
void __fastcall BasicBlockEntry::BranchEnterHookSlot(uint32 index) {
  ThreadState* state = GetThreadStateSlot<S>();
  if (state == NULL)
    return;

  base::AutoLock scoped_lock(*state->trace_lock());
  uint32 last_basic_block_id = state->last_basic_block_id();
  state->Enter(index, last_basic_block_id);
  state->reset_last_basic_block_id();
}

template<int S>
void __fastcall BasicBlockEntry::BranchEnterBufferedHookSlot(uint32 index) {
  ThreadState* state = GetThreadStateSlot<S>();
  if (state == NULL)
    return;

  if (state->Push(index)) {
    base::AutoLock scoped_lock(*state->trace_lock());
    state->Flush();
  }
  state->reset_last_basic_block_id();
}

template<int S>
void __fastcall BasicBlockEntry::BranchExitHookSlot(uint32 index) {
  ThreadState* state = GetThreadStateSlot<S>();
  if (state == NULL)
    return;

  state->Leave(index);
}

inline void WINAPI BasicBlockEntry::BranchExitHook(
    IncrementIndexedFreqDataFrame* entry_frame) {
  DCHECK(entry_frame != NULL);
  DCHECK(entry_frame->module_data != NULL);
  DCHECK_GT(entry_frame->module_data->num_entries,
            entry_frame->index);

  ThreadState* state = GetThreadState(entry_frame->module_data);
  if (state == NULL)
    return;

  state->Leave(entry_frame->index);
}

void WINAPI BasicBlockEntry::DllMainEntryHook(DllMainEntryFrame* entry_frame) {
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

void WINAPI BasicBlockEntry::ExeMainEntryHook(ExeMainEntryFrame* entry_frame) {
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

void BasicBlockEntry::RegisterFastPathSlot(
    IndexedFrequencyData* module_data, unsigned int slot) {
  DCHECK_NE(slot, 0U);
  DCHECK_LE(slot, kNumSlots);
  DCHECK(module_data != NULL);

  // The slot must not have been registered.
  CHECK_EQ((1 << slot) & registered_slots_, 0U);
  registered_slots_ |= (1 << slot);
}

void BasicBlockEntry::UnregisterFastPathSlot(
    IndexedFrequencyData* module_data, unsigned int slot) {
  DCHECK_NE(slot, 0U);
  DCHECK_LE(slot, kNumSlots);
  DCHECK(module_data != NULL);

  // The slot must be registered.
  CHECK_NE((1 << slot) & registered_slots_, 0U);
  registered_slots_ &= ~(1 << slot);
}

void BasicBlockEntry::OnProcessAttach(IndexedFrequencyData* module_data) {
  DCHECK(module_data != NULL);

  // Get a pointer to the extended indexed frequency data.
  BasicBlockIndexedFrequencyData* basicblock_data =
      reinterpret_cast<BasicBlockIndexedFrequencyData*>(module_data);

  // Exit if the magic number does not match.
  CHECK_EQ(::common::kBasicBlockEntryAgentId, module_data->agent_id);

  // Exit if the version does not match.
  CHECK(DatatypeVersionIsValid(module_data->data_type,
                               module_data->agent_id,
                               module_data->version,
                               module_data->frequency_size,
                               module_data->num_columns));

  // We allow for this hook to be called multiple times. We expect the first
  // time to occur under the loader lock, so we don't need to worry about
  // concurrency for this check.
  if (module_data->initialization_attempted)
    return;

  // Flag the module as initialized.
  module_data->initialization_attempted = 1U;

  // We expect this to be executed exactly once for each module.
  CHECK_EQ(TLS_OUT_OF_INDEXES, basicblock_data->tls_index);
  basicblock_data->tls_index = ::TlsAlloc();
  CHECK_NE(TLS_OUT_OF_INDEXES, basicblock_data->tls_index);

  // If there is a FS slot configured, register it.
  if (basicblock_data->fs_slot != 0)
    RegisterFastPathSlot(module_data, basicblock_data->fs_slot);

  // Register this module with the call_trace if the session is not disabled.
  // Note that we expect module_data to be statically defined within the
  // module of interest, so we can use its address to lookup the module.
  if (session_.IsDisabled()) {
    LOG(WARNING) << "Unable to initialize client as we are not tracing.";
    return;
  }

  if (!InitializeFrequencyData(module_data)) {
    LOG(ERROR) << "Failed to initialize frequency data.";
    return;
  }

  RegisterModule(module_data);

  LOG(INFO) << "BBEntry client initialized.";
}

void BasicBlockEntry::OnThreadDetach(IndexedFrequencyData* module_data) {
  DCHECK(module_data != NULL);
  DCHECK_EQ(1U, module_data->initialization_attempted);

  // Get a pointer to the extended indexed frequency data.
  BasicBlockIndexedFrequencyData* basicblock_data =
      reinterpret_cast<BasicBlockIndexedFrequencyData*>(module_data);

  DCHECK_NE(TLS_OUT_OF_INDEXES, basicblock_data->tls_index);

  ThreadState* state = GetThreadState(module_data);
  if (state == NULL)
    return;

  state->Flush();
  thread_state_manager_.MarkForDeath(state);
}

}  // namespace basic_block_entry
}  // namespace agent
