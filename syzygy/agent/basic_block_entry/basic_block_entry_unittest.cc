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
// BasicBlockEntry trace agent unit-tests.

#include "syzygy/agent/basic_block_entry/basic_block_entry.h"

#include "base/bind.h"
#include "base/callback.h"
#include "base/file_util.h"
#include "base/files/file_enumerator.h"
#include "base/files/scoped_temp_dir.h"
#include "base/strings/stringprintf.h"
#include "base/threading/thread.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/common/indexed_frequency_data.h"
#include "syzygy/trace/common/unittest_util.h"
#include "syzygy/trace/parse/unittest_util.h"

// There's a quick and dirty way to get the HMODULE of this module for MS
// linkers. HINSTANCE == HMODULE == &__ImageBase;
// See http://blogs.msdn.com/b/oldnewthing/archive/2004/10/25/247180.aspx
EXTERN_C IMAGE_DOS_HEADER __ImageBase;

namespace agent {
namespace basic_block_entry {

namespace {

using ::common::IndexedFrequencyData;
using testing::_;
using testing::StrictMockParseEventHandler;
using trace::parser::Parser;

// This is the name of the agent DLL.
const wchar_t kBasicBlockEntryClientDll[] = L"basic_block_entry_client.dll";

// The number of columns we'll work with for these tests.
const uint32 kNumColumns = 1;
const uint32 kNumBranchColumns = 3;

// The number of basic blocks we'll work with for these tests.
const uint32 kNumBasicBlocks = 2;

// The number of threads used for parallel tests.
const uint32 kNumThreads = 8;

// Number of iterations done by each thread.
const uint32 kNumThreadIteration = 4 * BasicBlockEntry::kBufferSize;

// The module defining this lib/executable.
const HMODULE kThisModule = reinterpret_cast<HMODULE>(&__ImageBase);

// A helper to match modules by base address.
MATCHER_P(ModuleAtAddress, module, "") {
  return arg->module_base_addr == module;
}

// A helper to match basic-block frequency results to expectations.
MATCHER_P3(FrequencyDataMatches, module, values_count, bb_freqs, "") {
  if (arg->module_base_addr != module)
    return false;

  if (arg->frequency_size != sizeof(uint32))
    return false;

  if (arg->num_entries * arg->num_columns != values_count)
    return false;

  return ::memcmp(bb_freqs, arg->frequency_data, values_count) == 0;
}

// The test fixture for the basic-block entry agent.
class BasicBlockEntryTest : public testing::Test {
 public:
  enum InstrumentationMode {
    kBasicBlockEntryInstrumentation,
    kBranchInstrumentation,
    kBufferedBranchInstrumentation,
    kBranchWithSlotInstrumentation,
    kBufferedBranchWithSlotInstrumentation
  };

  enum MainMode {
    kDllMain,
    kExeMain
  };

  BasicBlockEntryTest()
      : agent_module_(NULL) {
  }

  void ConfigureBasicBlockAgent() {
    common_data_->agent_id = ::common::kBasicBlockEntryAgentId;
    common_data_->data_type = ::common::IndexedFrequencyData::BASIC_BLOCK_ENTRY;
    common_data_->version = ::common::kBasicBlockFrequencyDataVersion;
    module_data_.tls_index = TLS_OUT_OF_INDEXES;
    module_data_.fs_slot = 0;
    common_data_->initialization_attempted = 0U;
    common_data_->num_entries = kNumBasicBlocks;
    common_data_->num_columns = kNumColumns;
    common_data_->frequency_size = sizeof(default_frequency_data_[0]);
    common_data_->frequency_data = default_frequency_data_;
    ::memset(&default_frequency_data_, 0, sizeof(default_frequency_data_));
  }

  void ConfigureBranchAgent() {
    common_data_->agent_id = ::common::kBasicBlockEntryAgentId;
    common_data_->data_type = ::common::IndexedFrequencyData::BRANCH;
    common_data_->version = ::common::kBasicBlockFrequencyDataVersion;
    module_data_.tls_index = TLS_OUT_OF_INDEXES;
    module_data_.fs_slot = 0;
    common_data_->initialization_attempted = 0U;
    common_data_->num_entries = kNumBasicBlocks;
    common_data_->num_columns = kNumBranchColumns;
    common_data_->frequency_size = sizeof(default_branch_data_[0]);
    common_data_->frequency_data = default_branch_data_;
    ::memset(&default_branch_data_, 0, sizeof(default_branch_data_));
  }

  void ConfigureAgent(InstrumentationMode mode) {
    switch (mode) {
      case kBasicBlockEntryInstrumentation:
        ConfigureBasicBlockAgent();
        break;
      case kBranchInstrumentation:
      case kBufferedBranchInstrumentation:
        ConfigureBranchAgent();
        break;
      case kBranchWithSlotInstrumentation:
      case kBufferedBranchWithSlotInstrumentation:
        ConfigureBranchAgent();
        module_data_.fs_slot = 1;
        break;
      default:
        NOTREACHED();
        break;
    }
  }

  void Startup(MainMode mode) {
    switch (mode) {
      case kDllMain:
        // Simulate the process attach event.
        SimulateModuleEvent(DLL_PROCESS_ATTACH);
        break;
      case kExeMain:
        // Simulate the call to main.
        ExeMainThunk();
        break;
      default:
        NOTREACHED();
        break;
    }
  }

  void Shutdown(MainMode mode) {
    switch (mode) {
      case kDllMain:
        // Simulate the process detach event.
        SimulateModuleEvent(DLL_PROCESS_DETACH);
        break;
      case kExeMain:
        break;
      default:
        NOTREACHED();
        break;
    }
  }

  virtual void SetUp() OVERRIDE {
    testing::Test::SetUp();
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    service_.SetEnvironment();
    common_data_ = &module_data_.module_data;
  }

  virtual void TearDown() OVERRIDE {
    UnloadDll();
    service_.Stop();
  }

  void StartService() {
    service_.Start(temp_dir_.path());
  }

  void StopService() {
    service_.Stop();
  }

  void ReplayLogs(size_t files_expected) {
    // Stop the service if it's running.
    ASSERT_NO_FATAL_FAILURE(StopService());

    Parser parser;
    ASSERT_TRUE(parser.Init(&handler_));

    // Queue up the trace file(s) we engendered.
    base::FileEnumerator enumerator(temp_dir_.path(),
                                    false,
                                    base::FileEnumerator::FILES);
    size_t num_files = 0;
    while (true) {
      base::FilePath trace_file = enumerator.Next();
      if (trace_file.empty())
        break;
      ASSERT_TRUE(parser.OpenTraceFile(trace_file));
      ++num_files;
    }

    EXPECT_EQ(files_expected, num_files);

    if (num_files > 0)
      ASSERT_TRUE(parser.Consume());
  }

  void LoadDll() {
    ASSERT_EQ(NULL, agent_module_);
    ASSERT_EQ(NULL, basic_block_enter_stub_);
    ASSERT_EQ(NULL, ::GetModuleHandle(kBasicBlockEntryClientDll));

    agent_module_ = ::LoadLibrary(kBasicBlockEntryClientDll);
    ASSERT_TRUE(agent_module_ != NULL);

    basic_block_enter_stub_ =
        ::GetProcAddress(agent_module_, "_branch_enter");
    ASSERT_TRUE(basic_block_enter_stub_ != NULL);

    basic_block_enter_buffered_stub_ =
        ::GetProcAddress(agent_module_, "_branch_enter_buffered");
    ASSERT_TRUE(basic_block_enter_buffered_stub_ != NULL);

    basic_block_enter_s1_stub_ =
        ::GetProcAddress(agent_module_, "_branch_enter_s1");
    ASSERT_TRUE(basic_block_enter_s1_stub_ != NULL);

    basic_block_enter_buffered_s1_stub_ =
        ::GetProcAddress(agent_module_, "_branch_enter_buffered_s1");
    ASSERT_TRUE(basic_block_enter_buffered_s1_stub_ != NULL);

    basic_block_exit_stub_ =
        ::GetProcAddress(agent_module_, "_branch_exit");
    ASSERT_TRUE(basic_block_exit_stub_ != NULL);

    basic_block_exit_s1_stub_ =
        ::GetProcAddress(agent_module_, "_branch_exit_s1");
    ASSERT_TRUE(basic_block_exit_s1_stub_ != NULL);

    basic_block_function_enter_s1_stub_ =
        ::GetProcAddress(agent_module_, "_function_enter_s1");
    ASSERT_TRUE(basic_block_function_enter_s1_stub_ != NULL);

    basic_block_increment_stub_ =
        ::GetProcAddress(agent_module_, "_increment_indexed_freq_data");
    ASSERT_TRUE(basic_block_increment_stub_ != NULL);

    indirect_penter_dllmain_stub_ =
        ::GetProcAddress(agent_module_, "_indirect_penter_dllmain");
    ASSERT_TRUE(indirect_penter_dllmain_stub_ != NULL);

    indirect_penter_exemain_stub_ =
        ::GetProcAddress(agent_module_, "_indirect_penter_exemain");
    ASSERT_TRUE(indirect_penter_exemain_stub_ != NULL);
  }

  void UnloadDll() {
    if (agent_module_ != NULL) {
      ASSERT_TRUE(::FreeLibrary(agent_module_));
      agent_module_ = NULL;
      basic_block_enter_stub_ = NULL;
      basic_block_enter_buffered_stub_ = NULL;
      basic_block_enter_s1_stub_ = NULL;
      basic_block_enter_buffered_s1_stub_ = NULL;
      basic_block_exit_stub_ = NULL;
      basic_block_exit_s1_stub_ = NULL;
      basic_block_function_enter_s1_stub_ = NULL;
      basic_block_increment_stub_ = NULL;
      indirect_penter_dllmain_stub_ = NULL;
      indirect_penter_exemain_stub_ = NULL;
    }
  }

 protected:
  static BOOL WINAPI DllMain(HMODULE module, DWORD reason, LPVOID reserved);
  static BOOL WINAPI DllMainThunk(
      HMODULE module, DWORD reason, LPVOID reserved);
  static int __cdecl ExeMain();
  static int __cdecl ExeMainThunk();
  static int __cdecl GetFrequencyDataThunk();

  void SimulateModuleEvent(DWORD reason) {
    DllMainThunk(kThisModule, reason, NULL);
  }

  void SimulateBasicBlockEntry(uint32 basic_block_id) {
    __asm {
      push basic_block_id
      push offset module_data_
      call basic_block_increment_stub_
    }
  }

  void SimulateBranchEnter(uint32 basic_block_id) {
    __asm {
      push basic_block_id
      push offset module_data_
      call basic_block_enter_stub_
    }
  }

  void SimulateBranchEnterBuffered(uint32 basic_block_id) {
    __asm {
      push basic_block_id
      push offset module_data_
      call basic_block_enter_buffered_stub_
    }
  }

  void SimulateFunctionEnter() {
    __asm {
      push offset module_data_
      call basic_block_function_enter_s1_stub_
    }
  }

  void SimulateBranchEnterSlot(uint32 basic_block_id) {
    __asm {
      push basic_block_id
      call basic_block_enter_s1_stub_
    }
  }

  void SimulateBranchEnterBufferedSlot(uint32 basic_block_id) {
    __asm {
      push basic_block_id
      call basic_block_enter_buffered_s1_stub_
    }
  }

  void SimulateBranchExit(uint32 basic_block_id) {
    __asm {
      push basic_block_id
      push offset module_data_
      call basic_block_exit_stub_
    }
  }

  void SimulateBranchExitSlot(uint32 basic_block_id) {
    __asm {
      push basic_block_id
      call basic_block_exit_s1_stub_
    }
  }

  void SimulateThreadFunction(InstrumentationMode mode) {
    switch (mode) {
      case kBranchWithSlotInstrumentation:
      case kBufferedBranchWithSlotInstrumentation:
        SimulateFunctionEnter();
        break;
    }
  }

  void SimulateThreadStep(InstrumentationMode mode, uint32 basic_block_id) {
    switch (mode) {
      case kBasicBlockEntryInstrumentation:
        SimulateBasicBlockEntry(basic_block_id);
        break;
      case kBranchInstrumentation:
        SimulateBranchEnter(basic_block_id);
        SimulateBranchExit(basic_block_id);
        break;
      case kBufferedBranchInstrumentation:
        SimulateBranchEnterBuffered(basic_block_id);
        SimulateBranchExit(basic_block_id);
        break;
      case kBranchWithSlotInstrumentation:
        SimulateBranchEnterSlot(basic_block_id);
        SimulateBranchExit(basic_block_id);
        break;
      case kBufferedBranchWithSlotInstrumentation:
        SimulateBranchEnterBufferedSlot(basic_block_id);
        SimulateBranchExit(basic_block_id);
        break;
      default:
        NOTREACHED();
        break;
    }
  }

  void SimulateThreadExecution(MainMode main_mode, InstrumentationMode mode) {
    // Simulate the thread attach event.
    if (main_mode == kDllMain)
      SimulateModuleEvent(DLL_THREAD_ATTACH);

    // Simulate entering a function.
    SimulateThreadFunction(mode);

    // Simulate the thread loop.
    for (uint32 i = 0; i < kNumThreadIteration; ++i) {
      for (uint32 j = 0; j < kNumBasicBlocks; ++j)
        SimulateThreadStep(mode, j);
    }

    // Simulate the thread detach event.
    if (main_mode == kDllMain)
      SimulateModuleEvent(DLL_THREAD_DETACH);
  }

  void CheckThreadExecution(MainMode main_mode, InstrumentationMode mode) {
    // Configure for instrumented mode.
    ConfigureAgent(mode);

    ASSERT_NO_FATAL_FAILURE(StartService());
    ASSERT_NO_FATAL_FAILURE(LoadDll());

    Startup(main_mode);

    std::vector<base::Thread*> threads;
    for (size_t i = 0; i < kNumThreads; ++i) {
      std::string thread_name = base::StringPrintf("thread-%d", i);
      threads.push_back(new base::Thread(thread_name.c_str()));

      threads[i]->Start();
      threads[i]->message_loop()->PostTask(FROM_HERE,
          base::Bind(&BasicBlockEntryTest::SimulateThreadExecution,
                     base::Unretained(this),
                     main_mode,
                     mode));
    }

    // Stop all running tasks.
    for (size_t i = 0; i < kNumThreads; ++i) {
      threads[i]->Stop();
      delete threads[i];
    }
    threads.clear();

    Shutdown(main_mode);

    // Validate all events have been committed.
    const uint32* frequency_data =
        reinterpret_cast<uint32*>(common_data_->frequency_data);
    uint32 num_columns = common_data_->num_columns;

    const uint32 expected_frequency = kNumThreads * kNumThreadIteration;
    for (size_t i = 0; i < kNumBasicBlocks; ++i) {
      EXPECT_EQ(expected_frequency, frequency_data[i * num_columns]);
    }

    // Unload the DLL and stop the service.
    ASSERT_NO_FATAL_FAILURE(UnloadDll());
    ASSERT_NO_FATAL_FAILURE(StopService());
  }

  void CheckExecution(MainMode main_mode, InstrumentationMode mode) {
    // Configure for instrumented mode.
    ConfigureAgent(mode);

    ASSERT_NO_FATAL_FAILURE(StartService());
    ASSERT_NO_FATAL_FAILURE(LoadDll());

    // Simulate the process attach event.
    Startup(main_mode);

    // Simulate entering a function.
    SimulateThreadFunction(mode);

    // Keep a pointer to raw counters.
    const uint32* frequency_data =
        reinterpret_cast<uint32*>(common_data_->frequency_data);
    uint32 num_columns = common_data_->num_columns;

    // Validate no events have been committed.
    for (size_t i = 0; i < num_columns; ++i) {
      EXPECT_EQ(0U, frequency_data[i]);
    }

    // Simulate a sequential execution.
    for (size_t i = 0; i < kNumThreads; ++i) {
      for (uint32 j = 0; j < kNumThreadIteration; ++j) {
        for (uint32 k = 0; k < kNumBasicBlocks; ++k)
          SimulateThreadStep(mode, k);
      }
    }

    // Simulate the process detach event.
    Shutdown(main_mode);

    // Validate all events have been committed.
    const uint32 expected_frequency = kNumThreads * kNumThreadIteration;
    for (size_t i = 0; i < kNumBasicBlocks; ++i) {
      EXPECT_EQ(expected_frequency, frequency_data[i * num_columns]);
    }

    // Unload the DLL and stop the service.
    ASSERT_NO_FATAL_FAILURE(UnloadDll());
    ASSERT_NO_FATAL_FAILURE(StopService());
  }

  // The directory where trace file output will be written.
  base::ScopedTempDir temp_dir_;

  // The handler to which the trace file parser will delegate events.
  StrictMockParseEventHandler handler_;

  // Our call trace service process instance.
  testing::CallTraceService service_;

  // The basic-block entry client module.
  HMODULE agent_module_;

  // This will be a stand-in for the (usually statically allocated) trace
  // data which would have been referenced by the instrumentation.
  static BasicBlockEntry::BasicBlockIndexedFrequencyData module_data_;
  static BasicBlockEntry::IndexedFrequencyData* common_data_;

  // This will be a stand-in for the (usually statically allocated) fall-back
  // frequency to which module_data_.frequency_data will point.
  static uint32 default_frequency_data_[kNumBasicBlocks];
  static uint32 default_branch_data_[kNumBranchColumns * kNumBasicBlocks];

  // The basic-block entry entrance hook.
  static FARPROC basic_block_enter_stub_;

  // The basic-block entry entrance hook (with buffering).
  static FARPROC basic_block_enter_buffered_stub_;

  // The basic-block entry entrance hook (FS-slot 1).
  static FARPROC basic_block_enter_s1_stub_;

  // The basic-block entry entrance hook (with buffering and FS-slot 1).
  static FARPROC basic_block_enter_buffered_s1_stub_;

  // The basic-block exit hook.
  static FARPROC basic_block_exit_stub_;

  // The basic-block exit hook (FS-slot 1).
  static FARPROC basic_block_exit_s1_stub_;

  // The function entrance hook (FS-slot 1).
  static FARPROC basic_block_function_enter_s1_stub_;

  // The basic-block increment hook.
  static FARPROC basic_block_increment_stub_;

  // The DllMain entry stub.
  static FARPROC indirect_penter_dllmain_stub_;

  // The ExeMain entry stub.
  static FARPROC indirect_penter_exemain_stub_;
};

BOOL WINAPI BasicBlockEntryTest::DllMain(
    HMODULE module, DWORD reason, LPVOID reserved) {
  return TRUE;
}

BOOL __declspec(naked) WINAPI BasicBlockEntryTest::DllMainThunk(
    HMODULE module, DWORD reason, LPVOID reserved) {
  __asm {
    push offset module_data_
    push DllMain
    jmp indirect_penter_dllmain_stub_
  }
}

int __cdecl BasicBlockEntryTest::ExeMain() {
  return 0;
}

BOOL __declspec(naked) __cdecl BasicBlockEntryTest::ExeMainThunk() {
  __asm {
    push offset module_data_
    push ExeMain
    jmp indirect_penter_exemain_stub_
  }
}

BasicBlockEntry::BasicBlockIndexedFrequencyData
    BasicBlockEntryTest::module_data_ = {};
BasicBlockEntry::IndexedFrequencyData* BasicBlockEntryTest::common_data_ = NULL;
uint32 BasicBlockEntryTest::default_frequency_data_[] = {};
uint32 BasicBlockEntryTest::default_branch_data_[] = {};
FARPROC BasicBlockEntryTest::basic_block_enter_stub_ = NULL;
FARPROC BasicBlockEntryTest::basic_block_enter_buffered_stub_ = NULL;
FARPROC BasicBlockEntryTest::basic_block_enter_s1_stub_ = NULL;
FARPROC BasicBlockEntryTest::basic_block_enter_buffered_s1_stub_ = NULL;
FARPROC BasicBlockEntryTest::basic_block_exit_stub_ = NULL;
FARPROC BasicBlockEntryTest::basic_block_exit_s1_stub_ = NULL;
FARPROC BasicBlockEntryTest::basic_block_function_enter_s1_stub_ = NULL;
FARPROC BasicBlockEntryTest::basic_block_increment_stub_ = NULL;
FARPROC BasicBlockEntryTest::indirect_penter_dllmain_stub_ = NULL;
FARPROC BasicBlockEntryTest::indirect_penter_exemain_stub_ = NULL;

}  // namespace

TEST_F(BasicBlockEntryTest, NoServerNoCrash) {
  // Configure for BasicBlock mode.
  ConfigureBasicBlockAgent();

  // Load the agent dll.
  ASSERT_NO_FATAL_FAILURE(LoadDll());

  // Simulate the process attach event.
  SimulateModuleEvent(DLL_PROCESS_ATTACH);

  // Validate that it only modified the tls_index and initialization_attempted
  // values.
  ASSERT_EQ(::common::kBasicBlockEntryAgentId, common_data_->agent_id);
  ASSERT_EQ(::common::kBasicBlockFrequencyDataVersion, common_data_->version);
  ASSERT_EQ(IndexedFrequencyData::BASIC_BLOCK_ENTRY, common_data_->data_type);
  ASSERT_NE(TLS_OUT_OF_INDEXES, module_data_.tls_index);
  ASSERT_EQ(0U, module_data_.fs_slot);
  ASSERT_NE(0U, common_data_->initialization_attempted);
  ASSERT_EQ(kNumColumns, common_data_->num_columns);
  ASSERT_EQ(kNumBasicBlocks, common_data_->num_entries);
  ASSERT_EQ(default_frequency_data_, common_data_->frequency_data);

  // Visiting an initial basic-block should not fail. It should increment the
  // call count in the default array.
  SimulateBasicBlockEntry(0);
  ASSERT_EQ(1U, default_frequency_data_[0]);
  ASSERT_EQ(0U, default_frequency_data_[1]);

  // Re-visiting the same basic-block should only update the frequency array.
  DWORD new_tls_index = module_data_.tls_index;
  SimulateBasicBlockEntry(0);
  ASSERT_EQ(new_tls_index, module_data_.tls_index);
  ASSERT_EQ(2U, default_frequency_data_[0]);
  ASSERT_EQ(0U, default_frequency_data_[1]);

  // Visiting a different basic-block should only update the frequency array.
  SimulateBasicBlockEntry(1);
  ASSERT_EQ(new_tls_index, module_data_.tls_index);
  ASSERT_EQ(2U, default_frequency_data_[0]);
  ASSERT_EQ(1U, default_frequency_data_[1]);

  // FS-Slot must stay unchanged.
  ASSERT_EQ(0U, module_data_.fs_slot);

  // Simulate the process detach event.
  SimulateModuleEvent(DLL_PROCESS_DETACH);

  // Unload the DLL.
  ASSERT_NO_FATAL_FAILURE(UnloadDll());

  // Replay the log. There should be none as we didn't start the service.
  ASSERT_NO_FATAL_FAILURE(ReplayLogs(0));
}

TEST_F(BasicBlockEntryTest, SingleThreadedDllBasicBlockEvents) {
  // Configure for BasicBlock mode.
  ConfigureBasicBlockAgent();

  ASSERT_NO_FATAL_FAILURE(StartService());
  ASSERT_NO_FATAL_FAILURE(LoadDll());

  // Simulate the process attach event.
  SimulateModuleEvent(DLL_PROCESS_ATTACH);

  // Validate that it does not modify any of our initialization values.
  ASSERT_EQ(::common::kBasicBlockEntryAgentId, common_data_->agent_id);
  ASSERT_EQ(::common::kBasicBlockFrequencyDataVersion, common_data_->version);
  ASSERT_EQ(IndexedFrequencyData::BASIC_BLOCK_ENTRY, common_data_->data_type);
  ASSERT_NE(TLS_OUT_OF_INDEXES, module_data_.tls_index);
  ASSERT_EQ(0U, module_data_.fs_slot);
  ASSERT_NE(0U, common_data_->initialization_attempted);
  ASSERT_EQ(kNumColumns, common_data_->num_columns);
  ASSERT_EQ(kNumBasicBlocks, common_data_->num_entries);

  // The frequency_data must be allocated and frequency_data must point to it.
  ASSERT_NE(default_branch_data_, common_data_->frequency_data);

  // Visiting an initial basic-block should not fail.
  SimulateBasicBlockEntry(0);
  ASSERT_EQ(0U, default_frequency_data_[0]);

  // Make a few more calls, just to keep things interesting.
  SimulateBasicBlockEntry(0);
  SimulateBasicBlockEntry(1);
  SimulateBasicBlockEntry(0);

  // Simulate the process detach event.
  SimulateModuleEvent(DLL_PROCESS_DETACH);

  // Unload the DLL and stop the service.
  ASSERT_NO_FATAL_FAILURE(UnloadDll());

  HMODULE self = ::GetModuleHandle(NULL);
  DWORD process_id = ::GetCurrentProcessId();
  DWORD thread_id = ::GetCurrentThreadId();

  static const uint32 kExpectedFrequencyData[kNumBasicBlocks] = { 3, 1 };

  // Set up expectations for what should be in the trace.
  EXPECT_CALL(handler_, OnProcessStarted(_, process_id, _));
  EXPECT_CALL(handler_, OnProcessAttach(_,
                                        process_id,
                                        thread_id,
                                        ModuleAtAddress(self)));
  EXPECT_CALL(handler_, OnIndexedFrequency(
      _,
      process_id,
      thread_id,
      FrequencyDataMatches(self, kNumBasicBlocks, kExpectedFrequencyData)));
  EXPECT_CALL(handler_, OnProcessEnded(_, process_id));

  // Replay the log.
  ASSERT_NO_FATAL_FAILURE(ReplayLogs(1));
}

TEST_F(BasicBlockEntryTest, SingleThreadedExeBasicBlockEvents) {
  // Configure for BasicBlock mode.
  ConfigureBasicBlockAgent();

  ASSERT_NO_FATAL_FAILURE(StartService());
  ASSERT_NO_FATAL_FAILURE(LoadDll());

  // Simulate the process attach event.
  ExeMainThunk();

  // Validate that it does not modify any of our initialization values.
  ASSERT_EQ(::common::kBasicBlockEntryAgentId, common_data_->agent_id);
  ASSERT_EQ(::common::kBasicBlockFrequencyDataVersion, common_data_->version);
  ASSERT_EQ(IndexedFrequencyData::BASIC_BLOCK_ENTRY, common_data_->data_type);
  ASSERT_NE(TLS_OUT_OF_INDEXES, module_data_.tls_index);
  ASSERT_EQ(0U, module_data_.fs_slot);
  ASSERT_NE(0U, common_data_->initialization_attempted);
  ASSERT_EQ(kNumColumns, common_data_->num_columns);
  ASSERT_EQ(kNumBasicBlocks, common_data_->num_entries);

  // The frequency_data must be allocated and frequency_data must point to it.
  ASSERT_NE(default_branch_data_, common_data_->frequency_data);

  // Visiting an initial basic-block should not fail.
  SimulateBasicBlockEntry(0);
  ASSERT_EQ(0U, default_frequency_data_[0]);

  // Make a few more calls, just to keep things interesting.
  SimulateBasicBlockEntry(0);
  SimulateBasicBlockEntry(1);
  SimulateBasicBlockEntry(0);

  // Simulate the process detach event.
  SimulateModuleEvent(DLL_PROCESS_DETACH);

  // Unload the DLL and stop the service.
  ASSERT_NO_FATAL_FAILURE(UnloadDll());

  HMODULE self = ::GetModuleHandle(NULL);
  DWORD process_id = ::GetCurrentProcessId();
  DWORD thread_id = ::GetCurrentThreadId();

  static const uint32 kExpectedFrequencyData[kNumBasicBlocks] = { 3, 1 };

  // Set up expectations for what should be in the trace.
  EXPECT_CALL(handler_, OnProcessStarted(_, process_id, _));
  EXPECT_CALL(handler_, OnProcessAttach(_,
                                        process_id,
                                        thread_id,
                                        ModuleAtAddress(self)));
  EXPECT_CALL(handler_, OnIndexedFrequency(
      _,
      process_id,
      thread_id,
      FrequencyDataMatches(self, kNumBasicBlocks, kExpectedFrequencyData)));
  EXPECT_CALL(handler_, OnProcessEnded(_, process_id));

  // Replay the log.
  ASSERT_NO_FATAL_FAILURE(ReplayLogs(1));
}

TEST_F(BasicBlockEntryTest, SingleThreadedExeBranchEvents) {
  // Configure for Branch mode.
  ConfigureBranchAgent();

  ASSERT_NO_FATAL_FAILURE(StartService());
  ASSERT_NO_FATAL_FAILURE(LoadDll());

  // Simulate the process attach event.
  ExeMainThunk();

  // Validate that it does not modify any of our initialization values.
  ASSERT_EQ(::common::kBasicBlockEntryAgentId, common_data_->agent_id);
  ASSERT_EQ(::common::kBasicBlockFrequencyDataVersion, common_data_->version);
  ASSERT_EQ(IndexedFrequencyData::BRANCH, common_data_->data_type);
  ASSERT_NE(TLS_OUT_OF_INDEXES, module_data_.tls_index);
  ASSERT_EQ(0U, module_data_.fs_slot);
  ASSERT_NE(0U, common_data_->initialization_attempted);
  ASSERT_EQ(kNumBranchColumns, common_data_->num_columns);
  ASSERT_EQ(kNumBasicBlocks, common_data_->num_entries);

  // The frequency_data must be allocated and frequency_data must point to it.
  ASSERT_NE(default_branch_data_, common_data_->frequency_data);

  // Visiting an initial basic-block should not fail.
  SimulateBranchEnter(0);
  SimulateBranchExit(0);
  ASSERT_NE(default_branch_data_, common_data_->frequency_data);
  for (size_t i = 0; i < kNumBranchColumns; ++i) {
    ASSERT_EQ(0U, default_branch_data_[i]);
  }

  // Make a few more calls, just to keep things interesting.
  SimulateBranchEnter(1);
  SimulateBranchExit(1);
  SimulateBranchEnter(0);
  SimulateBranchExit(0);
  SimulateBranchEnter(1);
  SimulateBranchExit(1);
  SimulateBranchEnter(0);
  SimulateBranchExit(0);
  for (int i = 0; i < 6; ++i) {
    SimulateBranchEnter(1);
    SimulateBranchExit(1);
  }
  for (int i = 0; i < 6; ++i) {
    SimulateBranchEnter(0);
    SimulateBranchExit(0);
  }

  // Simulate the process detach event.
  SimulateModuleEvent(DLL_PROCESS_DETACH);

  // Unload the DLL and stop the service.
  ASSERT_NO_FATAL_FAILURE(UnloadDll());

  HMODULE self = ::GetModuleHandle(NULL);
  DWORD process_id = ::GetCurrentProcessId();
  DWORD thread_id = ::GetCurrentThreadId();

  static const uint32 kExpectedBranchData[kNumBranchColumns * kNumBasicBlocks] =
      { 9, 5, 2, 8, 2, 2 };

  // Set up expectations for what should be in the trace.
  EXPECT_CALL(handler_, OnProcessStarted(_, process_id, _));
  EXPECT_CALL(handler_, OnProcessAttach(_,
                                        process_id,
                                        thread_id,
                                        ModuleAtAddress(self)));
  const uint32 kNumData = kNumBranchColumns * kNumBasicBlocks;
  EXPECT_CALL(handler_, OnIndexedFrequency(
      _,
      process_id,
      thread_id,
      FrequencyDataMatches(self, kNumData, kExpectedBranchData)));
  EXPECT_CALL(handler_, OnProcessEnded(_, process_id));

  // Replay the log.
  ASSERT_NO_FATAL_FAILURE(ReplayLogs(1));
}

TEST_F(BasicBlockEntryTest, BranchWithBufferingEvents) {
  // Configure for Branch mode.
  ConfigureBranchAgent();

  ASSERT_NO_FATAL_FAILURE(StartService());
  ASSERT_NO_FATAL_FAILURE(LoadDll());

  // Simulate the process attach event.
  ExeMainThunk();

  // Visiting an initial basic-block should not fail.
  SimulateBranchEnterBuffered(0);
  SimulateBranchExit(0);
  SimulateBranchEnterBuffered(1);
  SimulateBranchExit(1);
  ASSERT_NE(default_branch_data_, common_data_->frequency_data);

  // Keep a pointer to raw counters.
  uint32* frequency_data =
      reinterpret_cast<uint32*>(common_data_->frequency_data);

  // Validate no events have been committed.
  for (size_t i = 0; i < kNumBranchColumns; ++i) {
    EXPECT_EQ(0U, frequency_data[i]);
  }

  // Force a flush.
  const int kBigEnoughToCauseAFlush = BasicBlockEntry::kBufferSize + 1;
  for (int i = 0; i < kBigEnoughToCauseAFlush; ++i) {
    SimulateBranchEnterBuffered(0);
    SimulateBranchExit(0);
  }

  // Validate some events are committed.
  EXPECT_NE(0U, frequency_data[0 * kNumBranchColumns]);
  // Entering basic block 1 must be committed.
  EXPECT_EQ(1U, frequency_data[1 * kNumBranchColumns]);

  // Force a flush.
  uint32 old_count = frequency_data[0];
  for (int i = 0; i < kBigEnoughToCauseAFlush; ++i) {
    SimulateBranchEnterBuffered(0);
    SimulateBranchExit(0);
  }

  // Expect to have increasing values.
  uint32 new_count = frequency_data[0];
  EXPECT_LT(old_count, new_count);

  ASSERT_NO_FATAL_FAILURE(StopService());
}

TEST_F(BasicBlockEntryTest, SingleExeBranchEvents) {
  ASSERT_NO_FATAL_FAILURE(
    CheckExecution(kExeMain, kBranchInstrumentation));
}

TEST_F(BasicBlockEntryTest, SingleDllBranchEvents) {
  ASSERT_NO_FATAL_FAILURE(
    CheckExecution(kDllMain, kBranchInstrumentation));
}

TEST_F(BasicBlockEntryTest, SingleExeBranchWithSlotEvents) {
  ASSERT_NO_FATAL_FAILURE(
    CheckExecution(kExeMain, kBranchWithSlotInstrumentation));
}

TEST_F(BasicBlockEntryTest, SingleDllBranchWithSlotEvents) {
  ASSERT_NO_FATAL_FAILURE(
    CheckExecution(kDllMain, kBranchWithSlotInstrumentation));
}

TEST_F(BasicBlockEntryTest, SingleExeBranchBufferedEvents) {
  ASSERT_NO_FATAL_FAILURE(
    CheckExecution(kExeMain, kBufferedBranchInstrumentation));
}

TEST_F(BasicBlockEntryTest, SingleDllBranchBufferedEvents) {
  ASSERT_NO_FATAL_FAILURE(
    CheckExecution(kDllMain, kBufferedBranchInstrumentation));
}

TEST_F(BasicBlockEntryTest, SingleExeBranchBufferedWithSlotEvents) {
  ASSERT_NO_FATAL_FAILURE(
    CheckExecution(kExeMain, kBufferedBranchWithSlotInstrumentation));
}

TEST_F(BasicBlockEntryTest, SingleDllBranchBufferedWithSlotEvents) {
  ASSERT_NO_FATAL_FAILURE(
    CheckExecution(kDllMain, kBufferedBranchWithSlotInstrumentation));
}

TEST_F(BasicBlockEntryTest, MultiThreadedDllBasicBlockEvents) {
  ASSERT_NO_FATAL_FAILURE(
      CheckThreadExecution(kDllMain, kBasicBlockEntryInstrumentation));
}

TEST_F(BasicBlockEntryTest, MultiThreadedExeBasicBlockEvents) {
  ASSERT_NO_FATAL_FAILURE(
      CheckThreadExecution(kExeMain, kBasicBlockEntryInstrumentation));
}

TEST_F(BasicBlockEntryTest, MultiThreadedDllBranchEvents) {
  ASSERT_NO_FATAL_FAILURE(
      CheckThreadExecution(kDllMain, kBranchInstrumentation));
}

TEST_F(BasicBlockEntryTest, MultiThreadedExeBranchEvents) {
  ASSERT_NO_FATAL_FAILURE(
      CheckThreadExecution(kExeMain, kBranchInstrumentation));
}

TEST_F(BasicBlockEntryTest, MultiThreadedDllBranchWithSlotEvents) {
  ASSERT_NO_FATAL_FAILURE(
      CheckThreadExecution(kDllMain, kBranchWithSlotInstrumentation));
}

TEST_F(BasicBlockEntryTest, MultiThreadedExeBranchWithSlotEvents) {
  ASSERT_NO_FATAL_FAILURE(
      CheckThreadExecution(kExeMain, kBranchWithSlotInstrumentation));
}

TEST_F(BasicBlockEntryTest, MultiThreadedDllBufferedBranchEvents) {
  ASSERT_NO_FATAL_FAILURE(
      CheckThreadExecution(kDllMain, kBufferedBranchInstrumentation));
}

TEST_F(BasicBlockEntryTest, MultiThreadedExeBufferedBranchEvents) {
  ASSERT_NO_FATAL_FAILURE(
      CheckThreadExecution(kExeMain, kBufferedBranchInstrumentation));
}

TEST_F(BasicBlockEntryTest, MultiThreadedDllBufferedBranchWithSlotEvents) {
  ASSERT_NO_FATAL_FAILURE(
      CheckThreadExecution(kDllMain, kBufferedBranchWithSlotInstrumentation));
}

TEST_F(BasicBlockEntryTest, MultiThreadedExeBufferedBranchWithSlotEvents) {
  ASSERT_NO_FATAL_FAILURE(
      CheckThreadExecution(kExeMain, kBufferedBranchWithSlotInstrumentation));
}

}  // namespace basic_block_entry
}  // namespace agent
