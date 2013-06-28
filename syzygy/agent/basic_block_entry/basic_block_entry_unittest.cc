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

#include "base/file_util.h"
#include "base/files/scoped_temp_dir.h"
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

// The number of basic blocks we'll work with for these tests.
const uint32 kNumBasicBlocks = 2;

// The module defining this lib/executable.
const HMODULE kThisModule = reinterpret_cast<HMODULE>(&__ImageBase);

// A helper to match modules by base address.
MATCHER_P(ModuleAtAddress, module, "") {
  return arg->module_base_addr == module;
}

// A helper to match basic-block frequency results to expectations.
MATCHER_P3(FrequencyDataMatches, module, bb_count, bb_freqs, "") {
  if (arg->module_base_addr != module)
    return false;

  if (arg->frequency_size != sizeof(uint32))
    return false;

  if (arg->num_entries != bb_count)
    return false;

  return ::memcmp(bb_freqs, arg->frequency_data, bb_count) == 0;
}

// The test fixture for the basic-block entry agent.
class BasicBlockEntryTest : public testing::Test {
 public:
  BasicBlockEntryTest()
      : agent_module_(NULL) {
    module_data_.agent_id = ::common::kBasicBlockEntryAgentId;
    module_data_.data_type = ::common::IndexedFrequencyData::BASIC_BLOCK_ENTRY;
    module_data_.version = ::common::kBasicBlockFrequencyDataVersion;
    module_data_.tls_index = TLS_OUT_OF_INDEXES;
    module_data_.initialization_attempted = 0U;
    module_data_.num_entries = kNumBasicBlocks;
    module_data_.frequency_data = default_frequency_data_;
    ::memset(&default_frequency_data_, 0, sizeof(default_frequency_data_));
  }

  virtual void SetUp() OVERRIDE {
    testing::Test::SetUp();
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    service_.SetEnvironment();
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
    file_util::FileEnumerator enumerator(temp_dir_.path(),
                                         false,
                                         file_util::FileEnumerator::FILES);
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
        ::GetProcAddress(agent_module_, "_increment_indexed_freq_data");
    ASSERT_TRUE(basic_block_enter_stub_ != NULL);

    indirect_penter_dllmain_stub_ =
        ::GetProcAddress(agent_module_, "_indirect_penter_dllmain");
    ASSERT_TRUE(indirect_penter_dllmain_stub_ != NULL);

    indirect_penter_exemain_stub_ =
        ::GetProcAddress(agent_module_, "_indirect_penter_exemain");
    ASSERT_TRUE(indirect_penter_exemain_stub_ != NULL);

    get_raw_frequency_data_stub_ =
        ::GetProcAddress(agent_module_, "GetRawFrequencyData");
    ASSERT_TRUE(get_raw_frequency_data_stub_ != NULL);
  }

  void UnloadDll() {
    if (agent_module_ != NULL) {
      ASSERT_TRUE(::FreeLibrary(agent_module_));
      agent_module_ = NULL;
      basic_block_enter_stub_ = NULL;
      indirect_penter_dllmain_stub_ = NULL;
      indirect_penter_exemain_stub_ = NULL;
      get_raw_frequency_data_stub_ = NULL;
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
       call basic_block_enter_stub_
     }
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
  static IndexedFrequencyData module_data_;

  // This will be a stand-in for the (usually statically allocated) fall-back
  // frequency to which module_data_.frequency_data will point.
  static uint32 default_frequency_data_[kNumBasicBlocks];

  // The basic-block entry entrance hook.
  static FARPROC basic_block_enter_stub_;

  // The DllMain entry stub.
  static FARPROC indirect_penter_dllmain_stub_;

  // The ExeMain entry stub.
  static FARPROC indirect_penter_exemain_stub_;

  // The entry stub to get a pointer to data frequency.
  static FARPROC get_raw_frequency_data_stub_;
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

int __declspec(naked) __cdecl BasicBlockEntryTest::GetFrequencyDataThunk() {
  __asm {
    push offset module_data_
    call get_raw_frequency_data_stub_
    ret
  }
}

BOOL __declspec(naked) __cdecl BasicBlockEntryTest::ExeMainThunk() {
  __asm {
    push offset module_data_
    push ExeMain
    jmp indirect_penter_exemain_stub_
  }
}

IndexedFrequencyData BasicBlockEntryTest::module_data_ = {};
uint32 BasicBlockEntryTest::default_frequency_data_[] = {};
FARPROC BasicBlockEntryTest::basic_block_enter_stub_ = NULL;
FARPROC BasicBlockEntryTest::indirect_penter_dllmain_stub_ = NULL;
FARPROC BasicBlockEntryTest::indirect_penter_exemain_stub_ = NULL;
FARPROC BasicBlockEntryTest::get_raw_frequency_data_stub_ = NULL;

}  // namespace

TEST_F(BasicBlockEntryTest, NoServerNoCrash) {
  // Load the agent dll.
  ASSERT_NO_FATAL_FAILURE(LoadDll());

  // Simulate the process attach event.
  SimulateModuleEvent(DLL_PROCESS_ATTACH);

  // Validate that it only modified the tls_index and initialization_attempted
  // values.
  ASSERT_EQ(::common::kBasicBlockEntryAgentId, module_data_.agent_id);
  ASSERT_EQ(::common::kBasicBlockFrequencyDataVersion, module_data_.version);
  ASSERT_EQ(IndexedFrequencyData::BASIC_BLOCK_ENTRY, module_data_.data_type);
  ASSERT_NE(TLS_OUT_OF_INDEXES, module_data_.tls_index);
  ASSERT_NE(0U, module_data_.initialization_attempted);
  ASSERT_EQ(kNumBasicBlocks, module_data_.num_entries);
  ASSERT_EQ(default_frequency_data_, module_data_.frequency_data);

  // Visiting an initial basic-block should not fail. It should initialize the
  // TLS index, map the frequency data to the default array, and increment the
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

  // Simulate the process detach event.
  SimulateModuleEvent(DLL_PROCESS_DETACH);

  // Unload the DLL.
  ASSERT_NO_FATAL_FAILURE(UnloadDll());

  // Replay the log. There should be none as we didn't start the service.
  ASSERT_NO_FATAL_FAILURE(ReplayLogs(0));
}

TEST_F(BasicBlockEntryTest, SingleThreadedDllBasicBlockEvents) {
  ASSERT_NO_FATAL_FAILURE(StartService());
  ASSERT_NO_FATAL_FAILURE(LoadDll());

  // Simulate the process attach event.
  SimulateModuleEvent(DLL_PROCESS_ATTACH);

  // Validate that it does not modify any of our initialization values.
  ASSERT_EQ(::common::kBasicBlockEntryAgentId, module_data_.agent_id);
  ASSERT_EQ(::common::kBasicBlockFrequencyDataVersion, module_data_.version);
  ASSERT_EQ(IndexedFrequencyData::BASIC_BLOCK_ENTRY, module_data_.data_type);
  ASSERT_NE(TLS_OUT_OF_INDEXES, module_data_.tls_index);
  ASSERT_NE(0U, module_data_.initialization_attempted);
  ASSERT_EQ(kNumBasicBlocks, module_data_.num_entries);
  ASSERT_EQ(default_frequency_data_, module_data_.frequency_data);

  // Visiting an initial basic-block should not fail. It should initialize the
  // TLS index, allocate a frequency map for this thread, and increment the
  // call count in the allocated frequency map. The default frequency data
  // should be left unchanged.
  SimulateBasicBlockEntry(0);
  ASSERT_EQ(default_frequency_data_, module_data_.frequency_data);
  ASSERT_EQ(0U, default_frequency_data_[0]);

  // Make a few more calls, just to keep things interesting.
  SimulateBasicBlockEntry(0);
  SimulateBasicBlockEntry(1);
  SimulateBasicBlockEntry(0);

  // Simulate the process attach event.
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
                                        ModuleAtAddress(self)));;
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
  ASSERT_NO_FATAL_FAILURE(StartService());
  ASSERT_NO_FATAL_FAILURE(LoadDll());

  // Simulate the process attach event.
  ExeMainThunk();

  // Validate that it does not modify any of our initialization values.
  ASSERT_EQ(::common::kBasicBlockEntryAgentId, module_data_.agent_id);
  ASSERT_EQ(::common::kBasicBlockFrequencyDataVersion, module_data_.version);
  ASSERT_EQ(IndexedFrequencyData::BASIC_BLOCK_ENTRY, module_data_.data_type);
  ASSERT_NE(TLS_OUT_OF_INDEXES, module_data_.tls_index);
  ASSERT_NE(0U, module_data_.initialization_attempted);
  ASSERT_EQ(kNumBasicBlocks, module_data_.num_entries);
  ASSERT_EQ(default_frequency_data_, module_data_.frequency_data);

  // Visiting an initial basic-block should not fail. It should initialize the
  // TLS index, allocate a frequency map for this thread, and increment the
  // call count in the allocated frequency map. The default frequency data
  // should be left unchanged.
  SimulateBasicBlockEntry(0);
  ASSERT_EQ(default_frequency_data_, module_data_.frequency_data);
  ASSERT_EQ(0U, default_frequency_data_[0]);

  // Make a few more calls, just to keep things interesting.
  SimulateBasicBlockEntry(0);
  SimulateBasicBlockEntry(1);
  SimulateBasicBlockEntry(0);

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
                                        ModuleAtAddress(self)));;
  EXPECT_CALL(handler_, OnIndexedFrequency(
      _,
      process_id,
      thread_id,
      FrequencyDataMatches(self, kNumBasicBlocks, kExpectedFrequencyData)));
  EXPECT_CALL(handler_, OnProcessEnded(_, process_id));

  // Replay the log.
  ASSERT_NO_FATAL_FAILURE(ReplayLogs(1));
}

TEST_F(BasicBlockEntryTest, InvokeGetFrequencyData) {
  ASSERT_NO_FATAL_FAILURE(StartService());
  ASSERT_NO_FATAL_FAILURE(LoadDll());

  // Simulate the process attach event.
  ExeMainThunk();

  // Check creation of a buffer on first call.
  EXPECT_TRUE(::TlsGetValue(module_data_.tls_index) == NULL);
  uint32* data1 = reinterpret_cast<uint32*>(GetFrequencyDataThunk());
  EXPECT_TRUE(data1 != NULL);
  EXPECT_TRUE(::TlsGetValue(module_data_.tls_index) != NULL);

  // Next calls should return the same buffer.
  uint32* data2 = reinterpret_cast<uint32*>(GetFrequencyDataThunk());
  EXPECT_EQ(data1, data2);

  // Unload the DLL and stop the service.
  ASSERT_NO_FATAL_FAILURE(UnloadDll());
}

// TODO(rogerm): Add a decent multi-thread test case.

}  // namespace basic_block_entry
}  // namespace agent
