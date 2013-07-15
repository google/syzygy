// Copyright 2013 Google Inc. All Rights Reserved.
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

#include "base/environment.h"
#include "base/string_util.h"
#include "base/stringprintf.h"
#include "gtest/gtest.h"
#include "syzygy/agent/asan/asan_rtl_impl.h"
#include "syzygy/agent/asan/asan_runtime.h"
#include "syzygy/common/indexed_frequency_data.h"
#include "syzygy/common/unittest_util.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/grinder/basic_block_util.h"
#include "syzygy/grinder/grinder.h"
#include "syzygy/grinder/grinders/basic_block_entry_count_grinder.h"
#include "syzygy/grinder/grinders/coverage_grinder.h"
#include "syzygy/instrument/instrument_app.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/test_dll.h"
#include "syzygy/pe/unittest_util.h"
#include "syzygy/trace/common/unittest_util.h"

namespace integration_tests {

namespace {

using grinder::basic_block_util::EntryCountMap;
using grinder::basic_block_util::ModuleEntryCountMap;
using instrument::InstrumentApp;
using trace::parser::Parser;
typedef block_graph::BlockGraph::Block Block;
typedef block_graph::BlockGraph::BlockMap BlockMap;
typedef common::Application<InstrumentApp> TestApp;
typedef grinder::CoverageData::LineExecutionCountMap LineExecutionCountMap;
typedef grinder::CoverageData::SourceFileCoverageData SourceFileCoverageData;
typedef grinder::CoverageData::SourceFileCoverageDataMap
    SourceFileCoverageDataMap;

enum AccessMode {
  ASAN_READ_ACCESS = agent::asan::HeapProxy::ASAN_READ_ACCESS,
  ASAN_WRITE_ACCESS = agent::asan::HeapProxy::ASAN_WRITE_ACCESS,
  ASAN_UNKNOWN_ACCESS = agent::asan::HeapProxy::ASAN_UNKNOWN_ACCESS,
};

enum BadAccessKind {
  UNKNOWN_BAD_ACCESS = agent::asan::HeapProxy::UNKNOWN_BAD_ACCESS,
  USE_AFTER_FREE = agent::asan::HeapProxy::USE_AFTER_FREE,
  HEAP_BUFFER_OVERFLOW = agent::asan::HeapProxy::HEAP_BUFFER_OVERFLOW,
  HEAP_BUFFER_UNDERFLOW = agent::asan::HeapProxy::HEAP_BUFFER_UNDERFLOW,
};

// Contains the number of ASAN errors reported with our callback.
int asan_error_count;
// Contains the last ASAN error reported.
agent::asan::AsanErrorInfo last_asan_error;

void AsanSafeCallback(agent::asan::AsanErrorInfo* info) {
  asan_error_count++;
  last_asan_error = *info;
}

void ResetAsanErrors() {
  asan_error_count = 0;
}

void SetAsanCallBack() {
  typedef void (WINAPI *AsanSetCallBack)(AsanErrorCallBack);

  HMODULE asan_module = GetModuleHandle(L"asan_rtl.dll");
  DCHECK(asan_module != NULL);
  AsanSetCallBack set_callback = reinterpret_cast<AsanSetCallBack>(
      ::GetProcAddress(asan_module, "asan_SetCallBack"));
  DCHECK(set_callback != NULL);

  set_callback(AsanSafeCallback);
};

class InstrumentAppIntegrationTest : public testing::PELibUnitTest {
 public:
  typedef testing::PELibUnitTest Super;

  InstrumentAppIntegrationTest()
      : cmd_line_(base::FilePath(L"instrument.exe")),
        test_impl_(test_app_.implementation()),
        image_layout_(&block_graph_) {
  }

  void SetUp() {
    Super::SetUp();

    // Several of the tests generate progress and (deliberate) error messages
    // that would otherwise clutter the unittest output.
    logging::SetMinLogLevel(logging::LOG_FATAL);

    // Setup the IO streams.
    CreateTemporaryDir(&temp_dir_);
    stdin_path_ = temp_dir_.Append(L"NUL");
    stdout_path_ = temp_dir_.Append(L"stdout.txt");
    stderr_path_ = temp_dir_.Append(L"stderr.txt");
    InitStreams(stdin_path_, stdout_path_, stderr_path_);

    // Initialize the (potential) input and output path values.
    base::FilePath abs_input_dll_path_ =
        testing::GetExeRelativePath(testing::kTestDllName);
    input_dll_path_ = testing::GetRelativePath(abs_input_dll_path_);
    output_dll_path_ = temp_dir_.Append(input_dll_path_.BaseName());

    // Initialize call_service output directory for produced trace files.
    traces_dir_ = temp_dir_.Append(L"traces");

    // Initialize call_service session id.
    service_.SetEnvironment();

    ASSERT_NO_FATAL_FAILURE(ConfigureTestApp(&test_app_));
  }

  void TearDown() {
    // We need to release the module handle before Super::TearDown, otherwise
    // the library file cannot be deleted.
    module_.Release();

    Super::TearDown();
  }

  // Points the application at the fixture's command-line and IO streams.
  template<typename TestAppType>
  void ConfigureTestApp(TestAppType* test_app) {
    test_app->set_command_line(&cmd_line_);
    test_app->set_in(in());
    test_app->set_out(out());
    test_app->set_err(err());
  }

  void StartService() {
    service_.Start(traces_dir_);
  }

  void StopService() {
    service_.Stop();
  }

  // Runs an instrumentation pass in the given mode and validates that the
  // resulting output DLL loads.
  void EndToEndTest(const std::string& mode) {
    cmd_line_.AppendSwitchPath("input-image", input_dll_path_);
    cmd_line_.AppendSwitchPath("output-image", output_dll_path_);
    cmd_line_.AppendSwitchASCII("mode", mode);

    // Create the instrumented DLL.
    common::Application<instrument::InstrumentApp> app;
    ASSERT_NO_FATAL_FAILURE(ConfigureTestApp(&app));
    ASSERT_EQ(0, app.Run());

    // Validate that the test dll loads post instrumentation.
    ASSERT_NO_FATAL_FAILURE(CheckTestDll(output_dll_path_, &module_));
  }

  // Invoke a test function inside test_dll by addressing it with a test id.
  // Returns the value resulting of test function execution.
  unsigned int InvokeTestDllFunction(EndToEndTestId test) {
    // Load the exported 'function_name' function.
    typedef unsigned int (CALLBACK* TestDllFuncs)(unsigned int);
    TestDllFuncs func = reinterpret_cast<TestDllFuncs>(
        ::GetProcAddress(module_, "EndToEndTest"));
    DCHECK(func != NULL);

    // Invoke it, and returns its value.
    return func(test);
  }

  void EndToEndCheckTestDll() {
    // Validate that behavior is unchanged after instrumentation.
    EXPECT_EQ(0xfff80200, InvokeTestDllFunction(kArrayComputation1TestId));
    EXPECT_EQ(0x00000200, InvokeTestDllFunction(kArrayComputation2TestId));
  }

  void AsanErrorCheck(EndToEndTestId test, BadAccessKind kind,
      AccessMode mode, size_t size) {

    ResetAsanErrors();
    InvokeTestDllFunction(test);
    EXPECT_LT(0, asan_error_count);
    EXPECT_EQ(kind, last_asan_error.error_type);
    EXPECT_EQ(mode, last_asan_error.access_mode);
    EXPECT_EQ(size, last_asan_error.access_size);
  }

  void AsanErrorCheckTestDll() {
    ASSERT_NO_FATAL_FAILURE(SetAsanCallBack());

    AsanErrorCheck(kAsanRead8BufferOverflowTestId, HEAP_BUFFER_OVERFLOW,
        ASAN_READ_ACCESS, 1);
    AsanErrorCheck(kAsanRead16BufferOverflowTestId, HEAP_BUFFER_OVERFLOW,
        ASAN_READ_ACCESS, 2);
    AsanErrorCheck(kAsanRead32BufferOverflowTestId, HEAP_BUFFER_OVERFLOW,
        ASAN_READ_ACCESS, 4);
    AsanErrorCheck(kAsanRead64BufferOverflowTestId, HEAP_BUFFER_OVERFLOW,
        ASAN_READ_ACCESS, 8);

    AsanErrorCheck(kAsanRead8BufferUnderflowTestId, HEAP_BUFFER_UNDERFLOW,
        ASAN_READ_ACCESS, 1);
    AsanErrorCheck(kAsanRead16BufferUnderflowTestId, HEAP_BUFFER_UNDERFLOW,
        ASAN_READ_ACCESS, 2);
    AsanErrorCheck(kAsanRead32BufferUnderflowTestId, HEAP_BUFFER_UNDERFLOW,
        ASAN_READ_ACCESS, 4);
    AsanErrorCheck(kAsanRead64BufferUnderflowTestId, HEAP_BUFFER_UNDERFLOW,
        ASAN_READ_ACCESS, 8);

    AsanErrorCheck(kAsanWrite8BufferOverflowTestId, HEAP_BUFFER_OVERFLOW,
        ASAN_WRITE_ACCESS, 1);
    AsanErrorCheck(kAsanWrite16BufferOverflowTestId, HEAP_BUFFER_OVERFLOW,
        ASAN_WRITE_ACCESS, 2);
    AsanErrorCheck(kAsanWrite32BufferOverflowTestId, HEAP_BUFFER_OVERFLOW,
        ASAN_WRITE_ACCESS, 4);
    AsanErrorCheck(kAsanWrite64BufferOverflowTestId, HEAP_BUFFER_OVERFLOW,
        ASAN_WRITE_ACCESS, 8);

    AsanErrorCheck(kAsanWrite8BufferUnderflowTestId, HEAP_BUFFER_UNDERFLOW,
        ASAN_WRITE_ACCESS, 1);
    AsanErrorCheck(kAsanWrite16BufferUnderflowTestId, HEAP_BUFFER_UNDERFLOW,
        ASAN_WRITE_ACCESS, 2);
    AsanErrorCheck(kAsanWrite32BufferUnderflowTestId, HEAP_BUFFER_UNDERFLOW,
        ASAN_WRITE_ACCESS, 4);
    AsanErrorCheck(kAsanWrite64BufferUnderflowTestId, HEAP_BUFFER_UNDERFLOW,
        ASAN_WRITE_ACCESS, 8);

    AsanErrorCheck(kAsanRead8UseAfterFreeTestId, USE_AFTER_FREE,
        ASAN_READ_ACCESS, 1);
    AsanErrorCheck(kAsanRead16UseAfterFreeTestId, USE_AFTER_FREE,
        ASAN_READ_ACCESS, 2);
    AsanErrorCheck(kAsanRead32UseAfterFreeTestId, USE_AFTER_FREE,
        ASAN_READ_ACCESS, 4);
    AsanErrorCheck(kAsanRead64UseAfterFreeTestId, USE_AFTER_FREE,
        ASAN_READ_ACCESS, 8);

    AsanErrorCheck(kAsanWrite8UseAfterFreeTestId, USE_AFTER_FREE,
        ASAN_WRITE_ACCESS, 1);
    AsanErrorCheck(kAsanWrite16UseAfterFreeTestId, USE_AFTER_FREE,
        ASAN_WRITE_ACCESS, 2);
    AsanErrorCheck(kAsanWrite32UseAfterFreeTestId, USE_AFTER_FREE,
        ASAN_WRITE_ACCESS, 4);
    AsanErrorCheck(kAsanWrite64UseAfterFreeTestId, USE_AFTER_FREE,
        ASAN_WRITE_ACCESS, 8);
  }

  void AsanErrorCheckInterceptedFunctions() {
    AsanErrorCheck(kAsanMemsetOverflow, HEAP_BUFFER_OVERFLOW,
        ASAN_WRITE_ACCESS, 1);
    AsanErrorCheck(kAsanMemsetUnderflow, HEAP_BUFFER_UNDERFLOW,
        ASAN_WRITE_ACCESS, 1);
    AsanErrorCheck(kAsanMemchrOverflow, HEAP_BUFFER_OVERFLOW,
        ASAN_READ_ACCESS, 1);
    AsanErrorCheck(kAsanMemchrUnderflow, HEAP_BUFFER_UNDERFLOW,
        ASAN_READ_ACCESS, 1);
  }

  void BBEntryInvokeTestDll() {
    EXPECT_EQ(42, InvokeTestDllFunction(kBBEntryCallOnce));
    EXPECT_EQ(42, InvokeTestDllFunction(kBBEntryCallTree));
    EXPECT_EQ(42, InvokeTestDllFunction(kBBEntryCallRecursive));
  }

  void QueueTraces(Parser* parser) {
    DCHECK(parser != NULL);

    // Queue up the trace file(s) we engendered.
    file_util::FileEnumerator enumerator(traces_dir_,
                                         false,
                                         file_util::FileEnumerator::FILES);
    while (true) {
      base::FilePath trace_file = enumerator.Next();
      if (trace_file.empty())
        break;
      ASSERT_TRUE(parser->OpenTraceFile(trace_file));
    }
  }

  const Block* FindBlockWithName(std::string name) {
    const BlockMap& blocks = block_graph_.blocks();
    BlockMap::const_iterator block_iter = blocks.begin();
    for (; block_iter != blocks.end(); ++block_iter) {
      const Block& block = block_iter->second;
      if (block.type() != block_graph::BlockGraph::CODE_BLOCK)
        continue;
      if (block.name().compare(name) == 0)
        return &block;
    }
    return NULL;
  }

  int GetBlockFrequency(const EntryCountMap& entry_count, const Block* block) {
    DCHECK(block != NULL);
    EntryCountMap::const_iterator entry =
        entry_count.find(block->addr().value());
    if (entry == entry_count.end())
      return 0;
    return entry->second;
  }

  void ExpectFunctionFrequency(const EntryCountMap& entry_count,
                               const char* function_name,
                               int expected_frequency) {
    DCHECK(function_name != NULL);
    const Block* block = FindBlockWithName(function_name);
    ASSERT_TRUE(block != NULL);
    int exec_frequency = GetBlockFrequency(entry_count, block);
    EXPECT_EQ(expected_frequency, exec_frequency);
  }

  void DecomposeImage() {
    // Decompose the DLL.
    pe_image_.Init(input_dll_path_);
    pe::Decomposer decomposer(pe_image_);
    ASSERT_TRUE(decomposer.Decompose(&image_layout_));
  }

  void BBEntryCheckTestDll() {
    Parser parser;
    grinder::grinders::BasicBlockEntryCountGrinder grinder;

    // Initialize trace parser.
    ASSERT_TRUE(parser.Init(&grinder));
    grinder.SetParser(&parser);

    // Add generated traces to the parser.
    QueueTraces(&parser);

    // Parse all traces.
    ASSERT_TRUE(parser.Consume());
    ASSERT_FALSE(parser.error_occurred());
    ASSERT_TRUE(grinder.Grind());

    // Retrieve basic block count information.
    const grinder::basic_block_util::ModuleEntryCountMap& module_entry_count =
        grinder.entry_count_map();
    ASSERT_EQ(1u, module_entry_count.size());

    ModuleEntryCountMap::const_iterator entry_iter = module_entry_count.begin();
    const EntryCountMap& entry_count = entry_iter->second;

    // Decompose the output image.
    ASSERT_NO_FATAL_FAILURE(DecomposeImage());

    // Validate function entry counts.
    ASSERT_NO_FATAL_FAILURE(
        ExpectFunctionFrequency(entry_count, "BBEntryCallOnce", 1));
    ASSERT_NO_FATAL_FAILURE(
        ExpectFunctionFrequency(entry_count, "BBEntryCallTree", 1));
    ASSERT_NO_FATAL_FAILURE(
        ExpectFunctionFrequency(entry_count, "BBEntryFunction1", 4));
    ASSERT_NO_FATAL_FAILURE(
        ExpectFunctionFrequency(entry_count, "BBEntryFunction2", 2));
    ASSERT_NO_FATAL_FAILURE(
        ExpectFunctionFrequency(entry_count, "BBEntryFunction3", 1));
    ASSERT_NO_FATAL_FAILURE(
        ExpectFunctionFrequency(entry_count, "BBEntryCallRecursive", 1));
    ASSERT_NO_FATAL_FAILURE(
        ExpectFunctionFrequency(entry_count, "BBEntryFunctionRecursive", 42));
  }

  bool GetLineInfoExecution(const SourceFileCoverageData* data, size_t line) {
    DCHECK(data != NULL);

    const LineExecutionCountMap& lines = data->line_execution_count_map;
    LineExecutionCountMap::const_iterator look = lines.find(line);
    if (look != lines.end()) {
      if (look->second != 0)
        return true;
    }

    return false;
  }

  void CoverageInvokeTestDll() {
    EXPECT_EQ(182, InvokeTestDllFunction(kCoverage1));
    EXPECT_EQ(182, InvokeTestDllFunction(kCoverage2));
    EXPECT_EQ(2, InvokeTestDllFunction(kCoverage3));
  }

  void CoverageCheckTestDll() {
    Parser parser;
    grinder::grinders::CoverageGrinder grinder;

    // Initialize trace parser.
    ASSERT_TRUE(parser.Init(&grinder));
    grinder.SetParser(&parser);

    // Add generated traces to the parser.
    QueueTraces(&parser);

    // Parse all traces.
    ASSERT_TRUE(parser.Consume());
    ASSERT_FALSE(parser.error_occurred());
    ASSERT_TRUE(grinder.Grind());

    // Retrieve coverage information.
    const grinder::CoverageData& coverage_data = grinder.coverage_data();
    const SourceFileCoverageDataMap& files =
        coverage_data.source_file_coverage_data_map();

    // Find file "test_dll_cov.cc".
    SourceFileCoverageDataMap::const_iterator file = files.begin();
    const SourceFileCoverageData* data = NULL;
    for (; file != files.end(); ++file) {
      if (EndsWith(file->first, "test_dll_cov.cc", true)) {
        data = &file->second;
        break;
      }
    }
    ASSERT_TRUE(data != NULL);

    // Validate function entry counts.
    // Function: coverage_func1.
    EXPECT_TRUE(GetLineInfoExecution(data, 26));
    EXPECT_TRUE(GetLineInfoExecution(data, 27));

    // Function: coverage_func2.
    EXPECT_TRUE(GetLineInfoExecution(data, 33));
    EXPECT_TRUE(GetLineInfoExecution(data, 34));
    EXPECT_TRUE(GetLineInfoExecution(data, 35));
    EXPECT_FALSE(GetLineInfoExecution(data, 38));
    EXPECT_TRUE(GetLineInfoExecution(data, 40));

    // Function: coverage_func3.
    EXPECT_TRUE(GetLineInfoExecution(data, 45));
    EXPECT_FALSE(GetLineInfoExecution(data, 47));
    EXPECT_FALSE(GetLineInfoExecution(data, 48));
    EXPECT_TRUE(GetLineInfoExecution(data, 50));
    EXPECT_TRUE(GetLineInfoExecution(data, 52));
  }

  // Stashes the current log-level before each test instance and restores it
  // after each test completes.
  testing::ScopedLogLevelSaver log_level_saver;

  // @name The application under test.
  // @{
  TestApp test_app_;
  TestApp::Implementation& test_impl_;
  base::FilePath temp_dir_;
  base::FilePath stdin_path_;
  base::FilePath stdout_path_;
  base::FilePath stderr_path_;
  // @}

  // @name Command-line, parameters and outputs.
  // @{
  CommandLine cmd_line_;
  base::FilePath input_dll_path_;
  base::FilePath output_dll_path_;
  base::FilePath traces_dir_;
  // @}

  // The test_dll module.
  testing::ScopedHMODULE module_;

  // Our call trace service process instance.
  testing::CallTraceService service_;

  // Decomposed image.
  pe::PEFile pe_image_;
  pe::ImageLayout image_layout_;
  block_graph::BlockGraph block_graph_;
};

}  // namespace

TEST_F(InstrumentAppIntegrationTest, AsanEndToEndNoLiveness) {
  cmd_line_.AppendSwitch("no-liveness-analysis");
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("asan"));
  ASSERT_NO_FATAL_FAILURE(EndToEndCheckTestDll());
  ASSERT_NO_FATAL_FAILURE(AsanErrorCheckTestDll());
}

TEST_F(InstrumentAppIntegrationTest, AsanEndToEnd) {
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("asan"));
  ASSERT_NO_FATAL_FAILURE(EndToEndCheckTestDll());
  ASSERT_NO_FATAL_FAILURE(AsanErrorCheckTestDll());
}

TEST_F(InstrumentAppIntegrationTest, RedundantMemoryAsanEndToEnd) {
  cmd_line_.AppendSwitch("remove-redundant-checks");
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("asan"));
  ASSERT_NO_FATAL_FAILURE(EndToEndCheckTestDll());
  ASSERT_NO_FATAL_FAILURE(AsanErrorCheckTestDll());
}

TEST_F(InstrumentAppIntegrationTest, FullOptimizedAsanEndToEnd) {
  cmd_line_.AppendSwitch("remove-redundant-checks");
  cmd_line_.AppendSwitch("intercept-crt-functions");
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("asan"));
  ASSERT_NO_FATAL_FAILURE(EndToEndCheckTestDll());
  ASSERT_NO_FATAL_FAILURE(AsanErrorCheckTestDll());
  ASSERT_NO_FATAL_FAILURE(AsanErrorCheckInterceptedFunctions());
}

TEST_F(InstrumentAppIntegrationTest, BBEntryEndToEnd) {
  ASSERT_NO_FATAL_FAILURE(StartService());
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("bbentry"));
  ASSERT_NO_FATAL_FAILURE(EndToEndCheckTestDll());
  ASSERT_NO_FATAL_FAILURE(BBEntryInvokeTestDll());
  ASSERT_NO_FATAL_FAILURE(StopService());
  ASSERT_NO_FATAL_FAILURE(BBEntryCheckTestDll());
}

TEST_F(InstrumentAppIntegrationTest, InlineFastPathBBEntryEndToEnd) {
  cmd_line_.AppendSwitch("inline-fast-path");
  ASSERT_NO_FATAL_FAILURE(StartService());
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("bbentry"));
  ASSERT_NO_FATAL_FAILURE(EndToEndCheckTestDll());
  ASSERT_NO_FATAL_FAILURE(BBEntryInvokeTestDll());
  ASSERT_NO_FATAL_FAILURE(StopService());
  ASSERT_NO_FATAL_FAILURE(BBEntryCheckTestDll());
}

TEST_F(InstrumentAppIntegrationTest, CallTraceEndToEnd) {
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("calltrace"));
  ASSERT_NO_FATAL_FAILURE(EndToEndCheckTestDll());
}

TEST_F(InstrumentAppIntegrationTest, CoverageEndToEnd) {
  ASSERT_NO_FATAL_FAILURE(StartService());
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("coverage"));
  ASSERT_NO_FATAL_FAILURE(EndToEndCheckTestDll());
  ASSERT_NO_FATAL_FAILURE(CoverageInvokeTestDll());
  ASSERT_NO_FATAL_FAILURE(StopService());
  ASSERT_NO_FATAL_FAILURE(CoverageCheckTestDll());
}

TEST_F(InstrumentAppIntegrationTest, BBEntryCoverageEndToEnd) {
  // Coverage grinder must be able to process traces produced by bbentry
  // instrumentation.
  ASSERT_NO_FATAL_FAILURE(StartService());
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("bbentry"));
  ASSERT_NO_FATAL_FAILURE(EndToEndCheckTestDll());
  ASSERT_NO_FATAL_FAILURE(CoverageInvokeTestDll());
  ASSERT_NO_FATAL_FAILURE(StopService());
  ASSERT_NO_FATAL_FAILURE(CoverageCheckTestDll());
}

TEST_F(InstrumentAppIntegrationTest, ProfileEndToEnd) {
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("profile"));
  ASSERT_NO_FATAL_FAILURE(EndToEndCheckTestDll());
}

}  // namespace integration_tests
