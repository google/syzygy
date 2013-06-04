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
#include "base/stringprintf.h"
#include "gtest/gtest.h"
#include "syzygy/agent/asan/asan_rtl_impl.h"
#include "syzygy/agent/asan/asan_runtime.h"
#include "syzygy/common/unittest_util.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/instrument/instrument_app.h"
#include "syzygy/pe/test_dll.h"
#include "syzygy/pe/unittest_util.h"
#include "syzygy/trace/protocol/call_trace_defs.h"

namespace integration_tests {

namespace {

using instrument::InstrumentApp;
typedef common::Application<InstrumentApp> TestApp;

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

void AsanSafeCallback(CONTEXT* ctx, agent::asan::AsanErrorInfo* info) {
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

class IntrumentAppIntegrationTest : public testing::PELibUnitTest {
 public:
  typedef testing::PELibUnitTest Super;

  IntrumentAppIntegrationTest()
      : cmd_line_(base::FilePath(L"instrument.exe")),
        test_impl_(test_app_.implementation()) {
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

    // Make it non-mandatory that there be a trace service running.
    scoped_ptr<base::Environment> env(base::Environment::Create());
    std::string env_var;
    env->SetVar(
        ::kSyzygyRpcSessionMandatoryEnvVar,
        base::StringPrintf("%s,0;%s,0;%s,0;%s,0",
                           InstrumentApp::kAgentDllBasicBlockEntry,
                           InstrumentApp::kAgentDllCoverage,
                           InstrumentApp::kAgentDllProfile,
                           InstrumentApp::kAgentDllRpc));

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

  // @name Command-line and parameters.
  // @{
  CommandLine cmd_line_;
  base::FilePath input_dll_path_;
  base::FilePath output_dll_path_;
  // @}

  testing::ScopedHMODULE module_;
};

}  // namespace

TEST_F(IntrumentAppIntegrationTest, AsanEndToEnd) {
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("asan"));
  ASSERT_NO_FATAL_FAILURE(EndToEndCheckTestDll());
  ASSERT_NO_FATAL_FAILURE(AsanErrorCheckTestDll());
}

TEST_F(IntrumentAppIntegrationTest, LivenessAsanEndToEnd) {
  cmd_line_.AppendSwitchPath("use-liveness-analysis", input_dll_path_);
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("asan"));
  ASSERT_NO_FATAL_FAILURE(EndToEndCheckTestDll());
  ASSERT_NO_FATAL_FAILURE(AsanErrorCheckTestDll());
}

TEST_F(IntrumentAppIntegrationTest, RedundantMemoryAsanEndToEnd) {
  cmd_line_.AppendSwitchPath("remove-redundant-checks", input_dll_path_);
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("asan"));
  ASSERT_NO_FATAL_FAILURE(EndToEndCheckTestDll());
  ASSERT_NO_FATAL_FAILURE(AsanErrorCheckTestDll());
}

TEST_F(IntrumentAppIntegrationTest, FullOptimizedAsanEndToEnd) {
  cmd_line_.AppendSwitchPath("use-liveness-analysis", input_dll_path_);
  cmd_line_.AppendSwitchPath("remove-redundant-checks", input_dll_path_);
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("asan"));
  ASSERT_NO_FATAL_FAILURE(EndToEndCheckTestDll());
  ASSERT_NO_FATAL_FAILURE(AsanErrorCheckTestDll());
}

TEST_F(IntrumentAppIntegrationTest, BBEntryEndToEnd) {
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("bbentry"));
  ASSERT_NO_FATAL_FAILURE(EndToEndCheckTestDll());
}

TEST_F(IntrumentAppIntegrationTest, CallTraceEndToEnd) {
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("calltrace"));
  ASSERT_NO_FATAL_FAILURE(EndToEndCheckTestDll());
}

TEST_F(IntrumentAppIntegrationTest, CoverageEndToEnd) {
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("coverage"));
  ASSERT_NO_FATAL_FAILURE(EndToEndCheckTestDll());
}

TEST_F(IntrumentAppIntegrationTest, ProfileEndToEnd) {
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("profile"));
  ASSERT_NO_FATAL_FAILURE(EndToEndCheckTestDll());
}

}  // integration_tests instrument
