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
#include "base/files/file_enumerator.h"
#include "base/files/file_path.h"
#include "base/memory/ptr_util.h"
#include "base/process/kill.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "base/win/pe_image.h"
#include "base/win/scoped_com_initializer.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "pcrecpp.h"  // NOLINT
#include "syzygy/agent/asan/rtl_impl.h"
#include "syzygy/agent/asan/runtime.h"
#include "syzygy/block_graph/transforms/chained_basic_block_transforms.h"
#include "syzygy/common/asan_parameters.h"
#include "syzygy/common/indexed_frequency_data.h"
#include "syzygy/common/unittest_util.h"
#include "syzygy/core/disassembler_util.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/grinder/basic_block_util.h"
#include "syzygy/grinder/grinder.h"
#include "syzygy/grinder/grinders/coverage_grinder.h"
#include "syzygy/grinder/grinders/indexed_frequency_data_grinder.h"
#include "syzygy/grinder/grinders/profile_grinder.h"
#include "syzygy/instrument/instrument_app.h"
#include "syzygy/instrument/transforms/asan_transform.h"
#include "syzygy/integration_tests/asan_page_protection_tests.h"
#include "syzygy/integration_tests/integration_tests_dll.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/pe_transform_policy.h"
#include "syzygy/pe/unittest_util.h"
#include "syzygy/poirot/minidump_processor.h"
#include "syzygy/testing/laa.h"
#include "syzygy/trace/agent_logger/agent_logger.h"
#include "syzygy/trace/common/unittest_util.h"

namespace integration_tests {

namespace {

// The exit code used by crash_for_exception_harness if the exception
// was appropriately dispatched.
const int kExeCrashForExceptionExitCode = 99;

using grinder::basic_block_util::IndexedFrequencyInformation;
using grinder::basic_block_util::IndexedFrequencyMap;
using grinder::basic_block_util::ModuleIndexedFrequencyMap;
using instrument::InstrumentApp;
using trace::parser::Parser;
typedef block_graph::BlockGraph::Block Block;
typedef block_graph::BlockGraph::BlockMap BlockMap;
typedef application::Application<InstrumentApp> TestApp;
typedef grinder::CoverageData::LineExecutionCountMap LineExecutionCountMap;
typedef grinder::CoverageData::SourceFileCoverageData SourceFileCoverageData;
typedef grinder::CoverageData::SourceFileCoverageDataMap
    SourceFileCoverageDataMap;

#define _STRINGIFY(s) #s
#define STRINGIFY(s) _STRINGIFY(s)

const char kAsanAccessViolationLog[] =
    "SyzyASAN: Caught an invalid access via an access violation exception.";
const char kAsanHandlingException[] = "SyzyASAN: Handling an exception.";
const char kAsanHeapBufferOverflow[] = "SyzyASAN error: heap-buffer-overflow ";
const char kAsanCorruptHeap[] = "SyzyASAN error: corrupt-heap ";
const char kAsanHeapUseAfterFree[] = "SyzyASAN error: heap-use-after-free ";
const char kAsanNearNullptrAccessHeapCorruption[] =
    "SyzyASAN: Caught a near-nullptr access with heap corruption.";
const char kAsanNearNullptrAccessNoHeapCorruption[] =
    "SyzyASAN: Ignoring a near-nullptr access without heap corruption.";

// A convenience class for controlling an out of process agent_logger instance,
// and getting the contents of its log file. Not thread safe.
struct ScopedAgentLogger {
  explicit ScopedAgentLogger(base::FilePath temp_dir)
      : nul_(NULL), temp_dir_(temp_dir) {
    agent_logger_ = testing::GetOutputRelativePath(
        L"agent_logger.exe");
    instance_id_ = base::StringPrintf("integra%08X", ::GetCurrentProcessId());
  }

  ~ScopedAgentLogger() {
    if (nul_) {
      ::CloseHandle(nul_);
      nul_ = NULL;
    }
  }

  void RunAction(const char* action, base::Process* process) {
    DCHECK_NE(static_cast<const char*>(nullptr), action);
    DCHECK_NE(static_cast<base::Process*>(nullptr), process);

    base::CommandLine cmd_line(agent_logger_);
    cmd_line.AppendSwitchASCII("instance-id", instance_id_);
    cmd_line.AppendSwitchPath("minidump-dir", temp_dir_);
    cmd_line.AppendSwitchPath("output-file", log_file_);
    cmd_line.AppendArg(action);
    base::LaunchOptions options;
    options.inherit_handles = true;
    options.stderr_handle = nul_;
    options.stdin_handle = nul_;
    options.stdout_handle = nul_;
    *process = base::LaunchProcess(cmd_line, options);
    DCHECK(process->IsValid());
  }

  void Start() {
    DCHECK(!process_.IsValid());

    if (nul_ == NULL) {
      nul_ = CreateFile(L"NUL", GENERIC_READ | GENERIC_WRITE, 0, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
      CHECK(nul_);
    }

    log_file_ = temp_dir_.Append(L"integration_test.log");

    std::wstring start_event_name(L"syzygy-logger-started-");
    start_event_name += base::ASCIIToUTF16(instance_id_);
    base::win::ScopedHandle start_event(
        ::CreateEvent(NULL, FALSE, FALSE, start_event_name.c_str()));

    RunAction("start", &process_);

    ::WaitForSingleObject(start_event.Get(), INFINITE);
  }

  void Stop() {
    DCHECK(process_.IsValid());

    base::Process process;
    RunAction("stop", &process);
    int exit_code = 0;
    CHECK(process.WaitForExit(&exit_code));
    CHECK(process_.WaitForExit(&exit_code));

    // Read the contents of the log file.
    if (base::PathExists(log_file_))
      CHECK(base::ReadFileToString(log_file_, &log_contents_));
  }

  void GetLog(std::string* log) {
    DCHECK_NE(static_cast<std::string*>(nullptr), log);
    *log = log_contents_;
  }

  // Initialized at construction.
  base::FilePath agent_logger_;
  std::string instance_id_;

  // The temp directory used by this logger. This is owned by the object that
  // owns this logger.
  base::FilePath temp_dir_;

  // Modified by Start and Stop.
  base::FilePath log_file_;
  base::Process process_;
  HANDLE nul_;

  // Modified by Stop.
  std::string log_contents_;
};

enum AccessMode {
  ASAN_READ_ACCESS = agent::asan::ASAN_READ_ACCESS,
  ASAN_WRITE_ACCESS = agent::asan::ASAN_WRITE_ACCESS,
  ASAN_UNKNOWN_ACCESS = agent::asan::ASAN_UNKNOWN_ACCESS,
};

enum BadAccessKind {
  UNKNOWN_BAD_ACCESS = agent::asan::UNKNOWN_BAD_ACCESS,
  USE_AFTER_FREE = agent::asan::USE_AFTER_FREE,
  HEAP_BUFFER_OVERFLOW = agent::asan::HEAP_BUFFER_OVERFLOW,
  HEAP_BUFFER_UNDERFLOW = agent::asan::HEAP_BUFFER_UNDERFLOW,
  CORRUPT_BLOCK = agent::asan::CORRUPT_BLOCK,
  CORRUPT_HEAP = agent::asan::CORRUPT_HEAP,
};

// Contains the number of Asan errors reported with our callback.
int asan_error_count;
// Contains the last Asan error reported.
agent::asan::AsanErrorInfo last_asan_error;

void AsanCallback(agent::asan::AsanErrorInfo* info) {
  asan_error_count++;
  last_asan_error = *info;
  // We want to prevent write errors from corrupting the underlying block hence
  // we stop the flow of execution by raising an exception. The faulty calls are
  // themselves wrapped in try/catch statements, and continue executing
  // afterwards. Thus, they clean up after themselves.
  //
  // In the case of block corruption we elect to allow the code to continue
  // executing so that the normal code path is taken. If we raise an exception
  // this actually prevents the AsanHeap cleanup code from continuing, and we
  // leak memory.
  if (info->error_type != CORRUPT_BLOCK)
    ::RaiseException(EXCEPTION_ARRAY_BOUNDS_EXCEEDED, 0, 0, NULL);
}

void ResetAsanErrors() {
  asan_error_count = 0;
}

HMODULE GetAsanModule() {
  HMODULE asan_module = GetModuleHandle(L"syzyasan_rtl.dll");
  return asan_module;
}

void SetAsanDefaultCallBack(AsanErrorCallBack callback) {
  typedef void (WINAPI *AsanSetCallBack)(AsanErrorCallBack);

  HMODULE asan_module = GetAsanModule();
  DCHECK(asan_module != NULL);
  AsanSetCallBack set_callback = reinterpret_cast<AsanSetCallBack>(
      ::GetProcAddress(asan_module, "asan_SetCallBack"));
  DCHECK(set_callback != NULL);

  set_callback(callback);
}

agent::asan::OnExceptionCallback on_exception_callback;

void DispatchOnExceptionCallback(EXCEPTION_POINTERS* e) {
  if (!on_exception_callback.is_null())
    on_exception_callback.Run(e);
}

void SetOnExceptionCallback(agent::asan::OnExceptionCallback callback) {
  typedef void (*OnExceptionCallback)(EXCEPTION_POINTERS*);
  typedef void (WINAPI *SetOnExceptionCallback)(OnExceptionCallback);

  HMODULE asan_module = GetAsanModule();
  DCHECK(asan_module != NULL);
  SetOnExceptionCallback set_callback =
      reinterpret_cast<SetOnExceptionCallback>(
          ::GetProcAddress(asan_module, "asan_SetOnExceptionCallback"));
  DCHECK(set_callback != NULL);

  if (callback.is_null()) {
    set_callback(nullptr);
    on_exception_callback.Reset();
  } else {
    set_callback(&DispatchOnExceptionCallback);
    on_exception_callback = callback;
  }
}

agent::asan::AsanRuntime* GetActiveAsanRuntime() {
  HMODULE asan_module = GetAsanModule();
  DCHECK(asan_module != NULL);

  typedef agent::asan::AsanRuntime* (WINAPI *AsanGetActiveRuntimePtr)();
  AsanGetActiveRuntimePtr asan_get_active_runtime =
      reinterpret_cast<AsanGetActiveRuntimePtr>(
      ::GetProcAddress(asan_module, "asan_GetActiveRuntime"));
  DCHECK_NE(reinterpret_cast<AsanGetActiveRuntimePtr>(NULL),
            asan_get_active_runtime);

  return (*asan_get_active_runtime)();
}

// Filters non-continuable exceptions in the given module.
int FilterExceptionsInModule(HMODULE module,
                             unsigned int code,
                             struct _EXCEPTION_POINTERS* ep) {
  // Do a basic sanity check on the input parameters.
  if (module == NULL ||
      code != EXCEPTION_NONCONTINUABLE_EXCEPTION ||
      ep == NULL ||
      ep->ContextRecord == NULL ||
      ep->ExceptionRecord == NULL) {
    return EXCEPTION_CONTINUE_SEARCH;
  }

  // Get the module extents in memory.
  base::win::PEImage image(module);
  uint8_t* module_start = reinterpret_cast<uint8_t*>(module);
  uint8_t* module_end =
      module_start + image.GetNTHeaders()->OptionalHeader.SizeOfImage;

  // Filter exceptions where the return address originates from within the
  // instrumented module.
  uint8_t** ebp = reinterpret_cast<uint8_t**>(ep->ContextRecord->Ebp);
  uint8_t* ret = ebp[1];
  if (ret >= module_start && ret < module_end)
    return EXCEPTION_EXECUTE_HANDLER;

  return EXCEPTION_CONTINUE_SEARCH;
}

typedef std::map<std::string, FARPROC> ImportMap;
bool OnImport(const base::win::PEImage& image,
              LPCSTR module,
              DWORD ordinal,
              LPCSTR name,
              DWORD hint,
              PIMAGE_THUNK_DATA iat,
              PVOID cookie) {
  if (name == nullptr) {
    // This is an ordinal import.
    return true;
  }

  ImportMap* imports = reinterpret_cast<ImportMap*>(cookie);
  imports->insert(
      std::make_pair(name, reinterpret_cast<FARPROC>(iat->u1.Function)));
  return true;
}

bool GetModuleNamedImports(HMODULE module, ImportMap* imports) {
  base::win::PEImage image(module);
  if (!image.VerifyMagic())
    return false;

  return image.EnumAllImports(OnImport, imports);
}

class TestingProfileGrinder : public grinder::grinders::ProfileGrinder {
 public:
  // Expose for testing.
  typedef grinder::grinders::ProfileGrinder::InvocationNodeMap
      InvocationNodeMap;
  typedef grinder::grinders::ProfileGrinder::ModuleInformationSet
      ModuleInformationSet;

  using grinder::grinders::ProfileGrinder::PartData;
  using grinder::grinders::ProfileGrinder::PartDataMap;
  using grinder::grinders::ProfileGrinder::PartKey;

  using grinder::grinders::ProfileGrinder::modules_;
  using grinder::grinders::ProfileGrinder::parts_;
};

enum InstrumentationMode {
  SYZYGY,
  CLANG,
};

class LenientInstrumentAppIntegrationTest : public testing::PELibUnitTest {
 public:
  typedef testing::PELibUnitTest Super;

  // A callback that gets hooked up to catch exceptions in the RTL.
  MOCK_METHOD1(OnExceptionCallback, void(EXCEPTION_POINTERS*));

  LenientInstrumentAppIntegrationTest()
      : cmd_line_(base::FilePath(L"instrument.exe")),
        test_impl_(test_app_.implementation()),
        image_layout_(&block_graph_),
        get_my_rva_(NULL) {
  }

  void SetUp() {
    Super::SetUp();

    // Several of the tests generate progress and (deliberate) error messages
    // that would otherwise clutter the unittest output.
    logging::SetMinLogLevel(logging::LOG_FATAL);

    // Setup the IO streams.
    this->CreateTemporaryDir(&temp_dir_);
    stdin_path_ = temp_dir_.Append(L"NUL");
    stdout_path_ = temp_dir_.Append(L"stdout.txt");
    stderr_path_ = temp_dir_.Append(L"stderr.txt");
    InitStreams(stdin_path_, stdout_path_, stderr_path_);

    // Initialize the (potential) input and output path values.
    base::FilePath abs_input_dll_path_ =
        testing::GetExeRelativePath(testing::kIntegrationTestsDllName);
    input_dll_path_ = testing::GetRelativePath(abs_input_dll_path_);
    test_dll_path_ = temp_dir_.Append(input_dll_path_.BaseName());

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
    ResetEnvironment();
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

  // Restore the environment as it was before altering it.
  void ResetEnvironment() {
    // Remove the alterations in reverse order of creation.
    while (env_alterations_.size())
      env_alterations_.pop_back();
  }

  // Alter the environment by setting the environment variable |name| to
  // |value|.
  void AddEnvironmentChange(const char* name, const char* value) {
    env_alterations_.push_back(
        base::WrapUnique(new testing::ScopedEnvironmentVariable(name, value)));
  }

  void StartService() {
    service_.Start(traces_dir_);
  }

  void StopService() {
    service_.Stop();
  }

  void UnloadDll() {
    module_.Reset(NULL);
  }

  // Runs an instrumentation pass in the given mode and validates that the
  // resulting output DLL loads.
  virtual void EndToEndTest(const std::string& mode) {
    cmd_line_.AppendSwitchPath("input-image", input_dll_path_);
    cmd_line_.AppendSwitchPath("output-image", test_dll_path_);
    cmd_line_.AppendSwitchASCII("mode", mode);

    // Create the instrumented DLL.
    application::Application<instrument::InstrumentApp> app;
    ASSERT_NO_FATAL_FAILURE(ConfigureTestApp(&app));
    ASSERT_EQ(0, app.Run());

    // Validate that the test dll loads post instrumentation.
    ASSERT_NO_FATAL_FAILURE(LoadTestDll(test_dll_path_, &module_));
  }

  // Invoke a test function inside test_dll by addressing it with a test id.
  // Returns the value resulting from the test function execution.
  unsigned int InvokeTestDllFunction(testing::EndToEndTestId test) {
    // Load the exported 'function_name' function.
    typedef unsigned int (CALLBACK* TestDllFuncs)(unsigned int);
    TestDllFuncs func = reinterpret_cast<TestDllFuncs>(
        ::GetProcAddress(module_, "EndToEndTest"));
    DCHECK(func != NULL);

    // Invoke it, and returns its value.
    return func(test);
  }

  int RunOutOfProcessFunction(const base::string16& harness_name,
                              testing::EndToEndTestId test,
                              bool expect_exception) {
    base::FilePath harness = testing::GetExeRelativePath(harness_name.c_str());
    base::CommandLine cmd_line(harness);
    cmd_line.AppendSwitchASCII("test", base::StringPrintf("%d", test));
    cmd_line.AppendSwitchPath("dll", test_dll_path_);
    if (expect_exception)
      cmd_line.AppendSwitch("expect-exception");

    base::LaunchOptions options;
    base::Process process = base::LaunchProcess(cmd_line, options);
    EXPECT_TRUE(process.IsValid());

    int exit_code = 0;
    EXPECT_TRUE(process.WaitForExit(&exit_code));
    return exit_code;
  }

  // Runs an asan error check in an external process, invoking the test via the
  // integration test harness.
  void OutOfProcessAsanErrorCheck(testing::EndToEndTestId test,
                                  bool expect_exception,
                                  std::string* log) {
    DCHECK_NE(static_cast<std::string*>(nullptr), log);

    // If running under the debugger then don't do this test. The debugger's
    // exception handler prevents this from completing as expected.
    if (expect_exception && ::IsDebuggerPresent())
      return;

    ScopedAgentLogger logger(temp_dir_);
    logger.Start();

    std::unique_ptr<base::Environment> env(base::Environment::Create());
    CHECK_NE(static_cast<base::Environment*>(nullptr), env.get());

    // Update the instance ID environment variable to specifically aim the
    // Asan RTL to the agent logger we are running. We have to be careful not
    // to influence other RPC settings so as not to break coverage support.
    base::FilePath agent = testing::GetExeRelativePath(L"syzyasan_rtl.dll");
    std::string instance_id = base::WideToUTF8(agent.value());
    instance_id.append(",");
    instance_id.append(logger.instance_id_);
    bool had_instance_id = false;
    std::string orig_instance_id;
    had_instance_id = env->GetVar(kSyzygyRpcInstanceIdEnvVar,
                                  &orig_instance_id);
    if (had_instance_id) {
      instance_id.append(";");
      instance_id.append(orig_instance_id);
    }
    AddEnvironmentChange(kSyzygyRpcInstanceIdEnvVar, instance_id.c_str());

    int exit_code = RunOutOfProcessFunction(L"integration_tests_harness.exe",
                                            test, expect_exception);
    EXPECT_EQ(0, exit_code);
    logger.Stop();

    logger.GetLog(log);
  }

  void OutOfProcessAsanErrorCheckAndValidateLog(
      testing::EndToEndTestId test,
      bool expect_exception,
      const base::StringPiece& log_message_1,
      const base::StringPiece& log_message_2) {
    // If running under the debugger then don't do this test. The debugger's
    // exception handler prevents this from completing as expected.
    if (expect_exception && ::IsDebuggerPresent())
      return;

    std::string log;
    OutOfProcessAsanErrorCheck(test, expect_exception, &log);

    if (!expect_exception)
      return;
    // Check the log for any messages that are expected.
    if (!log_message_1.empty()) {
      EXPECT_NE(std::string::npos, log.find(log_message_1.as_string()))
          << "Expected to find '" << log_message_1 << "' in logs: " << log;
    }
    if (!log_message_2.empty()) {
      EXPECT_NE(std::string::npos, log.find(log_message_2.as_string()))
          << "Expected to find '" << log_message_2 << "' in logs: " << log;
    }
  }

  void CheckTestDllImportsRedirected() {
    HMODULE rtl = GetAsanModule();
    ASSERT_NE(static_cast<HMODULE>(nullptr), rtl);

    ImportMap imports;
    ASSERT_TRUE(GetModuleNamedImports(module_, &imports));
    for (auto pair : imports) {
      const std::string& name = pair.first;
      const FARPROC imported_fn = pair.second;

      // Is this an instrumentation import?
      const bool is_asan_fn =
          base::StartsWith(name, "asan_", base::CompareCase::SENSITIVE);
      if (!is_asan_fn)
        continue;

      // Retrieve the corresponding export on the instrumentation DLL.
      FARPROC rtl_export_fn = ::GetProcAddress(rtl, name.c_str());

      // Is it a memory accessor?
      const bool is_asan_check_fn =
          base::StartsWith(name, "asan_check", base::CompareCase::SENSITIVE);
      if (is_asan_check_fn) {
        // Memory acessors in the dynamic RTL must be redirected after first
        // use of the function. If the dynamic RTL doesn't redirect the imports
        // everything will still work, just terribly slowly.
        ASSERT_NE(rtl_export_fn, imported_fn);
      } else {
        ASSERT_EQ(rtl_export_fn, imported_fn);
      }
    }
  }

  virtual void EndToEndCheckTestDll() {
    // Validate that behavior is unchanged after instrumentation.
    EXPECT_EQ(0xfff80200, InvokeTestDllFunction(testing::kArrayComputation1));
    EXPECT_EQ(0x00000200, InvokeTestDllFunction(testing::kArrayComputation2));
  }

  bool AsanErrorCheck(testing::EndToEndTestId test,
                      BadAccessKind kind,
                      AccessMode mode,
                      size_t size,
                      size_t max_tries,
                      bool unload) {
    // A small selection of tests can fail due to hash collisions. These are
    // run repeatedly and expected to pass at least once. Every other test is
    // run with max_tries == 1.
    if (max_tries != 1) {
      // Ensure that only the desired tests are being run with retries. This is
      // a second layer of safety to make sure that flaky tests aren't simply
      // being hidden.
      EXPECT_TRUE(test == testing::kAsanCorruptBlock ||
                  test == testing::kAsanCorruptBlockInQuarantine);
    }

    ResetAsanErrors();
    EXPECT_NO_FATAL_FAILURE(SetAsanDefaultCallBack(AsanCallback));

    // Hook up the OnException callback to the test fixture.
    SetOnExceptionCallback(base::Bind(
        &LenientInstrumentAppIntegrationTest::OnExceptionCallback,
        base::Unretained(this)));

    for (size_t i = 0; i < max_tries; ++i) {
      InvokeTestDllFunction(test);
      if (unload)
        UnloadDll();

      // If this appears to have failed then retry it for all but the last
      // attempt. Some tests have a non-zero chance of failure, but their
      // chances of failing repeatedly are infinitesimally small.
      if (asan_error_count == 0 && i + 1 < max_tries) {
        // If the module was unloaded and the test is retrying, then reload it.
        if (unload)
          EXPECT_NO_FATAL_FAILURE(LoadTestDll(test_dll_path_, &module_));
        continue;
      }

      if (asan_error_count == 0 ||
          last_asan_error.error_type != kind ||
          last_asan_error.access_mode != mode ||
          last_asan_error.access_size != size) {
        return false;
      }
      break;
    }

    // Clear any expectations on this fixture.
    testing::Mock::VerifyAndClearExpectations(this);

    return true;
  }

  bool FilteredAsanErrorCheck(testing::EndToEndTestId test,
                              BadAccessKind kind,
                              AccessMode mode,
                              size_t size,
                              size_t max_tries,
                              bool unload) {
    __try {
      return AsanErrorCheck(test, kind, mode, size, max_tries, unload);
    } __except (FilterExceptionsInModule(module_,  // NOLINT
                                         GetExceptionCode(),
                                         GetExceptionInformation())) {
      // If the exception is of the expected type and originates from the
      // instrumented module, then we indicate that no Asan error was
      // detected.
      return false;
    }
  }

  void AsanErrorCheckTestDll() {
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanRead8BufferOverflow,
        HEAP_BUFFER_OVERFLOW, ASAN_READ_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanRead16BufferOverflow,
        HEAP_BUFFER_OVERFLOW, ASAN_READ_ACCESS, 2, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanRead32BufferOverflow,
        HEAP_BUFFER_OVERFLOW, ASAN_READ_ACCESS, 4, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanRead64BufferOverflow,
        HEAP_BUFFER_OVERFLOW, ASAN_READ_ACCESS, 8, 1, false));

    EXPECT_TRUE(AsanErrorCheck(testing::kAsanRead8BufferUnderflow,
        HEAP_BUFFER_UNDERFLOW, ASAN_READ_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanRead16BufferUnderflow,
        HEAP_BUFFER_UNDERFLOW, ASAN_READ_ACCESS, 2, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanRead32BufferUnderflow,
        HEAP_BUFFER_UNDERFLOW, ASAN_READ_ACCESS, 4, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanRead64BufferUnderflow,
        HEAP_BUFFER_UNDERFLOW, ASAN_READ_ACCESS, 8, 1, false));

    EXPECT_TRUE(AsanErrorCheck(testing::kAsanWrite8BufferOverflow,
        HEAP_BUFFER_OVERFLOW, ASAN_WRITE_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanWrite16BufferOverflow,
        HEAP_BUFFER_OVERFLOW, ASAN_WRITE_ACCESS, 2, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanWrite32BufferOverflow,
        HEAP_BUFFER_OVERFLOW, ASAN_WRITE_ACCESS, 4, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanWrite64BufferOverflow,
        HEAP_BUFFER_OVERFLOW, ASAN_WRITE_ACCESS, 8, 1, false));

    EXPECT_TRUE(AsanErrorCheck(testing::kAsanWrite8BufferUnderflow,
        HEAP_BUFFER_UNDERFLOW, ASAN_WRITE_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanWrite16BufferUnderflow,
        HEAP_BUFFER_UNDERFLOW, ASAN_WRITE_ACCESS, 2, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanWrite32BufferUnderflow,
        HEAP_BUFFER_UNDERFLOW, ASAN_WRITE_ACCESS, 4, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanWrite64BufferUnderflow,
        HEAP_BUFFER_UNDERFLOW, ASAN_WRITE_ACCESS, 8, 1, false));

    EXPECT_TRUE(AsanErrorCheck(testing::kAsanRead8UseAfterFree,
        USE_AFTER_FREE, ASAN_READ_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanRead16UseAfterFree,
        USE_AFTER_FREE, ASAN_READ_ACCESS, 2, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanRead32UseAfterFree,
        USE_AFTER_FREE, ASAN_READ_ACCESS, 4, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanRead64UseAfterFree,
        USE_AFTER_FREE, ASAN_READ_ACCESS, 8, 1, false));

    EXPECT_TRUE(AsanErrorCheck(testing::kAsanWrite8UseAfterFree,
        USE_AFTER_FREE, ASAN_WRITE_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanWrite16UseAfterFree,
        USE_AFTER_FREE, ASAN_WRITE_ACCESS, 2, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanWrite32UseAfterFree,
        USE_AFTER_FREE, ASAN_WRITE_ACCESS, 4, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanWrite64UseAfterFree,
        USE_AFTER_FREE, ASAN_WRITE_ACCESS, 8, 1, false));
  }

  void AsanErrorCheckSampledAllocations() {
    // This assumes we have a 50% allocation sampling rate.

    // Run Asan tests over and over again until we've done enough of them. We
    // only check the read operations as the writes may actually cause
    // corruption if not caught.
    size_t good = 0;
    size_t test = 0;
    while (test < 1000) {
      good += FilteredAsanErrorCheck(testing::kAsanRead8BufferOverflow,
          HEAP_BUFFER_OVERFLOW, ASAN_READ_ACCESS, 1, 1, false) ? 1 : 0;
      good += FilteredAsanErrorCheck(testing::kAsanRead16BufferOverflow,
          HEAP_BUFFER_OVERFLOW, ASAN_READ_ACCESS, 2, 1, false) ? 1 : 0;
      good += FilteredAsanErrorCheck(testing::kAsanRead32BufferOverflow,
          HEAP_BUFFER_OVERFLOW, ASAN_READ_ACCESS, 4, 1, false) ? 1 : 0;
      good += FilteredAsanErrorCheck(testing::kAsanRead64BufferOverflow,
          HEAP_BUFFER_OVERFLOW, ASAN_READ_ACCESS, 8, 1, false) ? 1 : 0;
      test += 4;

      good += FilteredAsanErrorCheck(testing::kAsanRead8BufferUnderflow,
          HEAP_BUFFER_UNDERFLOW, ASAN_READ_ACCESS, 1, 1, false) ? 1 : 0;
      good += FilteredAsanErrorCheck(testing::kAsanRead16BufferUnderflow,
          HEAP_BUFFER_UNDERFLOW, ASAN_READ_ACCESS, 2, 1, false) ? 1 : 0;
      good += FilteredAsanErrorCheck(testing::kAsanRead32BufferUnderflow,
          HEAP_BUFFER_UNDERFLOW, ASAN_READ_ACCESS, 4, 1, false) ? 1 : 0;
      good += FilteredAsanErrorCheck(testing::kAsanRead64BufferUnderflow,
          HEAP_BUFFER_UNDERFLOW, ASAN_READ_ACCESS, 8, 1, false) ? 1 : 0;
      test += 4;
    }

    // We expect half of the bugs to have been found, as the allocations are
    // subsampled. With 1000 allocations this gives us 10 nines of confidence
    // that the detection rate will be within 50 +/- 10%.
    EXPECT_LE(4 * test / 10, good);
    EXPECT_GE(6 * test / 10, good);
  }

  void AsanErrorCheckInterceptedFunctions() {
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanMemsetOverflow,
        HEAP_BUFFER_OVERFLOW, ASAN_WRITE_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanMemsetUnderflow,
        HEAP_BUFFER_UNDERFLOW, ASAN_WRITE_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanMemsetUseAfterFree,
        USE_AFTER_FREE, ASAN_WRITE_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanMemchrOverflow,
        HEAP_BUFFER_OVERFLOW, ASAN_READ_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanMemchrUnderflow,
        HEAP_BUFFER_UNDERFLOW, ASAN_READ_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanMemchrUseAfterFree,
        USE_AFTER_FREE, ASAN_READ_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanMemmoveReadOverflow,
        HEAP_BUFFER_OVERFLOW, ASAN_READ_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanMemmoveReadUnderflow,
        HEAP_BUFFER_UNDERFLOW, ASAN_READ_ACCESS, 1, 1, false));
    // In this test both buffers passed to memmove have been freed, but as the
    // interceptor starts by checking the source buffer this use after free is
    // seen as an invalid read access.
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanMemmoveUseAfterFree,
        USE_AFTER_FREE, ASAN_READ_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanMemmoveWriteOverflow,
        HEAP_BUFFER_OVERFLOW, ASAN_WRITE_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanMemmoveWriteUnderflow,
        HEAP_BUFFER_UNDERFLOW, ASAN_WRITE_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanMemcpyReadOverflow,
        HEAP_BUFFER_OVERFLOW, ASAN_READ_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanMemcpyReadUnderflow,
        HEAP_BUFFER_UNDERFLOW, ASAN_READ_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanMemcpyUseAfterFree,
        USE_AFTER_FREE, ASAN_READ_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanMemcpyWriteOverflow,
        HEAP_BUFFER_OVERFLOW, ASAN_WRITE_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanMemcpyWriteUnderflow,
        HEAP_BUFFER_UNDERFLOW, ASAN_WRITE_ACCESS, 1, 1, false));

    EXPECT_TRUE(AsanErrorCheck(testing::kAsanStrlenOverflow,
        HEAP_BUFFER_OVERFLOW, ASAN_READ_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanStrlenUnderflow,
        HEAP_BUFFER_UNDERFLOW, ASAN_READ_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanStrlenUseAfterFree,
        USE_AFTER_FREE, ASAN_READ_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanStrnlenOverflow,
        HEAP_BUFFER_OVERFLOW, ASAN_READ_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanStrnlenUnderflow,
        HEAP_BUFFER_UNDERFLOW, ASAN_READ_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanStrnlenUseAfterFree,
        USE_AFTER_FREE, ASAN_READ_ACCESS, 1, 1, false));
    // TODO(chrisha): These should actually be indicated as 2 byte reads. This
    // needs to be fixed in the runtime.
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanWcsnlenOverflow,
        HEAP_BUFFER_OVERFLOW, ASAN_READ_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanWcsnlenUnderflow,
        HEAP_BUFFER_UNDERFLOW, ASAN_READ_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanWcsnlenUseAfterFree,
        USE_AFTER_FREE, ASAN_READ_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanStrrchrOverflow,
        HEAP_BUFFER_OVERFLOW, ASAN_READ_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanStrrchrUnderflow,
        HEAP_BUFFER_UNDERFLOW, ASAN_READ_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanStrrchrUseAfterFree,
        USE_AFTER_FREE, ASAN_READ_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanWcsrchrOverflow,
        HEAP_BUFFER_OVERFLOW, ASAN_READ_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanWcsrchrUnderflow,
        HEAP_BUFFER_UNDERFLOW, ASAN_READ_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanWcsrchrUseAfterFree,
        USE_AFTER_FREE, ASAN_READ_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanWcschrOverflow,
        HEAP_BUFFER_OVERFLOW, ASAN_READ_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanWcschrUnderflow,
        HEAP_BUFFER_UNDERFLOW, ASAN_READ_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanWcschrUseAfterFree,
        USE_AFTER_FREE, ASAN_READ_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanWcsstrKeysOverflow,
        HEAP_BUFFER_OVERFLOW, ASAN_READ_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanStrncpySrcOverflow,
        HEAP_BUFFER_OVERFLOW, ASAN_READ_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanStrncpySrcUnderflow,
        HEAP_BUFFER_UNDERFLOW, ASAN_READ_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanStrncpySrcUseAfterFree,
        USE_AFTER_FREE, ASAN_READ_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanStrncpyDstOverflow,
        HEAP_BUFFER_OVERFLOW, ASAN_WRITE_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanStrncpyDstUnderflow,
        HEAP_BUFFER_UNDERFLOW, ASAN_WRITE_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanStrncpyDstUseAfterFree,
        USE_AFTER_FREE, ASAN_WRITE_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanStrncatSuffixOverflow,
        HEAP_BUFFER_OVERFLOW, ASAN_READ_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanStrncatSuffixUnderflow,
        HEAP_BUFFER_UNDERFLOW, ASAN_READ_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanStrncatSuffixUseAfterFree,
        USE_AFTER_FREE, ASAN_READ_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanStrncatDstOverflow,
        HEAP_BUFFER_OVERFLOW, ASAN_WRITE_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanStrncatDstUnderflow,
        HEAP_BUFFER_UNDERFLOW, ASAN_WRITE_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanStrncatDstUseAfterFree,
        USE_AFTER_FREE, ASAN_WRITE_ACCESS, 1, 1, false));

    EXPECT_TRUE(AsanErrorCheck(testing::kAsanReadFileOverflow,
        HEAP_BUFFER_OVERFLOW, ASAN_WRITE_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanReadFileUseAfterFree,
        USE_AFTER_FREE, ASAN_WRITE_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanWriteFileOverflow,
        HEAP_BUFFER_OVERFLOW, ASAN_READ_ACCESS, 1, 1, false));
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanWriteFileUseAfterFree,
        USE_AFTER_FREE, ASAN_READ_ACCESS, 1, 1, false));

    EXPECT_TRUE(AsanErrorCheck(testing::kAsanCorruptBlock,
        CORRUPT_BLOCK, ASAN_UNKNOWN_ACCESS, 0, 10, false));

    // We need to force the module to unload so that the quarantine gets
    // cleaned up and fires off the error we're looking for.
    EXPECT_TRUE(AsanErrorCheck(testing::kAsanCorruptBlockInQuarantine,
        CORRUPT_BLOCK, ASAN_UNKNOWN_ACCESS, 0, 10, true));

    OutOfProcessAsanErrorCheckAndValidateLog(
        testing::kAsanMemcmpAccessViolation, true, kAsanHandlingException,
        nullptr);
  }

  void AsanLargeBlockHeapTests(bool expect_exception) {
    OutOfProcessAsanErrorCheckAndValidateLog(
        testing::kAsanReadLargeAllocationTrailerBeforeFree, expect_exception,
        kAsanAccessViolationLog, kAsanHeapBufferOverflow);
    OutOfProcessAsanErrorCheckAndValidateLog(
        testing::kAsanReadLargeAllocationBodyAfterFree, true,
        kAsanAccessViolationLog, kAsanHeapUseAfterFree);
  }

  void AsanZebraHeapTest(bool enabled);

  void BBEntryInvokeTestDll() {
    EXPECT_EQ(42, InvokeTestDllFunction(testing::kBBEntryCallOnce));
    EXPECT_EQ(42, InvokeTestDllFunction(testing::kBBEntryCallTree));
    EXPECT_EQ(42, InvokeTestDllFunction(testing::kBBEntryCallRecursive));
  }

  void ProfileInvokeTestDll() {
    EXPECT_EQ(5, InvokeTestDllFunction(testing::kProfileCallExport));
    // Save the RVA of one of the invoked functions for testing later.
    get_my_rva_ = InvokeTestDllFunction(testing::kProfileGetMyRVA);

    // The profiler will record the address of the first instruction of the
    // original function, which is six bytes past the start of the function
    // as seen by itself post-instrumentation.
    get_my_rva_ += 6;
  }

  uint32_t ProfileInvokeGetRVA() {
    return InvokeTestDllFunction(testing::kProfileGetMyRVA);
  }

  void QueueTraces(Parser* parser) {
    DCHECK(parser != NULL);

    // Queue up the trace file(s) we engendered.
    base::FileEnumerator enumerator(traces_dir_,
                                    false,
                                    base::FileEnumerator::FILES);
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

  int GetBlockFrequency(const IndexedFrequencyMap& frequencies,
                        const Block* block) {
    DCHECK(block != NULL);
    IndexedFrequencyMap::const_iterator entry =
        frequencies.find(std::make_pair(block->addr(), 0));
    if (entry == frequencies.end())
      return 0;
    return entry->second;
  }

  void ExpectFunctionFrequency(const IndexedFrequencyMap& frequencies,
                               const char* function_name,
                               int expected_frequency) {
    DCHECK(function_name != NULL);
    const Block* block = FindBlockWithName(function_name);
    ASSERT_TRUE(block != NULL);
    int exec_frequency = GetBlockFrequency(frequencies, block);
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
    grinder::grinders::IndexedFrequencyDataGrinder grinder;

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
    const ModuleIndexedFrequencyMap& module_entry_count =
        grinder.frequency_data_map();
    ASSERT_EQ(1u, module_entry_count.size());

    ModuleIndexedFrequencyMap::const_iterator entry_iter =
        module_entry_count.begin();
    const IndexedFrequencyInformation& info = entry_iter->second;
    const IndexedFrequencyMap& entry_count = info.frequency_map;

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

  void BranchCheckTestDll() {
    Parser parser;
    grinder::grinders::IndexedFrequencyDataGrinder grinder;

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
    const grinder::basic_block_util::ModuleIndexedFrequencyMap& module_map =
        grinder.frequency_data_map();
    ASSERT_EQ(1u, module_map.size());

    ModuleIndexedFrequencyMap::const_iterator entry_iter = module_map.begin();
    const IndexedFrequencyInformation& information = entry_iter->second;
    const IndexedFrequencyMap& frequency_map = information.frequency_map;

    // Decompose the output image.
    ASSERT_NO_FATAL_FAILURE(DecomposeImage());

    // Validate function entry counts.
    ASSERT_NO_FATAL_FAILURE(
        ExpectFunctionFrequency(frequency_map, "BBEntryCallOnce", 1));
    ASSERT_NO_FATAL_FAILURE(
        ExpectFunctionFrequency(frequency_map, "BBEntryCallTree", 1));
    ASSERT_NO_FATAL_FAILURE(
        ExpectFunctionFrequency(frequency_map, "BBEntryFunction1", 4));
    ASSERT_NO_FATAL_FAILURE(
        ExpectFunctionFrequency(frequency_map, "BBEntryFunction2", 2));
    ASSERT_NO_FATAL_FAILURE(
        ExpectFunctionFrequency(frequency_map, "BBEntryFunction3", 1));
    ASSERT_NO_FATAL_FAILURE(
        ExpectFunctionFrequency(frequency_map, "BBEntryCallRecursive", 1));
    ASSERT_NO_FATAL_FAILURE(
        ExpectFunctionFrequency(frequency_map, "BBEntryFunctionRecursive", 42));
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
    EXPECT_EQ(182, InvokeTestDllFunction(testing::kCoverage1));
    EXPECT_EQ(182, InvokeTestDllFunction(testing::kCoverage2));
    EXPECT_EQ(2, InvokeTestDllFunction(testing::kCoverage3));
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

    // Find file "coverage_tests.cc".
    SourceFileCoverageDataMap::const_iterator file = files.begin();
    const SourceFileCoverageData* data = NULL;
    for (; file != files.end(); ++file) {
      if (base::EndsWith(file->first, "coverage_tests.cc",
                         base::CompareCase::SENSITIVE)) {
        data = &file->second;
        break;
      }
    }
    ASSERT_TRUE(data != NULL);

    // Validate function entry counts.
    // Function: coverage_func1.
    EXPECT_TRUE(GetLineInfoExecution(data, 28));
    EXPECT_TRUE(GetLineInfoExecution(data, 29));

    // Function: coverage_func2.
    EXPECT_TRUE(GetLineInfoExecution(data, 35));
    EXPECT_TRUE(GetLineInfoExecution(data, 36));
    EXPECT_TRUE(GetLineInfoExecution(data, 37));
    EXPECT_FALSE(GetLineInfoExecution(data, 40));
    EXPECT_TRUE(GetLineInfoExecution(data, 42));

    // Function: coverage_func3.
    EXPECT_TRUE(GetLineInfoExecution(data, 47));
    EXPECT_FALSE(GetLineInfoExecution(data, 49));
    EXPECT_FALSE(GetLineInfoExecution(data, 50));
    EXPECT_TRUE(GetLineInfoExecution(data, 52));
    EXPECT_TRUE(GetLineInfoExecution(data, 54));
  }

  static bool ContainsString(const std::vector<std::wstring>& vec,
                             const wchar_t* str) {
    return std::find(vec.begin(), vec.end(), str) != vec.end();
  }

  void ProfileCheckTestDll(bool thunk_imports) {
    Parser parser;
    TestingProfileGrinder grinder;

    // Have the grinder aggregate all data to a single part.
    grinder.set_thread_parts(false);

    // Initialize trace parser.
    ASSERT_TRUE(parser.Init(&grinder));
    grinder.SetParser(&parser);

    // Add generated traces to the parser.
    QueueTraces(&parser);

    // Parse all traces.
    ASSERT_TRUE(parser.Consume());
    ASSERT_FALSE(parser.error_occurred());
    ASSERT_TRUE(grinder.Grind());

    const TestingProfileGrinder::ModuleInformationSet& modules =
        grinder.modules_;
    TestingProfileGrinder::ModuleInformationSet::const_iterator mod_it;
    std::vector<std::wstring> module_names;
    for (mod_it = modules.begin(); mod_it != modules.end(); ++mod_it) {
      base::FilePath image_name(mod_it->path);
      module_names.push_back(image_name.BaseName().value());
    }

    EXPECT_TRUE(ContainsString(module_names,
                               testing::kIntegrationTestsDllName));
    // If imports are thunked, we expect to find a module entry for the export
    // DLL - otherwise it shouldn't be in there at all.
    if (thunk_imports) {
      EXPECT_TRUE(ContainsString(module_names, L"export_dll.dll"));
    } else {
      EXPECT_FALSE(ContainsString(module_names, L"export_dll.dll"));
    }

    // Make sure at least one function we know of was hit.
    ASSERT_EQ(1U, grinder.parts_.size());
    const TestingProfileGrinder::PartData& data =
        grinder.parts_.begin()->second;

    TestingProfileGrinder::InvocationNodeMap::const_iterator node_it =
        data.nodes_.begin();
    for (; node_it != data.nodes_.end(); ++node_it) {
      if (node_it->second.function.rva() == get_my_rva_)
        return;
    }

    FAIL() << "Didn't find GetMyRVA function entry.";
  }

  // Helper function to test the Asan symbolizer script.
  //
  // It starts by running a test with the '--minidump_on_failure' flag turned
  // on and then verify that the generated minidump can be symbolized correctly.
  //
  // @param test_id The test to run.
  // @param kind The expected bad access kind.
  // @param mode The expected bad access mode.
  // @param size The expected bad access size.
  // @param expect_corrupt_heap Indicates if we expect the heap to be corrupt.
  void AsanSymbolizerTest(testing::EndToEndTestId test_id,
                          const char* kind,
                          const char* mode,
                          size_t size,
                          bool expect_corrupt_heap) {
    ASSERT_NO_FATAL_FAILURE(EndToEndTest("asan"));
    ASSERT_NO_FATAL_FAILURE(EndToEndCheckTestDll());

    // Make sure that a minidump gets produced by the logger when a bug occurs.
    std::unique_ptr<base::Environment> env(base::Environment::Create());
    ASSERT_NE(env.get(), nullptr);
    if (expect_corrupt_heap) {
      AddEnvironmentChange(::common::kSyzyAsanOptionsEnvVar,
                           "--minidump_on_failure");
    } else {
      AddEnvironmentChange(::common::kSyzyAsanOptionsEnvVar,
                           "--minidump_on_failure --no_check_heap_on_failure");
    }
    std::string log;

    // Run the test.
    OutOfProcessAsanErrorCheck(test_id, true, &log);

    // Look for the minidump path in the logger's output.
    pcrecpp::RE re("A minidump has been written to (.*\\.dmp)\\.\\n?");
    std::string minidump_path;
    EXPECT_TRUE(re.PartialMatch(log, &minidump_path));

    // Run the symbolizer tester script to make sure that the minidump gets
    // symbolized correctly.

    // The build scripts may set the wrong python path, so clear it here.
    env->UnSetVar("PYTHONPATH");

    base::CommandLine cmd_line(
        ::testing::GetSrcRelativePath(L"third_party/python_26/python.exe"));
    cmd_line.AppendArgPath(::testing::GetSrcRelativePath(
        L"syzygy/scripts/asan/minidump_symbolizer_tester.py"));
    cmd_line.AppendArg(base::StringPrintf("--minidump=%s",
        minidump_path.c_str()));
    cmd_line.AppendArg(base::StringPrintf("--bug-type=%s", kind));
    cmd_line.AppendArg(base::StringPrintf("--access-mode=%s", mode));
    cmd_line.AppendArg(base::StringPrintf("--access-size=%d", size));
    if (expect_corrupt_heap)
      cmd_line.AppendArg("--corrupt-heap");

    base::LaunchOptions options;
    options.inherit_handles = true;
    base::Process process = base::LaunchProcess(cmd_line, options);
    EXPECT_TRUE(process.IsValid());

    int exit_code = 0;
    EXPECT_TRUE(process.WaitForExit(&exit_code));
    EXPECT_EQ(0u, exit_code);

    // Check if the minidump contains a valid protobuf.
    poirot::MinidumpProcessor poirot_processor(
        base::FilePath::FromUTF8Unsafe(minidump_path));
    EXPECT_TRUE(poirot_processor.ProcessDump());
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
  base::CommandLine cmd_line_;
  base::FilePath input_dll_path_;
  base::FilePath test_dll_path_;
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
  uint32_t get_my_rva_;

  // The alterations made to the environment, must be destructed from end to
  // beginning.
  std::vector<std::unique_ptr<testing::ScopedEnvironmentVariable>>
      env_alterations_;
};

// Class created to enable parametrization of the tests with Clang.
// Currently only Syzygy is supported but will be extended to work with CLANG.
// Right now it just forwards the calls to the parent class.
class ParametrizedLenientInstrumentAppIntegrationTest
    : public LenientInstrumentAppIntegrationTest,
      public ::testing::WithParamInterface<InstrumentationMode> {
 public:
  void EndToEndTest(const std::string& mode) override {
    if (GetParam() == SYZYGY) {
      LenientInstrumentAppIntegrationTest::EndToEndTest(mode);
    } else if (GetParam() == CLANG) {
      test_dll_path_ =
          testing::GetExeRelativePath(testing::kIntegrationTestsClangDllName);
      // Validates that the test dll loads post instrumentation.
      ASSERT_NO_FATAL_FAILURE(LoadTestDll(test_dll_path_, &module_));
    }
  }

  void EndToEndCheckTestDll() override {
    if (GetParam() == SYZYGY) {
      LenientInstrumentAppIntegrationTest::EndToEndCheckTestDll();
    }
  }
};

typedef testing::StrictMock<ParametrizedLenientInstrumentAppIntegrationTest>
    ParametrizedInstrumentAppIntegrationTest;

typedef testing::StrictMock<LenientInstrumentAppIntegrationTest>
    InstrumentAppIntegrationTest;

typedef std::map<std::string, size_t> FunctionOffsetMap;

// A utility transform for extracting call site offsets from blocks.
// Used by GetCallOffsets and ZebraBlockHeap tests.
class ExtractCallTransform
    : public block_graph::BasicBlockSubGraphTransformInterface {
 public:
  explicit ExtractCallTransform(FunctionOffsetMap* map) : map_(map) { }
  virtual ~ExtractCallTransform() { }
  virtual const char* name() const { return "ExtractCallTransform"; }

  virtual bool TransformBasicBlockSubGraph(
      const block_graph::TransformPolicyInterface* policy,
      block_graph::BlockGraph* block_graph,
      block_graph::BasicBlockSubGraph* basic_block_subgraph) {
    for (auto& desc : basic_block_subgraph->block_descriptions()) {
      auto map_it = map_->find(desc.name);
      if (map_it == map_->end())
        continue;

      // Set this to effectively 'infinite' to start with.
      map_it->second = static_cast<size_t>(-1);

      for (auto& bb : desc.basic_block_order) {
        block_graph::BasicCodeBlock* bcb =
            block_graph::BasicCodeBlock::Cast(bb);
        if (bcb == nullptr)
          continue;

        size_t offset = bcb->offset();
        for (auto& inst : bcb->instructions()) {
          offset += inst.size();
          if (inst.IsCall()) {
            map_it->second = std::min(map_it->second, offset);
          }
        }
      }
    }

    return true;
  }

 protected:
  FunctionOffsetMap* map_;
};

// Gets the offsets of the first call from each function named in |map|,
// as found in the image at |image_path|. Updates the map with the offsets.
void GetCallOffsets(const base::FilePath& image_path,
                    FunctionOffsetMap* map) {
  pe::PEFile pe_file;
  ASSERT_TRUE(pe_file.Init(image_path));
  block_graph::BlockGraph bg;
  block_graph::BlockGraph::Block* header = NULL;

  // Decompose the image.
  {
    pe::ImageLayout image_layout(&bg);
    pe::Decomposer decomposer(pe_file);
    ASSERT_TRUE(decomposer.Decompose(&image_layout));
    header = image_layout.blocks.GetBlockByAddress(
        block_graph::BlockGraph::RelativeAddress(0));
  }

  // Apply the Asan transform.
  pe::PETransformPolicy policy;
  {
    instrument::transforms::AsanTransform tx;
    ASSERT_TRUE(block_graph::ApplyBlockGraphTransform(
        &tx, &policy, &bg, header));
  }

  // Apply our dummy transform which simply extracts call addresses.
  {
    ExtractCallTransform bbtx(map);
    block_graph::transforms::ChainedBasicBlockTransforms tx;
    tx.AppendTransform(&bbtx);
    ASSERT_TRUE(block_graph::ApplyBlockGraphTransform(
        &tx, &policy, &bg, header));
  }
}

void LenientInstrumentAppIntegrationTest::AsanZebraHeapTest(bool enabled) {
  // Find the offset of the call we want to instrument.
  static const char kTest1[] =
      "testing::AsanReadPageAllocationTrailerBeforeFree";
  static const char kTest2[] =
      "testing::AsanWritePageAllocationBodyAfterFree";
  FunctionOffsetMap map({{kTest1, -1}, {kTest2, -1}});
  ASSERT_NO_FATAL_FAILURE(GetCallOffsets(input_dll_path_, &map));

  // Create an allocation filter.
  base::FilePath filter_path = temp_dir_.AppendASCII("allocation_filter.json");
  std::string filter_contents = base::StringPrintf(
      "{\"hooks\":{\"%s\":[%d],\"%s\":[%d]}}",
      kTest1, map[kTest1], kTest2, map[kTest2]);
  base::WriteFile(
      filter_path, filter_contents.c_str(), filter_contents.size());

  // Configure the transform and test the binary.
  cmd_line_.AppendSwitchPath("allocation-filter-config-file", filter_path);
  std::string rtl_options = "--no_check_heap_on_failure";
  if (enabled)
    rtl_options += " --enable_zebra_block_heap --enable_allocation_filter";
  AddEnvironmentChange(::common::kSyzyAsanOptionsEnvVar, rtl_options.c_str());
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("asan"));
  ASSERT_NO_FATAL_FAILURE(EndToEndCheckTestDll());

  // Run tests that are specific to the zebra block heap.
  OutOfProcessAsanErrorCheckAndValidateLog(
      testing::kAsanReadPageAllocationTrailerBeforeFreeAllocation, enabled,
      kAsanAccessViolationLog, kAsanHeapBufferOverflow);
  OutOfProcessAsanErrorCheckAndValidateLog(
      testing::kAsanWritePageAllocationBodyAfterFree, enabled,
      kAsanAccessViolationLog, kAsanHeapUseAfterFree);
}

}  // namespace

TEST_P(ParametrizedInstrumentAppIntegrationTest, AsanEndToEnd) {
  // Disable the heap checking as this is implies touching all the shadow bytes
  // and this make those tests really slow.
  AddEnvironmentChange(::common::kSyzyAsanOptionsEnvVar,
                       "--no_check_heap_on_failure");
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("asan"));
  ASSERT_NO_FATAL_FAILURE(EndToEndCheckTestDll());
  ASSERT_NO_FATAL_FAILURE(AsanErrorCheckTestDll());
  ASSERT_NO_FATAL_FAILURE(CheckTestDllImportsRedirected());
}

TEST_P(ParametrizedInstrumentAppIntegrationTest, AsanEndToEndWithRtlOptions) {
  AddEnvironmentChange(
      ::common::kSyzyAsanOptionsEnvVar,
      "--quarantine_size=20000000 --quarantine_block_size=1000000 "
      "--no_check_heap_on_failure");
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("asan"));
  ASSERT_NO_FATAL_FAILURE(EndToEndCheckTestDll());
  ASSERT_NO_FATAL_FAILURE(AsanErrorCheckTestDll());

  // Get the active runtime and validate its parameters.
  agent::asan::AsanRuntime* runtime = GetActiveAsanRuntime();
  ASSERT_TRUE(runtime != NULL);
  ASSERT_EQ(20000000u, runtime->params().quarantine_size);
  ASSERT_EQ(1000000u, runtime->params().quarantine_block_size);
}

TEST_P(ParametrizedInstrumentAppIntegrationTest,
       AsanInvalidAccessWithCorruptAllocatedBlockHeader) {
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("asan"));
  ASSERT_NO_FATAL_FAILURE(EndToEndCheckTestDll());
  ASSERT_NO_FATAL_FAILURE(AsanErrorCheckTestDll());
  OutOfProcessAsanErrorCheckAndValidateLog(
      testing::kAsanInvalidAccessWithCorruptAllocatedBlockHeader, true,
      kAsanCorruptHeap, NULL);
}

TEST_P(ParametrizedInstrumentAppIntegrationTest,
       AsanOverflowCallsCrashForException) {
  // Asan-detected violations go through CrashForException if it is available.
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("asan"));
  ASSERT_NO_FATAL_FAILURE(EndToEndCheckTestDll());
  int exit_code =
      RunOutOfProcessFunction(L"crash_for_exception_harness.exe",
                              testing::kAsanRead8BufferOverflow, true);
  EXPECT_EQ(kExeCrashForExceptionExitCode, exit_code);
}

TEST_P(ParametrizedInstrumentAppIntegrationTest,
       AsanInvalidAccessWithCorruptAllocatedBlockTrailer) {
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("asan"));
  ASSERT_NO_FATAL_FAILURE(EndToEndCheckTestDll());
  OutOfProcessAsanErrorCheckAndValidateLog(
      testing::kAsanInvalidAccessWithCorruptAllocatedBlockTrailer, true,
      kAsanCorruptHeap, NULL);
}

TEST_P(ParametrizedInstrumentAppIntegrationTest,
       AsanInvalidAccessWithCorruptFreedBlock) {
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("asan"));
  ASSERT_NO_FATAL_FAILURE(EndToEndCheckTestDll());
  OutOfProcessAsanErrorCheckAndValidateLog(
      testing::kAsanInvalidAccessWithCorruptFreedBlock, true, kAsanCorruptHeap,
      NULL);
}

TEST_P(ParametrizedInstrumentAppIntegrationTest,
       AsanCorruptBlockWithPageProtections) {
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("asan"));
  ASSERT_NO_FATAL_FAILURE(EndToEndCheckTestDll());
  OutOfProcessAsanErrorCheckAndValidateLog(
      testing::kAsanCorruptBlockWithPageProtections, true,
      kAsanHeapUseAfterFree, kAsanCorruptHeap);
}

TEST_P(ParametrizedInstrumentAppIntegrationTest,
       SampledAllocationsAsanEndToEnd) {
  AddEnvironmentChange(::common::kSyzyAsanOptionsEnvVar,
                       "--allocation_guard_rate=0.5 "
                       "--no_check_heap_on_failure");
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("asan"));
  ASSERT_NO_FATAL_FAILURE(EndToEndCheckTestDll());
  ASSERT_NO_FATAL_FAILURE(AsanErrorCheckSampledAllocations());
}

TEST_P(ParametrizedInstrumentAppIntegrationTest,
       AsanLargeBlockHeapEnabledTest) {
  AddEnvironmentChange(::common::kSyzyAsanOptionsEnvVar,
                       "--no_check_heap_on_failure "
                       "--quarantine_size=4000000 "
                       "--quarantine_block_size=2000000");
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("asan"));
  ASSERT_NO_FATAL_FAILURE(EndToEndCheckTestDll());
  ASSERT_NO_FATAL_FAILURE(AsanLargeBlockHeapTests(true));
}

TEST_P(ParametrizedInstrumentAppIntegrationTest,
       AsanLargeBlockHeapDisabledTest) {
  AddEnvironmentChange(::common::kSyzyAsanOptionsEnvVar,
                       "--no_check_heap_on_failure "
                       "--disable_large_block_heap");
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("asan"));
  ASSERT_NO_FATAL_FAILURE(EndToEndCheckTestDll());
  ASSERT_NO_FATAL_FAILURE(AsanLargeBlockHeapTests(false));
}

TEST_P(ParametrizedInstrumentAppIntegrationTest,
       AsanSymbolizerTestAsanBufferOverflow) {
  AsanSymbolizerTest(testing::kAsanRead8BufferOverflow,
                     STRINGIFY(HEAP_BUFFER_OVERFLOW),
                     STRINGIFY(ASAN_READ_ACCESS),
                     1,
                     false);
}

TEST_P(ParametrizedInstrumentAppIntegrationTest,
       AsanSymbolizerTestAsanBufferUnderflow) {
  AsanSymbolizerTest(testing::kAsanWrite32BufferUnderflow,
                     STRINGIFY(HEAP_BUFFER_UNDERFLOW),
                     STRINGIFY(ASAN_WRITE_ACCESS),
                     4,
                     false);
}

TEST_P(ParametrizedInstrumentAppIntegrationTest,
       AsanSymbolizerTestAsanUseAfterFree) {
  AsanSymbolizerTest(testing::kAsanRead64UseAfterFree,
                     STRINGIFY(USE_AFTER_FREE),
                     STRINGIFY(ASAN_READ_ACCESS),
                     8,
                     false);
}

TEST_P(ParametrizedInstrumentAppIntegrationTest,
       AsanSymbolizerTestAsanCorruptBlock) {
  AsanSymbolizerTest(testing::kAsanCorruptBlock,
                     STRINGIFY(CORRUPT_BLOCK),
                     STRINGIFY(ASAN_UNKNOWN_ACCESS),
                     0,
                     false);
}

// These tests require corrupt heap checking to be enabled.
TEST_P(ParametrizedInstrumentAppIntegrationTest, AsanNearNullptrAccess) {
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("asan"));

  OutOfProcessAsanErrorCheckAndValidateLog(
      testing::kAsanNearNullptrAccessHeapCorruptionInstrumented, true,
      kAsanHandlingException, kAsanNearNullptrAccessHeapCorruption);
  OutOfProcessAsanErrorCheckAndValidateLog(
      testing::kAsanNearNullptrAccessHeapCorruptionUninstrumented, true,
      kAsanHandlingException, kAsanNearNullptrAccessHeapCorruption);
  OutOfProcessAsanErrorCheckAndValidateLog(
      testing::kAsanNearNullptrAccessNoHeapCorruptionInstrumented, true,
      kAsanHandlingException, kAsanNearNullptrAccessNoHeapCorruption);
  OutOfProcessAsanErrorCheckAndValidateLog(
      testing::kAsanNearNullptrAccessNoHeapCorruptionUninstrumented, true,
      kAsanHandlingException, kAsanNearNullptrAccessNoHeapCorruption);
  OutOfProcessAsanErrorCheckAndValidateLog(
      testing::kAsanNullptrAccessNoHeapCorruptionUninstrumented, true,
      kAsanHandlingException, kAsanNearNullptrAccessNoHeapCorruption);
}

INSTANTIATE_TEST_CASE_P(InstantiationName,
                        ParametrizedInstrumentAppIntegrationTest,
                        testing::Values(SYZYGY, CLANG));

TEST_F(InstrumentAppIntegrationTest, AsanEndToEndNoLiveness) {
  // Disable the heap checking as this is implies touching all the shadow bytes
  // and this make those tests really slow.
  AddEnvironmentChange(::common::kSyzyAsanOptionsEnvVar,
                       "--no_check_heap_on_failure");
  cmd_line_.AppendSwitch("no-liveness-analysis");
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("asan"));
  ASSERT_NO_FATAL_FAILURE(EndToEndCheckTestDll());
  ASSERT_NO_FATAL_FAILURE(AsanErrorCheckTestDll());
}

TEST_F(InstrumentAppIntegrationTest, AsanEndToEndNoRedundancyAnalysis) {
  // Disable the heap checking as this is implies touching all the shadow bytes
  // and this make those tests really slow.
  AddEnvironmentChange(::common::kSyzyAsanOptionsEnvVar,
                       "--no_check_heap_on_failure");
  cmd_line_.AppendSwitch("no-redundancy-analysis");
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("asan"));
  ASSERT_NO_FATAL_FAILURE(EndToEndCheckTestDll());
  ASSERT_NO_FATAL_FAILURE(AsanErrorCheckTestDll());
}

TEST_F(InstrumentAppIntegrationTest, AsanEndToEndNoFunctionInterceptors) {
  // Disable the heap checking as this is implies touching all the shadow bytes
  // and this make those tests really slow.
  AddEnvironmentChange(::common::kSyzyAsanOptionsEnvVar,
                       "--no_check_heap_on_failure");
  cmd_line_.AppendSwitch("no-interceptors");
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("asan"));
  ASSERT_NO_FATAL_FAILURE(EndToEndCheckTestDll());
  ASSERT_NO_FATAL_FAILURE(AsanErrorCheckTestDll());
}

TEST_F(InstrumentAppIntegrationTest,
       AsanEndToEndWithRtlOptionsOverrideWithEnvironment) {
  std::unique_ptr<base::Environment> env(base::Environment::Create());
  ASSERT_NE(env.get(), nullptr);
  env->SetVar(::common::kSyzyAsanOptionsEnvVar,
              "--quarantine_block_size=800000 --ignored_stack_ids=0x1 "
              "--no_check_heap_on_failure");
  cmd_line_.AppendSwitchASCII(
      common::kAsanRtlOptions,
      "--quarantine_size=20000000 --quarantine_block_size=1000000 "
      "--ignored_stack_ids=0x2");
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("asan"));
  ASSERT_NO_FATAL_FAILURE(EndToEndCheckTestDll());
  ASSERT_NO_FATAL_FAILURE(AsanErrorCheckTestDll());

  // Get the active runtime and validate its parameters.
  agent::asan::AsanRuntime* runtime = GetActiveAsanRuntime();
  ASSERT_TRUE(runtime != NULL);
  ASSERT_EQ(20000000u, runtime->params().quarantine_size);
  ASSERT_EQ(800000u, runtime->params().quarantine_block_size);
  ASSERT_THAT(runtime->params().ignored_stack_ids_set,
              testing::ElementsAre(0x1, 0x2));

  env->UnSetVar(::common::kSyzyAsanOptionsEnvVar);
}

TEST_F(InstrumentAppIntegrationTest, FullOptimizedAsanEndToEnd) {
  // Disable the heap checking as this implies touching all the shadow bytes
  // and this make these tests really slow.
  AddEnvironmentChange(::common::kSyzyAsanOptionsEnvVar,
                       "--no_check_heap_on_failure");
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("asan"));
  ASSERT_NO_FATAL_FAILURE(EndToEndCheckTestDll());
  ASSERT_NO_FATAL_FAILURE(AsanErrorCheckTestDll());
  ASSERT_NO_FATAL_FAILURE(AsanErrorCheckInterceptedFunctions());
}

TEST_F(InstrumentAppIntegrationTest,
       AsanSymbolizerTestAsanCorruptBlockInQuarantine) {
  // This test requires the HeapCreate/HeapDestroy functions to be intercepted
  // and thus doesn't work on a Clang instrumented binary.
  AsanSymbolizerTest(testing::kAsanCorruptBlockInQuarantine,
                     STRINGIFY(CORRUPT_BLOCK), STRINGIFY(ASAN_UNKNOWN_ACCESS),
                     0, true);
}

TEST_F(InstrumentAppIntegrationTest, AsanZebraHeapDisabledTest) {
  AsanZebraHeapTest(false);
}

TEST_F(InstrumentAppIntegrationTest, AsanZebraHeapEnabledTest) {
  AsanZebraHeapTest(true);
}

TEST_F(InstrumentAppIntegrationTest, BBEntryEndToEnd) {
  ASSERT_NO_FATAL_FAILURE(StartService());
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("bbentry"));
  ASSERT_NO_FATAL_FAILURE(EndToEndCheckTestDll());
  ASSERT_NO_FATAL_FAILURE(BBEntryInvokeTestDll());
  ASSERT_NO_FATAL_FAILURE(StopService());
  ASSERT_NO_FATAL_FAILURE(BBEntryCheckTestDll());
}

TEST_F(InstrumentAppIntegrationTest, BranchEndToEnd) {
  ASSERT_NO_FATAL_FAILURE(StartService());
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("branch"));
  ASSERT_NO_FATAL_FAILURE(EndToEndCheckTestDll());
  ASSERT_NO_FATAL_FAILURE(BBEntryInvokeTestDll());
  ASSERT_NO_FATAL_FAILURE(UnloadDll());
  ASSERT_NO_FATAL_FAILURE(StopService());
  ASSERT_NO_FATAL_FAILURE(BranchCheckTestDll());
}

TEST_F(InstrumentAppIntegrationTest, BranchWithBufferingEndToEnd) {
  cmd_line_.AppendSwitch("buffering");
  ASSERT_NO_FATAL_FAILURE(StartService());
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("branch"));
  ASSERT_NO_FATAL_FAILURE(EndToEndCheckTestDll());
  ASSERT_NO_FATAL_FAILURE(BBEntryInvokeTestDll());
  ASSERT_NO_FATAL_FAILURE(UnloadDll());
  ASSERT_NO_FATAL_FAILURE(StopService());
  ASSERT_NO_FATAL_FAILURE(BranchCheckTestDll());
}

TEST_F(InstrumentAppIntegrationTest, BranchWithSlotEndToEnd) {
  cmd_line_.AppendSwitchASCII("fs-slot", "1");
  ASSERT_NO_FATAL_FAILURE(StartService());
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("branch"));
  ASSERT_NO_FATAL_FAILURE(EndToEndCheckTestDll());
  ASSERT_NO_FATAL_FAILURE(BBEntryInvokeTestDll());
  ASSERT_NO_FATAL_FAILURE(UnloadDll());
  ASSERT_NO_FATAL_FAILURE(StopService());
  ASSERT_NO_FATAL_FAILURE(BranchCheckTestDll());
}

TEST_F(InstrumentAppIntegrationTest, BranchWithSlotAndBufferingEndToEnd) {
  cmd_line_.AppendSwitch("buffering");
  cmd_line_.AppendSwitchASCII("fs-slot", "1");
  ASSERT_NO_FATAL_FAILURE(StartService());
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("branch"));
  ASSERT_NO_FATAL_FAILURE(EndToEndCheckTestDll());
  ASSERT_NO_FATAL_FAILURE(BBEntryInvokeTestDll());
  ASSERT_NO_FATAL_FAILURE(UnloadDll());
  ASSERT_NO_FATAL_FAILURE(StopService());
  ASSERT_NO_FATAL_FAILURE(BranchCheckTestDll());
}

TEST_F(InstrumentAppIntegrationTest, CallTraceEndToEnd) {
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("calltrace"));
  ASSERT_NO_FATAL_FAILURE(EndToEndCheckTestDll());
}

TEST_F(InstrumentAppIntegrationTest, CoverageEndToEnd) {
  base::win::ScopedCOMInitializer scoped_com_initializer;
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
  base::win::ScopedCOMInitializer scoped_com_initializer;
  ASSERT_NO_FATAL_FAILURE(StartService());
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("bbentry"));
  ASSERT_NO_FATAL_FAILURE(EndToEndCheckTestDll());
  ASSERT_NO_FATAL_FAILURE(CoverageInvokeTestDll());
  ASSERT_NO_FATAL_FAILURE(StopService());
  ASSERT_NO_FATAL_FAILURE(CoverageCheckTestDll());
}

TEST_F(InstrumentAppIntegrationTest, ProfileEndToEnd) {
  ASSERT_NO_FATAL_FAILURE(StartService());
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("profile"));
  ASSERT_NO_FATAL_FAILURE(ProfileInvokeTestDll());
  ASSERT_NO_FATAL_FAILURE(UnloadDll());
  ASSERT_NO_FATAL_FAILURE(StopService());
  ASSERT_NO_FATAL_FAILURE(ProfileCheckTestDll(false));
}

TEST_F(InstrumentAppIntegrationTest, ProfileWithImportsEndToEnd) {
  cmd_line_.AppendSwitch("instrument-imports");
  ASSERT_NO_FATAL_FAILURE(StartService());
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("profile"));
  ASSERT_NO_FATAL_FAILURE(ProfileInvokeTestDll());
  ASSERT_NO_FATAL_FAILURE(UnloadDll());
  ASSERT_NO_FATAL_FAILURE(StopService());
  ASSERT_NO_FATAL_FAILURE(ProfileCheckTestDll(true));
}

TEST_F(InstrumentAppIntegrationTest, DeferredFreeTLS) {
  ASSERT_NO_FATAL_FAILURE(StartService());
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("asan"));
  ASSERT_EQ(0, InvokeTestDllFunction(testing::kAsanDeferredFreeTLS));
  ASSERT_NO_FATAL_FAILURE(UnloadDll());
  ASSERT_NO_FATAL_FAILURE(StopService());
}

}  // namespace integration_tests
