// Copyright 2015 Google Inc. All Rights Reserved.
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

#include "syzygy/refinery/analyzers/stack_analyzer.h"

#include <Windows.h>  // NOLINT
#include <DbgHelp.h>

#include <string>

#include "base/base_switches.h"
#include "base/command_line.h"
#include "base/logging.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/memory/scoped_ptr.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_piece.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "base/test/multiprocess_test.h"
#include "base/test/test_timeouts.h"
#include "base/threading/platform_thread.h"
#include "base/win/scoped_com_initializer.h"
#include "gtest/gtest.h"
#include "syzygy/common/com_utils.h"
#include "syzygy/common/unittest_util.h"
#include "syzygy/pe/unittest_util.h"
#include "syzygy/refinery/unittest_util.h"
#include "syzygy/refinery/analyzers/analysis_runner.h"
#include "syzygy/refinery/analyzers/exception_analyzer.h"
#include "syzygy/refinery/analyzers/memory_analyzer.h"
#include "syzygy/refinery/analyzers/module_analyzer.h"
#include "syzygy/refinery/analyzers/thread_analyzer.h"
#include "syzygy/refinery/minidump/minidump.h"
#include "syzygy/refinery/process_state/process_state.h"
#include "syzygy/refinery/process_state/process_state_util.h"
#include "syzygy/refinery/process_state/refinery.pb.h"
#include "testing/multiprocess_func_list.h"

namespace refinery {

namespace {

// Symbol path.
const wchar_t kLocalSymbolDir[] = L"symbols";
const char kNtSymbolPathPrefix[] = "SRV*";
const char kNtSymbolPathSuffixMicrosoft[] =
    "*http://msdl.microsoft.com/download/symbols";
const char kNtSymbolPathSuffixGoogle[] =
    "*https://chromium-browser-symsrv.commondatastorage.googleapis.com";

// Minidump.
const wchar_t kMinidumpFileName[] = L"minidump.dmp";
const char kSwitchExceptionPtrs[] = "exception-ptrs";
const char kSwitchPid[] = "dump-pid";
const char kSwitchMinidumpPath[] = "dump-path";
const char kSwitchTid[] = "exception-thread-id";
const MINIDUMP_TYPE kSmallDumpType = static_cast<MINIDUMP_TYPE>(
    MiniDumpWithProcessThreadData |  // Get PEB and TEB.
    MiniDumpWithUnloadedModules);    // Get unloaded modules when available.

__declspec(noinline) DWORD GetEip() {
  return reinterpret_cast<DWORD>(_ReturnAddress());
}

bool GetPathValueNarrow(const base::FilePath& path, std::string* value) {
  const std::wstring value_wide = path.value();
  return base::WideToUTF8(value_wide.c_str(), value_wide.length(), value);
}

bool GetNtSymbolPathValue(std::string* nt_symbol_path) {
  DCHECK(nt_symbol_path);

  base::FilePath output_path =
      testing::GetOutputRelativePath(L"").NormalizePathSeparators();

  // Build the local symbol directory path and ensure it exists.
  base::FilePath local_symbol_path = output_path.Append(kLocalSymbolDir);
  if (!base::CreateDirectory(local_symbol_path))
    return false;

  // Build the full symbol path.
  std::string output_path_str;
  if (!GetPathValueNarrow(output_path, &output_path_str))
    return false;

  std::string local_symbol_path_microsoft;
  if (!GetPathValueNarrow(local_symbol_path.Append(L"microsoft"),
                          &local_symbol_path_microsoft)) {
    return false;
  }
  std::string local_symbol_path_google;
  if (!GetPathValueNarrow(local_symbol_path.Append(L"google"),
                          &local_symbol_path_google)) {
    return false;
  }

  base::SStringPrintf(
      nt_symbol_path, "%s;%s%s%s;%s%s%s", output_path_str.c_str(),
      kNtSymbolPathPrefix, local_symbol_path_google.c_str(),
      kNtSymbolPathSuffixGoogle, kNtSymbolPathPrefix,
      local_symbol_path_microsoft.c_str(), kNtSymbolPathSuffixMicrosoft);

  return true;
}

}  // namespace

MULTIPROCESS_TEST_MAIN(MinidumpDumperProcess) {
  // Retrieve information from the command line.
  base::CommandLine* cmd_line = base::CommandLine::ForCurrentProcess();
  if (!cmd_line->HasSwitch(kSwitchPid) || !cmd_line->HasSwitch(kSwitchTid) ||
      !cmd_line->HasSwitch(kSwitchExceptionPtrs) ||
      !cmd_line->HasSwitch(kSwitchMinidumpPath)) {
    return 1;
  }

  std::string pid_string = cmd_line->GetSwitchValueASCII(kSwitchPid);
  unsigned pid_uint = 0U;
  if (!base::StringToUint(pid_string, &pid_uint))
    return 1;
  base::ProcessId pid = static_cast<base::ProcessId>(pid_uint);

  std::string thread_id_string = cmd_line->GetSwitchValueASCII(kSwitchTid);
  unsigned thread_id = 0U;
  if (!base::StringToUint(thread_id_string, &thread_id))
    return 1;

  std::string exception_ptrs_string =
      cmd_line->GetSwitchValueASCII(kSwitchExceptionPtrs);
  unsigned exception_ptrs = 0ULL;
  if (!base::StringToUint(exception_ptrs_string, &exception_ptrs))
    return 1;

  base::FilePath minidump_path =
      cmd_line->GetSwitchValuePath(kSwitchMinidumpPath);

  // Get handles to dumpee and dump file.
  base::Process dumpee_process = base::Process::OpenWithAccess(
      pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
  if (!dumpee_process.IsValid()) {
    LOG(ERROR) << "Failed to open process: " << ::common::LogWe() << ".";
    return 1;
  }

  base::File minidump_file(minidump_path,
                           base::File::FLAG_CREATE | base::File::FLAG_WRITE);
  if (!minidump_file.IsValid()) {
    LOG(ERROR) << "Failed to create minidump file: " << minidump_path.value();
    return 1;
  }

  // Build the dump related information.
  MINIDUMP_EXCEPTION_INFORMATION exception_information = {};
  exception_information.ThreadId = static_cast<DWORD>(thread_id);
  exception_information.ExceptionPointers =
      reinterpret_cast<PEXCEPTION_POINTERS>(exception_ptrs);
  exception_information.ClientPointers = true;

  MINIDUMP_USER_STREAM_INFORMATION* user_info = nullptr;
  MINIDUMP_CALLBACK_INFORMATION* callback_info = nullptr;

  // Take the minidump.
  if (::MiniDumpWriteDump(dumpee_process.Handle(), pid,
                          minidump_file.GetPlatformFile(), kSmallDumpType,
                          &exception_information, user_info,
                          callback_info) == FALSE) {
    LOG(ERROR) << "MiniDumpWriteDump failed: " << ::common::LogWe() << ".";
    return 1;
  }

  return 0;
}

class StackAnalyzerTest : public testing::Test {
 protected:
  void SetUp() override {
    // Override NT symbol path.
    std::string nt_symbol_path;
    ASSERT_TRUE(GetNtSymbolPathValue(&nt_symbol_path));
    ASSERT_TRUE(
        scoped_env_variable_.Set(testing::kNtSymbolPathEnvVar, nt_symbol_path));

    // Determine minidump path.
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    minidump_path_ = temp_dir_.path().Append(kMinidumpFileName);
  }

  base::FilePath temp_dir() { return temp_dir_.path(); }
  base::FilePath minidump_path() { return minidump_path_; }

  bool GenerateMinidump(CONTEXT* context) {
    DCHECK(context);

    // Build the exception information.
    EXCEPTION_RECORD exception = {};
    exception.ExceptionCode = 0xCAFEBABE;  // Note: a random error code.
    exception.ExceptionAddress = reinterpret_cast<PVOID>(context->Eip);

    EXCEPTION_POINTERS exception_pointers = {&exception, context};

    // Build the dumper's command line.
    base::CommandLine dumper_command_line(
        base::GetMultiProcessTestChildBaseCommandLine());
    dumper_command_line.AppendSwitchASCII(switches::kTestChildProcess,
                                          "MinidumpDumperProcess");
    base::Process current_process = base::Process::Current();
    dumper_command_line.AppendSwitchASCII(
        kSwitchPid, base::UintToString(current_process.Pid()));
    dumper_command_line.AppendSwitchASCII(
        kSwitchTid, base::UintToString(::GetCurrentThreadId()));
    unsigned exception_pointers_uint =
        reinterpret_cast<unsigned>(&exception_pointers);
    dumper_command_line.AppendSwitchASCII(
        kSwitchExceptionPtrs, base::UintToString(exception_pointers_uint));
    dumper_command_line.AppendSwitchPath(kSwitchMinidumpPath, minidump_path());

    // Launch the dumper.
    base::Process dumper_process =
        base::LaunchProcess(dumper_command_line, base::LaunchOptions());
    int exit_code = 0;
    bool success = dumper_process.WaitForExitWithTimeout(
        TestTimeouts::action_timeout(), &exit_code);
    if (!success) {
      dumper_process.Terminate(0, true);
      return false;
    }

    return exit_code == 0;
  }

 private:
  base::ScopedTempDir temp_dir_;
  base::FilePath minidump_path_;

  testing::ScopedEnvironmentVariable scoped_env_variable_;
};

// This test fails under coverage instrumentation which is probably not friendly
// to stackwalking.
#ifdef _COVERAGE_BUILD
TEST_F(StackAnalyzerTest, DISABLED_AnalyzeMinidump) {
#else
TEST_F(StackAnalyzerTest, AnalyzeMinidump) {
#endif
  base::win::ScopedCOMInitializer com_initializer;
  base::FilePath path;

  // Generate a minidump.

  // TODO(manzagop): set up some stack state.
  CONTEXT context = {};
  ::RtlCaptureContext(&context);

  // RtlCaptureContext sets the instruction pointer, stack pointer and base
  // pointer to values from this function's callee (similar to _ReturnAddress).
  // Override them so they actually match the context.
  context.Eip = GetEip();
  __asm {
    mov context.Ebp, ebp
    mov context.Esp, esp
  }

  ASSERT_TRUE(GenerateMinidump(&context));

  Minidump minidump;
  ASSERT_TRUE(minidump.Open(minidump_path()));

  // Analyze.
  ProcessState process_state;

  AnalysisRunner runner;

  scoped_ptr<Analyzer> analyzer(new refinery::MemoryAnalyzer());
  runner.AddAnalyzer(analyzer.Pass());
  analyzer.reset(new refinery::ThreadAnalyzer());
  runner.AddAnalyzer(analyzer.Pass());
  analyzer.reset(new refinery::ExceptionAnalyzer());
  runner.AddAnalyzer(analyzer.Pass());
  analyzer.reset(new refinery::ModuleAnalyzer());
  runner.AddAnalyzer(analyzer.Pass());
  analyzer.reset(new refinery::StackAnalyzer());
  runner.AddAnalyzer(analyzer.Pass());

  ASSERT_EQ(Analyzer::ANALYSIS_COMPLETE,
            runner.Analyze(minidump, &process_state));

  // Ensure the test's thread was successfully walked.
  // TODO(manzagop): actual validation of stack walk result once added to
  // process state.
  StackRecordPtr stack;
  DWORD thread_id = ::GetCurrentThreadId();
  ASSERT_TRUE(
      process_state.FindStackRecord(static_cast<size_t>(thread_id), &stack));
  ASSERT_TRUE(stack->data().stack_walk_success());
}

}  // namespace refinery
