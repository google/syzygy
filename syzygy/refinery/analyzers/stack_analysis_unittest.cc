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

#include <Windows.h>  // NOLINT
#include <DbgHelp.h>

#include <string>
#include <vector>

#include "base/base_switches.h"
#include "base/command_line.h"
#include "base/logging.h"
#include "base/debug/alias.h"
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
#include "syzygy/refinery/analyzers/stack_analyzer.h"
#include "syzygy/refinery/analyzers/stack_frame_analyzer.h"
#include "syzygy/refinery/analyzers/thread_analyzer.h"
#include "syzygy/refinery/minidump/minidump.h"
#include "syzygy/refinery/process_state/process_state.h"
#include "syzygy/refinery/process_state/process_state_util.h"
#include "syzygy/refinery/process_state/refinery.pb.h"
#include "syzygy/refinery/symbols/dia_symbol_provider.h"
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

struct SimpleUDT {
  int one;
  const char two;
};

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

bool AnalyzeMinidump(const base::FilePath& minidump_path,
                     ProcessState* process_state) {
  Minidump minidump;
  if (!minidump.Open(minidump_path))
    return false;

  scoped_refptr<DiaSymbolProvider> dia_symbol_provider(new DiaSymbolProvider());
  scoped_refptr<SymbolProvider> symbol_provider(new SymbolProvider());

  AnalysisRunner runner;
  scoped_ptr<Analyzer> analyzer(new refinery::MemoryAnalyzer());
  runner.AddAnalyzer(analyzer.Pass());
  analyzer.reset(new refinery::ThreadAnalyzer());
  runner.AddAnalyzer(analyzer.Pass());
  analyzer.reset(new refinery::ExceptionAnalyzer());
  runner.AddAnalyzer(analyzer.Pass());
  analyzer.reset(new refinery::ModuleAnalyzer());
  runner.AddAnalyzer(analyzer.Pass());
  analyzer.reset(new refinery::StackAnalyzer(dia_symbol_provider));
  runner.AddAnalyzer(analyzer.Pass());
  analyzer.reset(
      new refinery::StackFrameAnalyzer(dia_symbol_provider, symbol_provider));
  runner.AddAnalyzer(analyzer.Pass());

  return runner.Analyze(minidump, process_state) == Analyzer::ANALYSIS_COMPLETE;
}

void ValidateTypedBlock(ProcessState* process_state,
                        Address expected_address,
                        Size expected_size,
                        const std::string& expected_variable_name,
                        const std::string& expected_type_name) {
  TypedBlockRecordPtr typedblock_record;
  // Note: using FindSingleRecord as there should be no typed block overlap in
  // the context of this test.
  ASSERT_TRUE(
      process_state->FindSingleRecord(expected_address, &typedblock_record));

  ASSERT_EQ(expected_address, typedblock_record->range().addr());
  ASSERT_EQ(expected_size, typedblock_record->range().size());
  const TypedBlock& typedblock = typedblock_record->data();
  ASSERT_EQ(expected_variable_name, typedblock.data_name());
  ASSERT_EQ(expected_type_name, typedblock.type_name());
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

class StackAndFrameAnalyzersTest : public testing::Test {
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

    expected_esp_ = 0U;
    eip_lowerbound_ = 0U;
    eip_upperbound_ = 0U;

    expected_param_address_ = 0ULL;
    expected_udt_address_ = 0ULL;
    expected_udt_ptr_address_ = 0ULL;
  }

  base::FilePath temp_dir() { return temp_dir_.path(); }
  base::FilePath minidump_path() { return minidump_path_; }
  uint32 expected_esp() { return expected_esp_; }
  uint32 eip_lowerbound() { return eip_lowerbound_; }
  uint32 eip_upperbound() { return eip_upperbound_; }
  Address expected_param_address() { return expected_param_address_; }
  Address expected_udt_address() { return expected_udt_address_; }
  Address expected_udt_ptr_address() { return expected_udt_ptr_address_; }

  bool GenerateMinidump() {
    // Grab a context. RtlCaptureContext sets the instruction pointer, stack
    // pointer and base pointer to values from this function's callee (similar
    // to _ReturnAddress). Override them so they actually match the context.
    // TODO(manzagop): package this to a utility function.
    CONTEXT context = {};
    ::RtlCaptureContext(&context);
    __asm {
      mov context.Ebp, ebp
      mov context.Esp, esp
    }
    context.Eip = GetEip();

    // Build the exception information.
    EXCEPTION_RECORD exception = {};
    exception.ExceptionCode = 0xCAFEBABE;  // Note: a random error code.
    exception.ExceptionAddress = reinterpret_cast<PVOID>(context.Eip);

    EXCEPTION_POINTERS exception_pointers = {&exception, &context};

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

  bool SetupStackFrameAndGenerateMinidump(int dummy_param) {
    bool success = true;

    // Create some local variables to validate analysis.
    SimpleUDT udt_local = {42, 'a'};
    base::debug::Alias(&udt_local);
    SimpleUDT* udt_ptr_local = &udt_local;
    base::debug::Alias(&udt_ptr_local);

    // Copy esp to expected_esp_. Note: esp must not be changed prior to calling
    // GenerateMinidump.
    __asm {
      mov ebx, this
      mov [ebx].expected_esp_, esp
    }

    eip_lowerbound_ = GetEip();

    // Note: GenerateMinidump takes no parameters. This means when the frame is
    // walked, its top should equal the captured esp.
    success = GenerateMinidump();

    eip_upperbound_ = GetEip();

    expected_param_address_ = reinterpret_cast<Address>(&dummy_param);
    expected_udt_address_ = reinterpret_cast<Address>(&udt_local);
    expected_udt_ptr_address_ = reinterpret_cast<Address>(&udt_ptr_local);

    return success;
  }

 private:
  base::ScopedTempDir temp_dir_;
  base::FilePath minidump_path_;

  // For stack frame validation.
  uint32 expected_esp_;
  uint32 eip_lowerbound_;
  uint32 eip_upperbound_;

  // Typed block validation.
  Address expected_param_address_;
  Address expected_udt_address_;
  Address expected_udt_ptr_address_;

  testing::ScopedEnvironmentVariable scoped_env_variable_;
};

// This test fails under coverage instrumentation which is probably not friendly
// to stackwalking.
#ifdef _COVERAGE_BUILD
TEST_F(StackAndFrameAnalyzersTest, DISABLED_BasicTest) {
#else
TEST_F(StackAndFrameAnalyzersTest, BasicTest) {
#endif
  base::win::ScopedCOMInitializer com_initializer;

  // Note: intentionally declared before determining expected_frame_base.
  int dummy_argument = 22;

  // Generate the minidump, then analyze it.
  // Note: the expected frame base for SetupStackFrameAndGenerateMinidump should
  // be sizeof(void*) + sizeof(int) off of the current frame's top of stack
  // immediately prior to the call (accounting for callee argument and return
  // address).
  uint32 expected_frame_base = 0U;
  __asm {
    mov expected_frame_base, esp
  }
  expected_frame_base -= (sizeof(void*) + sizeof(int));

  ASSERT_TRUE(SetupStackFrameAndGenerateMinidump(dummy_argument));

  ProcessState process_state;
  ASSERT_TRUE(AnalyzeMinidump(minidump_path(), &process_state));

  // Ensure the test's thread was successfully walked.
  StackRecordPtr stack;
  DWORD thread_id = ::GetCurrentThreadId();
  ASSERT_TRUE(
      process_state.FindStackRecord(static_cast<size_t>(thread_id), &stack));
  ASSERT_TRUE(stack->data().stack_walk_success());

  // Validate SetupStackFrameAndGenerateMinidump's frame.
  StackFrameRecordPtr frame_record;
  // Note: using FindSingleRecord as there should be no frame record overlap
  // in the context of this test.
  ASSERT_TRUE(process_state.FindSingleRecord(
      static_cast<Address>(expected_esp()), &frame_record));

  ASSERT_EQ(expected_esp(), frame_record->range().addr());
  ASSERT_EQ(expected_frame_base - expected_esp(), frame_record->range().size());

  const StackFrame& frame = frame_record->data();
  uint32_t recovered_eip = frame.register_info().eip();
  ASSERT_LT(eip_lowerbound(), recovered_eip);
  ASSERT_GT(eip_upperbound(), recovered_eip);

  // Sanity and tightness check.
  ASSERT_GT(eip_upperbound(), eip_lowerbound());
  ASSERT_LT(eip_upperbound() - eip_lowerbound(), 100);

  // TODO(manzagop): validate frame_size_bytes. It should be sizeof(void*)
  // smaller than expected_frame_base - expected_esp(), to account for ebp
  // and since the function called into has no parameters.

  // TODO(manzagop): validate locals_base. It should be sizeof(void*) off of
  // the frame base, to account for ebp.

  // Validate typed block layer for SetupStackFrameAndGenerateMinidump.
  // - Validate some locals.
  ASSERT_NO_FATAL_FAILURE(ValidateTypedBlock(
      &process_state, expected_udt_address(), sizeof(SimpleUDT), "udt_local",
      "refinery::`anonymous-namespace'::SimpleUDT"));
  ASSERT_NO_FATAL_FAILURE(ValidateTypedBlock(
      &process_state, expected_udt_ptr_address(), sizeof(SimpleUDT*),
      "udt_ptr_local", "refinery::`anonymous-namespace'::SimpleUDT*"));
  // - Validate a parameter.
  ASSERT_NO_FATAL_FAILURE(
      ValidateTypedBlock(&process_state, expected_param_address(), sizeof(int),
                         "dummy_param", "int32_t"));
}

}  // namespace refinery
