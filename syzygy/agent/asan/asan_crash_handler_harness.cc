// Copyright 2014 Google Inc. All Rights Reserved.
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
// The main entry point for the test harness that validates the proper working
// of the AsanCrashHandler. This needs to be done in a clean binary so as to
// avoid problems coexisting with gtest. Test success is communicated via the
// return code of this harness.

#include "base/bind.h"
#include "base/command_line.h"
#include "base/logging.h"
#include "base/synchronization/lock.h"
#include "syzygy/agent/asan/asan_crash_handler.h"

namespace {

using agent::asan::AsanCrashHandler;

LPTOP_LEVEL_EXCEPTION_FILTER previous_unhandled_exception_filter = NULL;

// The return code that will be used when the exception makes it to our base
// filter.
UINT test_unhandled_exception_filter_return_code = 1;

void Exit(UINT code) {
  if (code != 0) {
    LOG(ERROR) << "Exiting with an error.";
  } else {
    VLOG(1) << "Terminating successfully.";
  }
  ::TerminateProcess(::GetCurrentProcess(), code);
}

LONG WINAPI TestUnhandledExceptionFilter(
    struct _EXCEPTION_POINTERS* exception) {
  VLOG(1) << "Entering TestUnhandledExceptionFilter.";
  Exit(test_unhandled_exception_filter_return_code);

  return EXCEPTION_EXECUTE_HANDLER;
}

// The return code that will be used when the exception is handled by the
// registered ASAN filter.
UINT on_exception_return_code = 1;

// The callback that will be invoked for the exception if filtering is
// enabled.
void OnException(struct _EXCEPTION_POINTERS** exception) {
  VLOG(1) << "Entering OnException callback.";
  Exit(on_exception_return_code);
}

void RegisterTestUnhandledExceptionFilter() {
  previous_unhandled_exception_filter = ::SetUnhandledExceptionFilter(
      &TestUnhandledExceptionFilter);

  VLOG(1) << "Registering exception filter and callback.";
  AsanCrashHandler::Initialize();
  AsanCrashHandler::SetOnExceptionCallback(base::Bind(&OnException));
}

uint32 Crash() {
  LOG(INFO) << "Dereferencing an invalid address.";
  uint32 invalid_address = ::rand();
  invalid_address &= 0xFC;
  uint32 value_at_invalid_address =
      *reinterpret_cast<uint32*>(invalid_address);
  return value_at_invalid_address;
}

void TestFilterDisabled() {
  // We expect the error to be handled by the base filter we install, and
  // not the ASAN filter.
  test_unhandled_exception_filter_return_code = 0;
  on_exception_return_code = 1;

  AsanCrashHandler::DisableForCurrentThread();
  uint32 value = Crash();
  AsanCrashHandler::EnableForCurrentThread();

  // This is a dummy statement just to ensure that value and Crash can't be
  // optimized away. The code should never reach here.
  value ^= ::rand();
  Exit(value != 0 ? 1 : 0);
}

void TestFilterEnabled() {
  // We expect the error to be handled by the ASAN filter.
  test_unhandled_exception_filter_return_code = 1;
  on_exception_return_code = 0;

  uint32 value = Crash();

  // This is a dummy statement just to ensure that value and Crash can't be
  // optimized away. The code should never reach here.
  value ^= ::rand();
  Exit(value != 0 ? 1 : 0);
}

}  // namespace

int main(int argc, char** argv) {
  // Initialize the command-line.
  CommandLine::Init(argc, argv);
  CommandLine* cmd_line = CommandLine::ForCurrentProcess();

  // Initialize logging.
  logging::InitLogging(NULL,
                       logging::LOG_ONLY_TO_SYSTEM_DEBUG_LOG,
                       logging::DONT_LOCK_LOG_FILE,
                       logging::APPEND_TO_OLD_LOG_FILE,
                       logging::ENABLE_DCHECK_FOR_NON_OFFICIAL_RELEASE_BUILDS);
  logging::SetMinLogLevel(logging::LOG_ERROR);
  if (cmd_line->HasSwitch("verbose"))
    logging::SetMinLogLevel(logging::LOG_VERBOSE);

  // Set up our map of tests.
  typedef void (*TestFunctionPtr)();
  typedef std::map<std::string, TestFunctionPtr> TestMap;
  TestMap test_map;
  test_map["FilterDisabled"] = &TestFilterDisabled;
  test_map["FilterEnabled"] = &TestFilterEnabled;

  // Parse the command-line.
  std::string test = cmd_line->GetSwitchValueASCII("test");
  if (test.empty()) {
    LOG(ERROR) << "Must specify --test.";
    return 1;
  }
  TestMap::const_iterator test_it = test_map.find(test);
  if (test_it == test_map.end()) {
    LOG(ERROR) << "No test exists with name \"" << test << "\".";
    return 1;
  }

  // We always terminate with success if a debugger is present, as we can't
  // actually test the unhandled exception filters otherwise.
  if (::IsDebuggerPresent()) {
    LOG(INFO) << "Not running test \"" << test
              << "\" as a debugger is attached.";
    return 0;
  }

  // Set up the test environment and run the test.
  LOG(INFO) << "Running test \"" << test << "\".";
  RegisterTestUnhandledExceptionFilter();
  (*test_it->second)();

  // We should never get here as the test should invoke the unhandled exception
  // filter and eventually call TerminateProcess directly.
  NOTREACHED() << "Should never get here. No exception raised?";
  return 1;
}
