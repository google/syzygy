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
// A harness for loading integration_tests_dll, and calling a test function
// within it. This is intended for use with instrumented versions of the
// DLL, and is required for certain tests that raise exceptions. The test has
// to be moved to a separate process so as to avoid gtest interference in
// exception handling.

#include "base/command_line.h"
#include "base/file_util.h"
#include "base/logging.h"
#include "base/files/file_path.h"
#include "base/strings/string_number_conversions.h"
#include "syzygy/common/com_utils.h"
#include "syzygy/integration_tests/integration_tests_dll.h"

namespace {

typedef unsigned int (__stdcall* EndToEndTestFunction)(unsigned int);

#define _STRINGIFY(s) #s
#define STRINGIFY(s) _STRINGIFY(s)

// An array of test names. The test integer ID is the position of the name in
// the array.
const char* kTestNames[] = {
#define DEFINE_TEST_NAME(enum_name, function_name) STRINGIFY(enum_name),
  END_TO_END_TEST_ID_TABLE(DEFINE_TEST_NAME)
#undef DEFINE_TEST_NAME
};

// Top level configuration and parameters.
LPTOP_LEVEL_EXCEPTION_FILTER previous_unhandled_exception_filter = NULL;
base::FilePath dll;
size_t test_id = 0;
bool expect_exception = false;

bool ParseTestId(CommandLine* cmd_line) {
  DCHECK_NE(reinterpret_cast<CommandLine*>(NULL), cmd_line);

  std::string test = cmd_line->GetSwitchValueASCII("test");
  if (test.empty()) {
    LOG(ERROR) << "Must specify --test.";
    return false;
  }

  // Search for the test by name
  for (size_t i = 0; i < arraysize(kTestNames); ++i) {
    if (test == kTestNames[i]) {
      test_id = i;
      return true;
    }
  }

  // Try to convert the string to an integer.
  if (!base::StringToSizeT(test, &test_id)) {
    LOG(ERROR) << "Invalid test name or id: " << test;
    return false;
  }

  // If integer parsing worked then ensure it's a valid test id.
  if (test_id >= arraysize(kTestNames)) {
    LOG(ERROR) << "Invalid test id: " << test_id;
    return false;
  }

  return true;
}

bool ParseCommandLine(CommandLine* cmd_line) {
  DCHECK_NE(reinterpret_cast<CommandLine*>(NULL), cmd_line);

  // Parse and validate the path to the DLL.
  dll = cmd_line->GetSwitchValuePath("dll");
  if (dll.empty()) {
    LOG(ERROR) << "Must specify --dll.";
    return false;
  }
  if (!base::PathExists(dll)) {
    LOG(ERROR) << "File does not exist: " << dll.value();
    return false;
  }

  // Parse the test ID.
  if (!ParseTestId(cmd_line))
    return false;

  expect_exception = cmd_line->HasSwitch("expect-exception");

  return true;
}

// A utility function for terminating the process with a given return code.
void Exit(UINT code) {
  if (code != 0) {
    LOG(ERROR) << "Exiting with an error.";
  } else {
    VLOG(1) << "Terminating successfully.";
  }
  ::TerminateProcess(::GetCurrentProcess(), code);
}

// The base unhandled exception filter. If an exception is raised then this is
// our exit path.
LONG WINAPI MyUnhandledExceptionFilter(struct _EXCEPTION_POINTERS* exception) {
  VLOG(1) << "Entering UnhandledExceptionFilter.";

  if (!expect_exception) {
    LOG(ERROR) << "An exception was raised, but none was expected.";
    Exit(1);
  }
  Exit(0);

  LOG(ERROR) << "Something went terribly wrong.";
  return EXCEPTION_EXECUTE_HANDLER;
}

}  // namespace

int main(int argc, char** argv) {
  // Initialize the command-line.
  CommandLine::Init(argc, argv);
  CommandLine* cmd_line = CommandLine::ForCurrentProcess();

  // Initialize logging.
  logging::LoggingSettings settings;
  settings.logging_dest = logging::LOG_TO_SYSTEM_DEBUG_LOG;
  settings.lock_log = logging::DONT_LOCK_LOG_FILE;
  settings.delete_old = logging::APPEND_TO_OLD_LOG_FILE;
  logging::InitLogging(settings);
  logging::SetMinLogLevel(logging::LOG_ERROR);
  if (cmd_line->HasSwitch("verbose"))
    logging::SetMinLogLevel(logging::LOG_VERBOSE);

  // Parse the command-line.
  if (!ParseCommandLine(cmd_line))
    return 1;

  // Prevent dialog boxes from popping up.
  ::SetErrorMode(SEM_FAILCRITICALERRORS);

  VLOG(1) << "Registering unhandled exception filter and callback.";
  previous_unhandled_exception_filter = ::SetUnhandledExceptionFilter(
      &MyUnhandledExceptionFilter);

  // Load the module.
  LOG(INFO) << "Loading module: " << dll.value();
  HMODULE module = ::LoadLibrary(dll.value().c_str());
  if (module == NULL) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "LoadLibrary failed: " << common::LogWe(error);
    return 1;
  }

  // Get the EndToEndTest function. It is the entry point for calling
  // the various tests.
  LOG(INFO) << "Looking up EndToEndTest function.";
  EndToEndTestFunction func = reinterpret_cast<EndToEndTestFunction>(
      ::GetProcAddress(module, "EndToEndTest"));
  if (func == NULL) {
    LOG(ERROR) << "Failed to find EndToEndTest function.";
    return 1;
  }

  // Invoke the test function.
  LOG(INFO) << "Invoking test " << test_id << ".";
  size_t ret = func(test_id);

  if (expect_exception) {
    LOG(ERROR) << "Expected an exception, but none was raised.";
    Exit(1);
  }
  Exit(0);

  LOG(ERROR) << "Something went terribly wrong.";
  return 1;
}
