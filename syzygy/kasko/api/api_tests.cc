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

#include "base/base_switches.h"
#include "base/bind.h"
#include "base/command_line.h"
#include "base/logging.h"
#include "base/files/file_path.h"
#include "base/files/scoped_temp_dir.h"
#include "base/process/kill.h"
#include "base/process/launch.h"
#include "base/process/process_handle.h"
#include "base/strings/string16.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/utf_string_conversions.h"
#include "base/synchronization/waitable_event.h"
#include "base/test/multiprocess_test.h"
#include "base/win/scoped_handle.h"
#include "syzygy/kasko/api/client.h"
#include "syzygy/kasko/api/reporter.h"
#include "syzygy/kasko/testing/minidump_unittest_helpers.h"
#include "syzygy/kasko/testing/test_server.h"
#include "testing/multiprocess_func_list.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace kasko {
namespace api {

namespace {

const char kTestInstanceKeySwitch[] = "test-instance-key";
const char kClientProcessIdSwitch[] = "client-process-id";
const base::char16 kExitEventNamePrefix[] = L"kasko_api_test_exit_event_";
const base::char16 kReadyEventNamePrefix[] = L"kasko_api_test_ready_event_";
const base::char16 kEndpointPrefix[] = L"kasko_api_test_endpoint_";

MULTIPROCESS_TEST_MAIN(ApiTestReporterProcess) {
  // Read the client-supplied parameters.
  base::CommandLine* cmd_line = base::CommandLine::ForCurrentProcess();
  unsigned int client_process_id_uint = 0;
  CHECK(
      base::StringToUint(cmd_line->GetSwitchValueASCII(kClientProcessIdSwitch),
                         &client_process_id_uint));
  base::ProcessId client_process_id = client_process_id_uint;
  base::string16 test_instance_key =
      base::ASCIIToUTF16(cmd_line->GetSwitchValueASCII(kTestInstanceKeySwitch));
  base::string16 endpoint = kEndpointPrefix + test_instance_key;
  base::ScopedTempDir permanent_failure_directory;
  CHECK(permanent_failure_directory.CreateUniqueTempDir());

  // Set up a directory for the Reporter to generate and store crash dumps.
  base::ScopedTempDir data_directory;
  CHECK(data_directory.CreateUniqueTempDir());

  // Create the events used for inter-process synchronization.
  base::WaitableEvent exit_event(::CreateEvent(
      NULL, FALSE, FALSE, (kExitEventNamePrefix + test_instance_key).c_str()));
  base::WaitableEvent ready_event(::CreateEvent(
      NULL, FALSE, FALSE, (kReadyEventNamePrefix + test_instance_key).c_str()));

  // Start up a test server to receive uploads.
  testing::TestServer server;
  CHECK(server.Start());
  base::string16 url =
      L"http://127.0.0.1:" + base::UintToString16(server.port()) + L"/crash";


  // Initialize the Reporter process
  InitializeReporter(endpoint.c_str(), url.c_str(),
                     data_directory.path().value().c_str(),
                     permanent_failure_directory.path().value().c_str());

  // Request a dump of the client process.
  base::char16* keys[] = {L"hello", nullptr};
  base::char16* values[] = {L"world", nullptr};
  base::win::ScopedHandle client_process(
      ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, client_process_id));
  CHECK(client_process.IsValid());
  SendReportForProcess(client_process.Get(), keys, values);

  // Tell the client process that we are active.
  ready_event.Signal();

  // Wait until the client signals us to shut down.
  exit_event.Wait();

  // Shut down the Reporter process.
  ShutdownReporter();

  return 0;
}

}  // namespace

// This test exercises all of the API methods of Kasko.dll. It does not do an
// end-to-end test (i.e. by verifying that the requested crash report is
// properly uploaded). The primary reason is that the delay before uploading is
// not configurable via the public API and this test would therefore need to
// wait 3 minutes before observing an upload.
TEST(ApiTest, BasicTest) {
  // Pick an ID used to avoid global namespace collisions.
  base::string16 test_instance_key =
      base::UintToString16(base::GetCurrentProcId());

  // Create the events used for inter-process synchronization.
  base::win::ScopedHandle exit_event_handle(::CreateEvent(
      NULL, FALSE, FALSE, (kExitEventNamePrefix + test_instance_key).c_str()));
  ASSERT_TRUE(exit_event_handle.IsValid());
  base::WaitableEvent exit_event(exit_event_handle.Take());

  base::win::ScopedHandle ready_event_handle(::CreateEvent(
      NULL, FALSE, FALSE, (kReadyEventNamePrefix + test_instance_key).c_str()));
  ASSERT_TRUE(ready_event_handle.IsValid());
  base::WaitableEvent ready_event(ready_event_handle.Take());

  // Start building the Reporter process command line.
  base::CommandLine reporter_command_line =
      base::GetMultiProcessTestChildBaseCommandLine();
  reporter_command_line.AppendSwitchASCII(switches::kTestChildProcess,
                                          "ApiTestReporterProcess");

  // Pass the test instance ID.
  reporter_command_line.AppendSwitchASCII(
      kTestInstanceKeySwitch, base::UTF16ToASCII(test_instance_key));

  // Pass the client process ID, used by the reporter to invoke
  // SendReportForProcess.
  reporter_command_line.AppendSwitchASCII(
      kClientProcessIdSwitch, base::UintToString(base::GetCurrentProcId()));

  // Launch the Reporter process and wait until it is fully initialized.
  base::ProcessHandle reporter_process;
  ASSERT_TRUE(base::LaunchProcess(reporter_command_line, base::LaunchOptions(),
                                  &reporter_process));
  ready_event.Wait();

  // Initialize the Client process.
  InitializeClient((kEndpointPrefix + test_instance_key).c_str());

  // Send up a crash report.
  CONTEXT ctx = {};
  ::RtlCaptureContext(&ctx);
  EXCEPTION_RECORD exc_rec = {};
  exc_rec.ExceptionAddress = reinterpret_cast<void*>(ctx.Eip);
  exc_rec.ExceptionCode = EXCEPTION_ARRAY_BOUNDS_EXCEEDED;
  EXCEPTION_POINTERS exc_ptrs = { &exc_rec, &ctx };

  CrashKey crash_keys[] = {{L"hello", L"world"}, {L"", L"bar"}};
  SendReport(&exc_ptrs, NULL, 0, crash_keys, arraysize(crash_keys));

  // TODO(erikwright): Wait for the upload and verify the report contents.

  // Shut down the client.
  ShutdownClient();

  // Tell the reporter process that we are done.
  exit_event.Signal();

  // Wait for the reporter process to exit and verify its status code.
  int exit_code = 0;
  base::WaitForExitCode(reporter_process, &exit_code);
  ASSERT_EQ(0, exit_code);
}

}  // namespace api
}  // namespace kasko
