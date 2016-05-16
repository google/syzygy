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

#include "syzygy/kasko/reporter.h"

#include <Windows.h>  // NOLINT
#include <Dbgeng.h>
#include <Rpc.h>

#include <memory>
#include <string>

#include "base/base_switches.h"
#include "base/bind.h"
#include "base/command_line.h"
#include "base/files/file_path.h"
#include "base/files/scoped_temp_dir.h"
#include "base/process/kill.h"
#include "base/process/launch.h"
#include "base/strings/string16.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/utf_string_conversions.h"
#include "base/synchronization/waitable_event.h"
#include "base/test/multiprocess_test.h"
#include "base/time/time.h"
#include "gtest/gtest.h"
#include "syzygy/common/rpc/helpers.h"
#include "syzygy/kasko/kasko_rpc.h"
#include "syzygy/kasko/minidump_request.h"
#include "syzygy/kasko/version.h"
#include "syzygy/kasko/testing/minidump_unittest_helpers.h"
#include "syzygy/kasko/testing/test_server.h"
#include "syzygy/kasko/testing/upload_observer.h"
#include "testing/multiprocess_func_list.h"

// The test server will respond to POSTs to /crash by writing all parameters to
// a report directory. Each file in the directory has the name of a parameter
// and the parameter value as its contents.
//
// This test instantiates a reporter process, points it at a test server, and
// then monitors the server's "incoming" director for new files named
// Reporter::kMinidumpUploadFilePart.
//
// These tests are flaky on the bots. They appear to occasionally hang.
// Presumably there is some kind of race condition.
// TODO(erikwright): Debug these on the bots, add additional tracing, or do
// whatever's necessary to diagnose and deflake these tests.
namespace kasko {

namespace {

const base::char16 kCrashKey1Name[] = L"foo";
const base::char16 kCrashKey1Value[] = L"bar";
const base::char16 kCrashKey2Name[] = L"hello";
const base::char16 kCrashKey2Value[] = L"world";

const char kEndpointSwitch[] = "endpoint";
const char kReadyEventSwitch[] = "ready-event";

// Signals an event named by kReadyEventSwitch, then blocks indefinitely.
MULTIPROCESS_TEST_MAIN(ReporterTestBlockingProcess) {
  // Read the caller-supplied parameters.
  base::CommandLine* cmd_line = base::CommandLine::ForCurrentProcess();
  base::string16 ready_event_name =
      base::ASCIIToUTF16(cmd_line->GetSwitchValueASCII(kReadyEventSwitch));
  base::WaitableEvent ready_event(base::win::ScopedHandle(
      ::OpenEvent(EVENT_MODIFY_STATE, FALSE, ready_event_name.c_str())));
  ready_event.Signal();
  ::Sleep(INFINITE);
  return 0;
}

// Invokes SendDiagnosticReport via the RPC endpoint named by kEndpointSwitch.
MULTIPROCESS_TEST_MAIN(ReporterTestClientProcess) {
  // Read the caller-supplied parameters.
  base::CommandLine* cmd_line = base::CommandLine::ForCurrentProcess();
  base::string16 endpoint =
      base::ASCIIToUTF16(cmd_line->GetSwitchValueASCII(kEndpointSwitch));
  common::rpc::ScopedRpcBinding rpc_binding;
  if (!rpc_binding.Open(L"ncalrpc", endpoint)) {
    PLOG(ERROR) << "ScopedRpcBinding::Open";
    return 1;
  }

  CrashKey crash_keys[] = {{kCrashKey1Name, kCrashKey1Value},
                           {kCrashKey2Name, kCrashKey2Value}};
  ::MinidumpRequest rpc_request = {0,          0,       SMALL_DUMP,
                                   0,          nullptr, arraysize(crash_keys),
                                   crash_keys, 0,       nullptr};

  common::rpc::RpcStatus status = common::rpc::InvokeRpc(
      KaskoClient_SendDiagnosticReport, rpc_binding.Get(), rpc_request);
  if (status.exception_occurred || !status.succeeded()) {
    PLOG(ERROR) << "InvokeRpc";
    return 1;
  }
  return 0;
}

// Invokes |instance|->SendReportForProcess() using |child_process|.
void InvokeSendReportForProcess(Reporter* instance,
                                base::ProcessHandle child_process) {
  MinidumpRequest request;
  request.crash_keys.push_back(
      MinidumpRequest::CrashKey(kCrashKey1Name, kCrashKey1Value));
  request.crash_keys.push_back(
      MinidumpRequest::CrashKey(kCrashKey2Name, kCrashKey2Value));

  instance->SendReportForProcess(child_process, 0, request);
}

// Verifies that the uploaded minidump is plausibly a dump of this test process.
void ValidateMinidump(IDebugClient4* debug_client,
                      IDebugControl* debug_control,
                      IDebugSymbols* debug_symbols) {
  ASSERT_HRESULT_SUCCEEDED(
      debug_symbols->GetModuleByModuleName("kasko_unittests", 0, NULL, NULL));
}

void OnUpload(base::string16* report_id_out,
              const base::string16& report_id,
              const base::FilePath& minidump_path,
              const std::map<base::string16, base::string16>& crash_keys) {
  *report_id_out = report_id;
  ASSERT_FALSE(report_id.empty());
  ASSERT_FALSE(minidump_path.empty());
}

}  // namespace

class ReporterTest : public ::testing::Test {
 public:
  ReporterTest()
      : test_instance_key_(base::UintToString(base::GetCurrentProcId())) {}

  void SetUp() override {
    ASSERT_TRUE(server_.Start());
    ASSERT_TRUE(temp_directory_.CreateUniqueTempDir());
  }

 protected:
  // Launches a child process that will invoke SendDiagnosticReport using the
  // RPC endpoint returned by endpoint().
  void InvokeRpcFromChildProcess() {
    base::CommandLine client_command_line =
        base::GetMultiProcessTestChildBaseCommandLine();
    client_command_line.AppendSwitchASCII(switches::kTestChildProcess,
                                          "ReporterTestClientProcess");
    client_command_line.AppendSwitchASCII(kEndpointSwitch,
                                          base::UTF16ToASCII(endpoint()));
    base::Process client_process = base::LaunchProcess(client_command_line,
                                                       base::LaunchOptions());
    ASSERT_TRUE(client_process.IsValid());

    int exit_code = 0;
    ASSERT_TRUE(client_process.WaitForExit(&exit_code));
    ASSERT_EQ(0, exit_code);
  }

  // Launches a child process and passes its handle to |callback|. Then kills
  // the child process.
  void DoWithChildProcess(
      const base::Callback<void(base::ProcessHandle)>& callback) {
    std::string ready_event_name = "reporter_test_ready_" + test_instance_key_;
    base::WaitableEvent ready_event(base::win::ScopedHandle(::CreateEvent(
        NULL, FALSE, FALSE, base::ASCIIToUTF16(ready_event_name).c_str())));

    base::CommandLine child_command_line =
        base::GetMultiProcessTestChildBaseCommandLine();
    child_command_line.AppendSwitchASCII(switches::kTestChildProcess,
                                         "ReporterTestBlockingProcess");
    child_command_line.AppendSwitchASCII(kReadyEventSwitch, ready_event_name);
    base::Process child_process = base::LaunchProcess(child_command_line,
                                                      base::LaunchOptions());
    ASSERT_TRUE(child_process.IsValid());
    ready_event.Wait();
    callback.Run(child_process.Handle());
    ASSERT_TRUE(child_process.Terminate(0, true));
  }

  uint16_t server_port() { return server_.port(); }

  base::string16 endpoint() {
    return base::ASCIIToUTF16("reporter_test_endpoint_" + test_instance_key_);
  }

  // This directory is intentionally non-existant to verify that the reporter
  // creates the target directory as needed.
  base::FilePath data_directory() {
    return temp_directory_.path().Append(L"Crash Reports");
  }

  // This directory is intentionally non-existant to verify that the reporter
  // creates the target directory as needed.
  base::FilePath permanent_failure_directory() {
    return temp_directory_.path().Append(L"Permanent Failure");
  }

  base::FilePath upload_directory() { return server_.incoming_directory(); }

 private:
  testing::TestServer server_;
  base::ScopedTempDir temp_directory_;
  std::string test_instance_key_;

  DISALLOW_COPY_AND_ASSIGN(ReporterTest);
};

TEST_F(ReporterTest, BasicTest) {
  base::string16 report_id;
  std::unique_ptr<Reporter> instance(Reporter::Create(
      endpoint(),
      L"http://127.0.0.1:" + base::UintToString16(server_port()) + L"/crash",
      data_directory(), permanent_failure_directory(),
      base::TimeDelta::FromMilliseconds(1),
      base::TimeDelta::FromMilliseconds(1),
      base::Bind(&OnUpload, base::Unretained(&report_id))));

  ASSERT_TRUE(instance);

  testing::UploadObserver upload_observer(upload_directory(),
                                          permanent_failure_directory());

  ASSERT_NO_FATAL_FAILURE(InvokeRpcFromChildProcess());

  base::FilePath minidump_path;
  std::map<std::string, std::string> crash_keys;
  bool upload_success = false;

  upload_observer.WaitForUpload(&minidump_path, &crash_keys, &upload_success);

  EXPECT_TRUE(upload_success);
  EXPECT_HRESULT_SUCCEEDED(
      testing::VisitMinidump(minidump_path, base::Bind(&ValidateMinidump)));
  Reporter::Shutdown(std::move(instance));

  auto entry = crash_keys.find(base::UTF16ToASCII(kCrashKey1Name));
  ASSERT_NE(entry, crash_keys.end());
  ASSERT_EQ(base::UTF16ToASCII(kCrashKey1Value), entry->second);
  entry = crash_keys.find(base::UTF16ToASCII(kCrashKey2Name));
  ASSERT_NE(entry, crash_keys.end());
  ASSERT_EQ(base::UTF16ToASCII(kCrashKey2Value), entry->second);
  entry =
      crash_keys.find(base::UTF16ToASCII(Reporter::kKaskoUploadedByVersion));
  ASSERT_NE(entry, crash_keys.end());
  ASSERT_EQ(KASKO_VERSION_STRING, entry->second);
  entry =
      crash_keys.find(base::UTF16ToASCII(Reporter::kKaskoGeneratedByVersion));
  ASSERT_NE(entry, crash_keys.end());
  ASSERT_EQ(KASKO_VERSION_STRING, entry->second);

  ASSERT_FALSE(report_id.empty());
}

TEST_F(ReporterTest, NoCallback) {
  std::unique_ptr<Reporter> instance(Reporter::Create(
      endpoint(),
      L"http://127.0.0.1:" + base::UintToString16(server_port()) + L"/crash",
      data_directory(), permanent_failure_directory(),
      base::TimeDelta::FromMilliseconds(1),
      base::TimeDelta::FromMilliseconds(1), Reporter::OnUploadCallback()));

  ASSERT_TRUE(instance);

  testing::UploadObserver upload_observer(upload_directory(),
                                          permanent_failure_directory());

  ASSERT_NO_FATAL_FAILURE(InvokeRpcFromChildProcess());

  base::FilePath minidump_path;
  std::map<std::string, std::string> crash_keys;
  bool upload_success = false;

  upload_observer.WaitForUpload(&minidump_path, &crash_keys, &upload_success);

  EXPECT_TRUE(upload_success);
  EXPECT_HRESULT_SUCCEEDED(
      testing::VisitMinidump(minidump_path, base::Bind(&ValidateMinidump)));

  Reporter::Shutdown(std::move(instance));
}

TEST_F(ReporterTest, SendReportForProcessTest) {
  base::string16 report_id;
  std::unique_ptr<Reporter> instance(Reporter::Create(
      endpoint(),
      L"http://127.0.0.1:" + base::UintToString16(server_port()) + L"/crash",
      data_directory(), permanent_failure_directory(),
      base::TimeDelta::FromMilliseconds(1),
      base::TimeDelta::FromMilliseconds(1),
      base::Bind(&OnUpload, base::Unretained(&report_id))));

  ASSERT_TRUE(instance);

  testing::UploadObserver upload_observer(upload_directory(),
                                          permanent_failure_directory());

  ASSERT_NO_FATAL_FAILURE(DoWithChildProcess(base::Bind(
      &InvokeSendReportForProcess, base::Unretained(instance.get()))));

  base::FilePath minidump_path;
  std::map<std::string, std::string> crash_keys;
  bool upload_success = false;
  upload_observer.WaitForUpload(&minidump_path, &crash_keys, &upload_success);

  EXPECT_TRUE(upload_success);
  EXPECT_HRESULT_SUCCEEDED(
      testing::VisitMinidump(minidump_path, base::Bind(&ValidateMinidump)));

  Reporter::Shutdown(std::move(instance));

  ASSERT_FALSE(report_id.empty());
}

TEST_F(ReporterTest, PermanentFailureTest) {
  base::string16 report_id;
  std::unique_ptr<Reporter> instance(Reporter::Create(
      endpoint(), L"http://127.0.0.1:" + base::UintToString16(server_port()) +
                      L"/crash_failure",
      data_directory(), permanent_failure_directory(),
      base::TimeDelta::FromMilliseconds(1),
      base::TimeDelta::FromMilliseconds(1),
      base::Bind(&OnUpload, base::Unretained(&report_id))));

  ASSERT_TRUE(instance);

  testing::UploadObserver upload_observer(upload_directory(),
                                          permanent_failure_directory());

  ASSERT_NO_FATAL_FAILURE(InvokeRpcFromChildProcess());

  base::FilePath minidump_path;
  std::map<std::string, std::string> crash_keys;
  bool upload_success = false;

  upload_observer.WaitForUpload(&minidump_path, &crash_keys, &upload_success);

  EXPECT_FALSE(upload_success);
  EXPECT_HRESULT_SUCCEEDED(
      testing::VisitMinidump(minidump_path, base::Bind(&ValidateMinidump)));

  Reporter::Shutdown(std::move(instance));

  ASSERT_TRUE(report_id.empty());
}

}  // namespace kasko
