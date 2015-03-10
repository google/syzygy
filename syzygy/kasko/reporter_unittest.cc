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

#include <string>

#include "base/bind.h"
#include "base/files/file_path.h"
#include "base/files/scoped_temp_dir.h"
#include "base/memory/scoped_ptr.h"
#include "base/strings/string16.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/utf_string_conversions.h"
#include "base/time/time.h"
#include "gtest/gtest.h"
#include "syzygy/common/rpc/helpers.h"
#include "syzygy/kasko/kasko_rpc.h"
#include "syzygy/kasko/testing/minidump_unittest_helpers.h"
#include "syzygy/kasko/testing/test_server.h"
#include "syzygy/kasko/testing/upload_observer.h"

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

const char kCrashKey1Name[] = "foo";
const char kCrashKey1Value[] = "bar";
const char kCrashKey2Name[] = "hello";
const char kCrashKey2Value[] = "world";

// Invokes the diagnostic report RPC service at |endpoint|, requesting a dump of
// the current process, and including |protobuf|.
void DoInvokeService(const base::string16& endpoint,
                     const std::string& protobuf) {
  common::rpc::ScopedRpcBinding rpc_binding;
  ASSERT_TRUE(rpc_binding.Open(L"ncalrpc", endpoint));

  CrashKey crash_keys[] = {
      {reinterpret_cast<const signed char*>(kCrashKey1Name),
       reinterpret_cast<const signed char*>(kCrashKey1Value)},
      {reinterpret_cast<const signed char*>(kCrashKey2Name),
       reinterpret_cast<const signed char*>(kCrashKey2Value)}};

  common::rpc::RpcStatus status = common::rpc::InvokeRpc(
      KaskoClient_SendDiagnosticReport, rpc_binding.Get(), NULL, 0, SMALL_DUMP,
      protobuf.length(), reinterpret_cast<const signed char*>(protobuf.c_str()),
      arraysize(crash_keys), crash_keys);
  ASSERT_FALSE(status.exception_occurred);
  ASSERT_TRUE(status.succeeded());
}

// Verifies that the uploaded minidump is plausibly a dump of this test process.
void ValidateMinidump(IDebugClient4* debug_client,
                      IDebugControl* debug_control,
                      IDebugSymbols* debug_symbols) {
  ASSERT_HRESULT_SUCCEEDED(
      debug_symbols->GetModuleByModuleName("kasko_unittests", 0, NULL, NULL));
}

}  // namespace

class ReporterTest : public ::testing::Test {
 public:
  ReporterTest() {}

  virtual void SetUp() override {
    ASSERT_TRUE(server_.Start());
    ASSERT_TRUE(temp_directory_.CreateUniqueTempDir());
  }

 protected:
  uint16_t server_port() { return server_.port(); }

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

  DISALLOW_COPY_AND_ASSIGN(ReporterTest);
};

TEST_F(ReporterTest, DISABLED_BasicTest) {
  scoped_ptr<Reporter> instance(Reporter::Create(
      L"test_endpoint",
      L"http://127.0.0.1:" + base::UintToString16(server_port()) + L"/crash",
      data_directory(), permanent_failure_directory(),
      base::TimeDelta::FromMilliseconds(1),
      base::TimeDelta::FromMilliseconds(1)));

  ASSERT_TRUE(instance);

  testing::UploadObserver upload_observer(upload_directory(),
                                          permanent_failure_directory());

  ASSERT_NO_FATAL_FAILURE(DoInvokeService(L"test_endpoint", "protobuf"));

  base::FilePath minidump_path;
  std::map<std::string, std::string> crash_keys;
  bool upload_success = false;

  upload_observer.WaitForUpload(&minidump_path, &crash_keys, &upload_success);

  ASSERT_TRUE(upload_success);
  EXPECT_HRESULT_SUCCEEDED(
      testing::VisitMinidump(minidump_path, base::Bind(&ValidateMinidump)));

  Reporter::Shutdown(instance.Pass());
}

TEST_F(ReporterTest, DISABLED_SendReportForProcessTest) {
  scoped_ptr<Reporter> instance(Reporter::Create(
      L"test_endpoint",
      L"http://127.0.0.1:" + base::UintToString16(server_port()) + L"/crash",
      data_directory(), permanent_failure_directory(),
      base::TimeDelta::FromMilliseconds(1),
      base::TimeDelta::FromMilliseconds(1)));

  ASSERT_TRUE(instance);

  testing::UploadObserver upload_observer(upload_directory(),
                                          permanent_failure_directory());

  std::map<base::string16, base::string16> crash_keys_in;
  crash_keys_in[base::UTF8ToUTF16(kCrashKey1Name)] =
      base::UTF8ToUTF16(kCrashKey1Value);
  crash_keys_in[base::UTF8ToUTF16(kCrashKey2Name)] =
      base::UTF8ToUTF16(kCrashKey2Value);

  instance->SendReportForProcess(base::GetCurrentProcessHandle(),
                                 SMALL_DUMP_TYPE, crash_keys_in);

  base::FilePath minidump_path;
  std::map<std::string, std::string> crash_keys;
  bool upload_success = false;
  upload_observer.WaitForUpload(&minidump_path, &crash_keys, &upload_success);

  ASSERT_TRUE(upload_success);
  EXPECT_HRESULT_SUCCEEDED(
      testing::VisitMinidump(minidump_path, base::Bind(&ValidateMinidump)));

  Reporter::Shutdown(instance.Pass());
}

TEST_F(ReporterTest, DISABLED_PermanentFailureTest) {
  scoped_ptr<Reporter> instance(Reporter::Create(
      L"test_endpoint",
      L"http://127.0.0.1:" + base::UintToString16(server_port()) +
          L"/crash_failure",
      data_directory(), permanent_failure_directory(),
      base::TimeDelta::FromMilliseconds(1),
      base::TimeDelta::FromMilliseconds(1)));

  ASSERT_TRUE(instance);

  testing::UploadObserver upload_observer(upload_directory(),
                                          permanent_failure_directory());

  ASSERT_NO_FATAL_FAILURE(DoInvokeService(L"test_endpoint", "protobuf"));

  base::FilePath minidump_path;
  std::map<std::string, std::string> crash_keys;
  bool upload_success = false;

  upload_observer.WaitForUpload(&minidump_path, &crash_keys, &upload_success);

  ASSERT_FALSE(upload_success);
  EXPECT_HRESULT_SUCCEEDED(
      testing::VisitMinidump(minidump_path, base::Bind(&ValidateMinidump)));

  Reporter::Shutdown(instance.Pass());
}

}  // namespace kasko
