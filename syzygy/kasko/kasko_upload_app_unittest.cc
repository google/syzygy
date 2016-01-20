// Copyright 2016 Google Inc. All Rights Reserved.
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

#include "syzygy/kasko/kasko_upload_app.h"

#include "base/files/file_util.h"
#include "base/strings/stringprintf.h"
#include "gtest/gtest.h"
#include "syzygy/common/unittest_util.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/kasko/crash_keys_serialization.h"
#include "syzygy/kasko/testing/test_server.h"

namespace kasko {

// A server that is unlikely to exist. Even if it does exist, the path is very
// unlikely to exist, so this should fail most anywhere.
static const base::string16 kDummyServer(
    L"http:/bla.bar.baz.google.com:65001/unlikely/to/exist");

class KaskoUploadAppTest : public ::testing::ApplicationTestBase {
 public:
  typedef ::testing::ApplicationTestBase Super;
  typedef application::Application<KaskoUploadApp> TestApplication;

  KaskoUploadAppTest()
      : cmd_line_(base::FilePath(L"kasko_upload.exe")),
        impl_(app_.implementation()) {
  }

  void SetUp() override {
    Super::SetUp();

    // Setup the IO streams.
    ASSERT_NO_FATAL_FAILURE(CreateTemporaryDir(&temp_dir_));
    stdin_path_ = temp_dir_.Append(L"NUL");
    stdout_path_ = temp_dir_.Append(L"stdout.txt");
    stderr_path_ = temp_dir_.Append(L"stderr.txt");
    ASSERT_NO_FATAL_FAILURE(InitStreams(
        stdin_path_, stdout_path_, stderr_path_));

    // Point the application at the test's command-line and IO streams.
    app_.set_command_line(&cmd_line_);
    app_.set_in(in());
    app_.set_out(out());
    app_.set_err(err());
  }

  base::FilePath ValidMinidumpPath() const {
    return ::testing::GetSrcRelativePath(
        L"syzygy/poirot/test_data/use-after-free.dmp");
  }

  base::FilePath InvalidMinidumpPath() const {
    return base::FilePath(L"Z:\\this\\does\\not\\exist.dmp");
  }

  base::FilePath ValidCrashKeysPath() const {
    base::FilePath path = temp_dir_.Append(L"valid-crash-keys.kys");
    if (!base::PathExists(path)) {
      std::map<base::string16, base::string16> crash_keys;
      crash_keys[L"channel"] = L"canary";
      crash_keys[L"guid"] = L"aa2f3148-3a99-4b92-b53b-8ce5ee0ab6ec";
      crash_keys[L"platform"] = L"win32";
      crash_keys[L"prod"] = L"Chrome";
      crash_keys[L"ptype"] = L"browser";
      crash_keys[L"ver"] = L"49.0.2619.1";
      crash_keys[L"metrics_client_id"] = L"BDB9F5962B1F43E18C530B0BA1B80040";
      EXPECT_TRUE(WriteCrashKeysToFile(path, crash_keys));
    }
    return path;
  }

  base::FilePath IncompleteCrashKeysPath() const {
    base::FilePath path = temp_dir_.Append(L"incomplete-crash-keys.kys");
    if (!base::PathExists(path)) {
      std::map<base::string16, base::string16> crash_keys;
      crash_keys[L"foo"] = L"bar";
      EXPECT_TRUE(WriteCrashKeysToFile(path, crash_keys));
    }
    return path;
  }

  base::FilePath MalformedCrashKeysPath() const {
    static const char kBadData[] = "this is \"no good as a } JSON dictionary";
    base::FilePath path = temp_dir_.Append(L"malformed-crash-keys.kys");
    if (!base::PathExists(path))
      base::WriteFile(path, kBadData, sizeof(kBadData));
    return path;
  }

  base::FilePath InvalidCrashKeysPath() const {
    return base::FilePath(L"Z:\\not\\a\\valid\\path.kys");
  }

  // The command line to be given to the application under test.
  base::CommandLine cmd_line_;

  // The application object under test.
  TestApplication app_;

  // A reference to the underlying application implementation for convenience.
  KaskoUploadApp& impl_;

  // A temporary folder where all IO will be stored.
  base::FilePath temp_dir_;

  // @name File paths used for the standard IO streams.
  // @{
  base::FilePath stdin_path_;
  base::FilePath stdout_path_;
  base::FilePath stderr_path_;
  // @}
};

TEST_F(KaskoUploadAppTest, FailedParseMissingMinidump) {
  ASSERT_FALSE(impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(KaskoUploadAppTest, SuccessfulParseMinimal) {
  cmd_line_.AppendSwitchPath(KaskoUploadApp::kMinidumpSwitch,
                             InvalidMinidumpPath());
  ASSERT_TRUE(impl_.ParseCommandLine(&cmd_line_));
  EXPECT_EQ(InvalidMinidumpPath(), impl_.minidump_path());

  base::FilePath expected_crash_keys_path =
      impl_.minidump_path().ReplaceExtension(L".kys");
  EXPECT_EQ(expected_crash_keys_path, impl_.crash_keys_path());

  EXPECT_EQ(impl_.kDefaultUploadUrl, impl_.upload_url());
}

TEST_F(KaskoUploadAppTest, SuccessfulParseFull) {
  cmd_line_.AppendSwitchPath(KaskoUploadApp::kMinidumpSwitch,
                             InvalidMinidumpPath());
  cmd_line_.AppendSwitchPath(KaskoUploadApp::kCrashKeysSwitch,
                             InvalidCrashKeysPath());
  cmd_line_.AppendSwitchNative(KaskoUploadApp::kUploadUrlSwitch, kDummyServer);
  ASSERT_TRUE(impl_.ParseCommandLine(&cmd_line_));

  EXPECT_EQ(InvalidMinidumpPath(), impl_.minidump_path());
  EXPECT_EQ(InvalidCrashKeysPath(), impl_.crash_keys_path());
  EXPECT_EQ(kDummyServer, impl_.upload_url());
}

TEST_F(KaskoUploadAppTest, CrashKeysFileMissing) {
  cmd_line_.AppendSwitchPath(KaskoUploadApp::kMinidumpSwitch,
                             ValidMinidumpPath());
  cmd_line_.AppendSwitchPath(KaskoUploadApp::kCrashKeysSwitch,
                             InvalidCrashKeysPath());
  EXPECT_EQ(KaskoUploadApp::kReturnCodeCrashKeysFileMissing, app_.Run());
}

TEST_F(KaskoUploadAppTest, CrashKeysFileMalformed) {
  cmd_line_.AppendSwitchPath(KaskoUploadApp::kMinidumpSwitch,
                             ValidMinidumpPath());
  cmd_line_.AppendSwitchPath(KaskoUploadApp::kCrashKeysSwitch,
                             MalformedCrashKeysPath());
  EXPECT_EQ(KaskoUploadApp::kReturnCodeCrashKeysFileMalformed, app_.Run());
}

TEST_F(KaskoUploadAppTest, CrashKeysAbsent) {
  cmd_line_.AppendSwitchPath(KaskoUploadApp::kMinidumpSwitch,
                             ValidMinidumpPath());
  cmd_line_.AppendSwitchPath(KaskoUploadApp::kCrashKeysSwitch,
                             IncompleteCrashKeysPath());
  EXPECT_EQ(KaskoUploadApp::kReturnCodeCrashKeysAbsent, app_.Run());
}

TEST_F(KaskoUploadAppTest, MinidumpFileMissing) {
  cmd_line_.AppendSwitchPath(KaskoUploadApp::kMinidumpSwitch,
                             InvalidMinidumpPath());
  cmd_line_.AppendSwitchPath(KaskoUploadApp::kCrashKeysSwitch,
                             ValidCrashKeysPath());
  EXPECT_EQ(KaskoUploadApp::kReturnCodeMinidumpFileMissing, app_.Run());
}

TEST_F(KaskoUploadAppTest, UploadFailed) {
  cmd_line_.AppendSwitchPath(KaskoUploadApp::kMinidumpSwitch,
                             ValidMinidumpPath());
  cmd_line_.AppendSwitchPath(KaskoUploadApp::kCrashKeysSwitch,
                             ValidCrashKeysPath());
  cmd_line_.AppendSwitchNative(KaskoUploadApp::kUploadUrlSwitch, kDummyServer);
  EXPECT_EQ(KaskoUploadApp::kReturnCodeUploadFailed, app_.Run());
}

TEST_F(KaskoUploadAppTest, UploadSucceeds) {
  kasko::testing::TestServer test_server;
  ASSERT_TRUE(test_server.Start());
  base::string16 upload_url = base::StringPrintf(L"http://localhost:%d/crash",
                                                 test_server.port());

  cmd_line_.AppendSwitchPath(KaskoUploadApp::kMinidumpSwitch,
                             ValidMinidumpPath());
  cmd_line_.AppendSwitchPath(KaskoUploadApp::kCrashKeysSwitch,
                             ValidCrashKeysPath());
  cmd_line_.AppendSwitchNative(KaskoUploadApp::kUploadUrlSwitch, upload_url);

  EXPECT_EQ(KaskoUploadApp::kReturnCodeSuccess, app_.Run());
}

}  // namespace kasko
