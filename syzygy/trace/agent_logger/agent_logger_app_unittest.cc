// Copyright 2012 Google Inc. All Rights Reserved.
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

#include "syzygy/trace/agent_logger/agent_logger_app.h"

#include <psapi.h>
#include <userenv.h>
#include <memory>

#include "base/command_line.h"
#include "base/environment.h"
#include "base/path_service.h"
#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/process/kill.h"
#include "base/process/launch.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/common/align.h"
#include "syzygy/common/unittest_util.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/trace/agent_logger/agent_logger.h"
#include "syzygy/trace/client/client_utils.h"
#include "syzygy/trace/parse/parse_utils.h"
#include "syzygy/trace/protocol/call_trace_defs.h"
#include "syzygy/trace/service/service_rpc_impl.h"

namespace trace {
namespace agent_logger {

namespace {

class TestLoggerApp : public LoggerApp {
 public:
  using LoggerApp::FindActionHandler;
  using LoggerApp::OpenOutputFile;
  using LoggerApp::kStart;
  using LoggerApp::kSpawn;
  using LoggerApp::kStatus;
  using LoggerApp::kStop;
  using LoggerApp::kInstanceId;
  using LoggerApp::kUniqueInstanceId;
  using LoggerApp::kOutputFile;
  using LoggerApp::kMiniDumpDir;
  using LoggerApp::kStdOut;
  using LoggerApp::kStdErr;
  using LoggerApp::logger_command_line_;
  using LoggerApp::app_command_line_;
  using LoggerApp::instance_id_;
  using LoggerApp::action_;
  using LoggerApp::action_handler_;
  using LoggerApp::output_file_path_;
  using LoggerApp::append_;
  using LoggerApp::mini_dump_dir_;
};

typedef ::application::Application<TestLoggerApp> TestApp;

class LoggerAppTest : public testing::ApplicationTestBase {
 public:
  typedef testing::ApplicationTestBase Super;

  LoggerAppTest()
      : cmd_line_(base::FilePath(L"agent_logger.exe")),
        test_impl_(test_app_.implementation()) {
  }

  void SetUp() {
    Super::SetUp();

    // Several of the tests generate progress and (deliberate) error messages
    // that would otherwise clutter the unit-test output.
    logging::SetMinLogLevel(logging::LOG_FATAL);

    // Setup the IO streams.
    CreateTemporaryDir(&temp_dir_);
    stdin_path_ = temp_dir_.Append(L"NUL");
    stdout_path_ = temp_dir_.Append(L"stdout.txt");
    stderr_path_ = temp_dir_.Append(L"stderr.txt");
    InitStreams(stdin_path_, stdout_path_, stderr_path_);

    // Initialize the (potential) input and output path values.
    instance_id_ = base::StringPrintf(L"%d", ::GetCurrentProcessId());
    output_file_path_ = temp_dir_.Append(L"output.txt");

    // Point the application at the test's command-line and IO streams.
    test_app_.set_command_line(&cmd_line_);
    test_app_.set_in(in());
    test_app_.set_out(out());
    test_app_.set_err(err());
  }

 protected:
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
  base::CommandLine cmd_line_;
  std::wstring instance_id_;
  base::FilePath output_file_path_;
  // @}
};

}  // namespace

TEST_F(LoggerAppTest, GetHelp) {
  cmd_line_.AppendSwitch("help");
  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(LoggerAppTest, EmptyCommandLineFails) {
  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(LoggerAppTest, ParseUnknownActionFails) {
  cmd_line_.AppendArg("unknown");
  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(LoggerAppTest, ParseMispelledActionFails) {
  cmd_line_.AppendArg("star");
  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(LoggerAppTest, ParseUniqueInstanceId) {
  cmd_line_.AppendSwitch(TestLoggerApp::kUniqueInstanceId);
  cmd_line_.AppendArg("start");
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_EQ(TestLoggerApp::kMaxInstanceIdLength,
            test_impl_.instance_id_.size());
}

TEST_F(LoggerAppTest, ParseDefaultMiniDumpDir) {
  cmd_line_.AppendArg("start");
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));

  base::FilePath cwd;
  ASSERT_TRUE(::PathService::Get(base::DIR_CURRENT, &cwd));

  EXPECT_EQ(cwd, test_impl_.mini_dump_dir_);
}

TEST_F(LoggerAppTest, ParseMiniDumpDir) {
  base::FilePath new_mini_dump_dir(temp_dir_.Append(L"mini_dumps"));
  ASSERT_FALSE(base::DirectoryExists(new_mini_dump_dir));

  cmd_line_.AppendSwitchPath(TestLoggerApp::kMiniDumpDir, new_mini_dump_dir);
  cmd_line_.AppendArg("start");
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));

  EXPECT_EQ(new_mini_dump_dir, test_impl_.mini_dump_dir_);
  EXPECT_TRUE(base::DirectoryExists(new_mini_dump_dir));
}

TEST_F(LoggerAppTest, ParseBasicStart) {
  cmd_line_.AppendSwitchPath(
      TestLoggerApp::kOutputFile, output_file_path_);
  cmd_line_.AppendArgNative(TestLoggerApp::kStart);
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_EQ(output_file_path_, test_impl_.output_file_path_);
  EXPECT_TRUE(test_impl_.instance_id_.empty());
  EXPECT_EQ(std::wstring(TestLoggerApp::kStart), test_impl_.action_);
  EXPECT_TRUE(test_impl_.app_command_line_.get() == NULL);
  EXPECT_EQ(&TestLoggerApp::Start, test_impl_.action_handler_);
}

TEST_F(LoggerAppTest, ParseBasicStartWithCommand) {
  const base::FilePath kFooExe(L"foo.exe");
  cmd_line_.AppendSwitchPath(
      TestLoggerApp::kOutputFile, output_file_path_);
  cmd_line_.AppendArgNative(TestLoggerApp::kStart);
  cmd_line_.AppendArgNative(kFooExe.value());
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_EQ(output_file_path_, test_impl_.output_file_path_);
  EXPECT_EQ(std::wstring(TestLoggerApp::kStart), test_impl_.action_);
  EXPECT_TRUE(test_impl_.instance_id_.empty());
  EXPECT_TRUE(test_impl_.app_command_line_.get() != NULL);
  EXPECT_EQ(&TestLoggerApp::Start, test_impl_.action_handler_);
}

TEST_F(LoggerAppTest, ParseFullStartWithCommand) {
  const base::FilePath kFooExe(L"foo.exe");
  const std::wstring kSwitchName(L"switch");
  const std::wstring kSwitchValue(L"value");
  const std::wstring kDash(L"--");
  const std::wstring kArg1 = kDash + kSwitchName + L"=" + kSwitchValue;

  cmd_line_.AppendSwitchPath(
      TestLoggerApp::kOutputFile, output_file_path_);
  cmd_line_.AppendSwitchNative(
      TestLoggerApp::kInstanceId, instance_id_);
  cmd_line_.AppendArgNative(TestLoggerApp::kStart);
  cmd_line_.AppendArgNative(kDash);
  cmd_line_.AppendArgNative(kFooExe.value());
  cmd_line_.AppendArgNative(kArg1);
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_EQ(output_file_path_, test_impl_.output_file_path_);
  EXPECT_EQ(instance_id_, test_impl_.instance_id_);
  EXPECT_EQ(std::wstring(TestLoggerApp::kStart), test_impl_.action_);
  const base::CommandLine* app_cmd_line = test_impl_.app_command_line_.get();
  ASSERT_TRUE(app_cmd_line != NULL);
  EXPECT_EQ(kFooExe, app_cmd_line->GetProgram());
  EXPECT_TRUE(app_cmd_line->GetSwitches().empty());
  ASSERT_TRUE(app_cmd_line->GetArgs().size() == 1);
  EXPECT_TRUE(app_cmd_line->GetArgs().at(0) == kArg1);

  EXPECT_EQ(&TestLoggerApp::Start, test_impl_.action_handler_);
}

TEST_F(LoggerAppTest, ParseSpawn) {
  cmd_line_.AppendSwitchNative(
      TestLoggerApp::kInstanceId, instance_id_);
  cmd_line_.AppendArgNative(TestLoggerApp::kSpawn);
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_TRUE(test_impl_.output_file_path_.empty());
  EXPECT_EQ(instance_id_, test_impl_.instance_id_);
  EXPECT_EQ(std::wstring(TestLoggerApp::kSpawn), test_impl_.action_);
  EXPECT_EQ(NULL, test_impl_.app_command_line_.get());
  EXPECT_EQ(&TestLoggerApp::Spawn, test_impl_.action_handler_);
}

TEST_F(LoggerAppTest, ParseStop) {
  cmd_line_.AppendSwitchNative(
      TestLoggerApp::kInstanceId, instance_id_);
  cmd_line_.AppendArgNative(TestLoggerApp::kStop);
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_TRUE(test_impl_.output_file_path_.empty());
  EXPECT_EQ(instance_id_, test_impl_.instance_id_);
  EXPECT_EQ(std::wstring(TestLoggerApp::kStop), test_impl_.action_);
  EXPECT_EQ(NULL, test_impl_.app_command_line_.get());
  EXPECT_EQ(&TestLoggerApp::Stop, test_impl_.action_handler_);
}

TEST_F(LoggerAppTest, ParseStatus) {
  cmd_line_.AppendSwitchNative(
      TestLoggerApp::kInstanceId, instance_id_);
  cmd_line_.AppendArgNative(TestLoggerApp::kStatus);
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_TRUE(test_impl_.output_file_path_.empty());
  EXPECT_EQ(instance_id_, test_impl_.instance_id_);
  EXPECT_EQ(std::wstring(TestLoggerApp::kStatus), test_impl_.action_);
  EXPECT_EQ(NULL, test_impl_.app_command_line_.get());
  EXPECT_EQ(&TestLoggerApp::Status, test_impl_.action_handler_);
}

TEST_F(LoggerAppTest, ParseUnknown) {
  const std::wstring kUnknown(L"unknown");
  cmd_line_.AppendSwitchNative(
      TestLoggerApp::kInstanceId, instance_id_);
  cmd_line_.AppendArgNative(kUnknown);
  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_TRUE(test_impl_.output_file_path_.empty());
  EXPECT_EQ(instance_id_, test_impl_.instance_id_);
  EXPECT_EQ(kUnknown, test_impl_.action_);
  EXPECT_EQ(NULL, test_impl_.app_command_line_.get());
  EXPECT_TRUE(test_impl_.action_handler_ == NULL);
}

TEST_F(LoggerAppTest, StartEndToEnd) {
  cmd_line_.AppendSwitchNative(
      TestLoggerApp::kInstanceId, instance_id_);
  cmd_line_.AppendArgNative(TestLoggerApp::kStart);
  cmd_line_.AppendArgNative(L"--");
  cmd_line_.AppendArgNative(L"cmd.exe");
  cmd_line_.AppendArgNative(L"/C");
  cmd_line_.AppendArgNative(L"date /t");

  ASSERT_EQ(0, test_app_.Run());
}

TEST_F(LoggerAppTest, StartSetsStopResetsEvent) {
  // The maximum time we're willing to wait for the process to get
  // started/killed. This is very generous, but also prevents the unittests
  // from hanging if the event never fires.
  static const size_t kTimeOutMs = 10000;

  // We need a different instance ID because we are spawning a new process
  // otherwise we get a conflict with the test above (permission issue).
  // TODO(georgesak): Look into that issue.
  instance_id_ += L"-0";
  cmd_line_.SetProgram(testing::GetExeRelativePath(L"agent_logger.exe"));
  cmd_line_.AppendSwitchNative(TestLoggerApp::kInstanceId, instance_id_);
  // Saving the command line to be used when stopping the logger.
  base::CommandLine cmd_line_saved(cmd_line_);
  cmd_line_.AppendArgNative(TestLoggerApp::kStart);

  // Launch the logger as a separate process and make sure it succeeds.
  base::LaunchOptions options;
  options.start_hidden = true;
  base::Process logger_process = base::LaunchProcess(cmd_line_, options);
  ASSERT_TRUE(logger_process.IsValid());

  std::wstring event_name;
  AgentLogger::GetSyzygyAgentLoggerEventName(instance_id_, &event_name);
  base::win::ScopedHandle event(
      ::CreateEvent(NULL, FALSE, FALSE, event_name.c_str()));
  EXPECT_EQ(WAIT_OBJECT_0, ::WaitForSingleObject(event.Get(), kTimeOutMs));
  cmd_line_ = cmd_line_saved;
  cmd_line_.AppendArgNative(TestLoggerApp::kStop);
  base::Process logger_process_kill = base::LaunchProcess(cmd_line_, options);
  ASSERT_TRUE(logger_process_kill.IsValid());
  int exit_code = 0;
  ASSERT_TRUE(logger_process.WaitForExitWithTimeout(
      base::TimeDelta::FromMilliseconds(kTimeOutMs), &exit_code));
  ASSERT_EQ(WAIT_TIMEOUT, ::WaitForSingleObject(event.Get(), 0));
}

}  // namespace agent_logger
}  // namespace trace
