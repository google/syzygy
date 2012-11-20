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

#include "syzygy/trace/logger/logger.h"

#include "base/bind.h"
#include "base/file_path.h"
#include "base/file_util.h"
#include "base/scoped_temp_dir.h"
#include "base/stringprintf.h"
#include "base/threading/thread.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/trace/logger/logger_rpc_impl.h"
#include "syzygy/trace/rpc/rpc_helpers.h"

namespace trace {
namespace logger {

namespace {

using testing::_;
using testing::Return;
using trace::client::CreateRpcBinding;
using trace::client::InvokeRpc;

class TestLogger : public Logger {
 public:
  using Logger::owning_thread_id_;
  using Logger::destination_;
  using Logger::state_;
  using Logger::instance_id_;
  using Logger::logger_started_callback_;
  using Logger::logger_stopped_callback_;
};

class LoggerTest : public testing::Test {
 public:
  MOCK_METHOD1(LoggerStartedCallback, bool(Logger*));
  MOCK_METHOD1(LoggerStoppedCallback, bool(Logger*));

  LoggerTest() : io_thread_("LoggerTest IO Thread") {
  }

  virtual void SetUp() OVERRIDE {
    ASSERT_NO_FATAL_FAILURE(testing::Test::SetUp());

    // Create a log file.
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    log_file_path_ = temp_dir_.path().AppendASCII("log.txt");
    ASSERT_TRUE(!log_file_path_.empty());
    log_file_.reset(file_util::OpenFile(log_file_path_, "wb"));
    ASSERT_TRUE(log_file_.get() != NULL);

    // Setup the instance ID.
    instance_id_ = base::StringPrintf(L"%d", ::GetCurrentProcessId());

    // Start the IO thread.
    ASSERT_TRUE(io_thread_.StartWithOptions(
        base::Thread::Options(MessageLoop::TYPE_IO, 0)));

    // Setup a logger to use.
    logger_.set_instance_id(instance_id_);
    logger_.set_destination(log_file_.get());
    logger_.set_logger_started_callback(
        base::Bind(&LoggerTest::LoggerStartedCallback, base::Unretained(this)));
    logger_.set_logger_stopped_callback(
        base::Bind(&LoggerTest::LoggerStoppedCallback, base::Unretained(this)));

    // Validate that the Logger's constructor and setters have done their jobs.
    ASSERT_EQ(base::PlatformThread::CurrentId(), logger_.owning_thread_id_);
    ASSERT_EQ(log_file_.get(), logger_.destination_);
    ASSERT_TRUE(!logger_.instance_id_.empty());
    ASSERT_TRUE(!logger_.logger_started_callback_.is_null());
    ASSERT_TRUE(!logger_.logger_stopped_callback_.is_null());
    ASSERT_EQ(Logger::kStopped, logger_.state_);
  }

  static const char kLine1[];
  static const char kLine2[];
  static const char kLine3[];

  ScopedTempDir temp_dir_;
  FilePath log_file_path_;
  file_util::ScopedFILE log_file_;
  std::wstring instance_id_;
  base::Thread io_thread_;
  TestLogger logger_;
};

const char LoggerTest::kLine1[] = "This is line 1\n";
const char LoggerTest::kLine2[] = "This is line 2";  // Note no trailing '\n'.
const char LoggerTest::kLine3[] = "This is line 3\n";

inline const unsigned char* MakeUnsigned(const char* s) {
  return reinterpret_cast<const unsigned char*>(s);
}

// TODO(rogerm): Move to rpc helpers?
class RpcBinding {
 public:
  RpcBinding() : rpc_binding_(NULL) {
  }

  ~RpcBinding() {
    Close();
  }

  operator handle_t() const { return rpc_binding_; }

  bool Open(const base::StringPiece16& protocol,
            const base::StringPiece16& endpoint) {
    if (!CreateRpcBinding(protocol, endpoint, &rpc_binding_))
      return false;
    return true;
  }

  bool Close() {
    if (rpc_binding_ == NULL)
      return true;

    RPC_STATUS status = ::RpcBindingFree(&rpc_binding_);
    rpc_binding_ = NULL;
    if (status != RPC_S_OK)
      return false;

    return true;
  }

 protected:
  handle_t rpc_binding_;
};

}  // namespace

TEST_F(LoggerTest, StartStop) {
  // Start the logger.
  EXPECT_CALL(*this, LoggerStartedCallback(&logger_))
      .WillOnce(Return(true));
  ASSERT_TRUE(logger_.Start());
  ASSERT_EQ(Logger::kRunning, logger_.state_);

  // Stop the logger (asynchronously).
  ASSERT_TRUE(logger_.Stop());

  // Run the logger to completion.
  EXPECT_CALL(*this, LoggerStoppedCallback(&logger_))
      .WillOnce(Return(true));
  ASSERT_TRUE(logger_.RunToCompletion());
  ASSERT_EQ(Logger::kStopped, logger_.state_);
}

TEST_F(LoggerTest, Write) {
  // Start the logger.
  EXPECT_CALL(*this, LoggerStartedCallback(&logger_))
      .WillOnce(Return(true));
  ASSERT_TRUE(logger_.Start());

  // Write the lines.
  ASSERT_TRUE(logger_.Write(kLine1));
  ASSERT_TRUE(logger_.Write(kLine2));
  ASSERT_TRUE(logger_.Write(kLine3));

  // Stop the logger (asynchronously).
  ASSERT_TRUE(logger_.Stop());

  // Run the logger to completion.
  EXPECT_CALL(*this, LoggerStoppedCallback(&logger_))
      .WillOnce(Return(true));
  ASSERT_TRUE(logger_.RunToCompletion());
  ASSERT_EQ(Logger::kStopped, logger_.state_);

  // Close the log file.
  log_file_.reset(NULL);

  // Read in the log contents.
  std::string contents;
  ASSERT_TRUE(file_util::ReadFileToString(log_file_path_, &contents));

  // Build the expected contents (append a newline to line2)
  std::string expected_contents(kLine1);
  expected_contents += kLine2;
  expected_contents += '\n';
  expected_contents += kLine3;

  // Compare the log contents.
  EXPECT_EQ(expected_contents, contents);
}

TEST_F(LoggerTest, RpcEntryPoints) {
  // Hook up the logger instance to the RPC engine.
  RpcLoggerInstanceManager instance_manager(&logger_);

  // Start the logger.
  EXPECT_CALL(*this, LoggerStartedCallback(&logger_))
      .WillOnce(Return(true));
  ASSERT_TRUE(logger_.Start());
  ASSERT_EQ(Logger::kRunning, logger_.state_);

  // Connect to the logger over RPC.
  RpcBinding rpc_binding;
  std::wstring endpoint(
      Logger::GetInstanceString(kLoggerRpcEndpointRoot, instance_id_));
  ASSERT_TRUE(rpc_binding.Open(kLoggerRpcProtocol, endpoint));

  // Write to and stop the logger via RPC.
  ASSERT_TRUE(LoggerClient_Write(rpc_binding, MakeUnsigned(kLine1)));
  ASSERT_TRUE(LoggerClient_Write(rpc_binding, MakeUnsigned(kLine2)));
  ASSERT_TRUE(LoggerClient_Write(rpc_binding, MakeUnsigned(kLine3)));
  ASSERT_TRUE(LoggerClient_Stop(rpc_binding));
  ASSERT_TRUE(rpc_binding.Close());

  // Run the logger to completion.
  EXPECT_CALL(*this, LoggerStoppedCallback(&logger_))
      .WillOnce(Return(true));
  ASSERT_TRUE(logger_.RunToCompletion());
  ASSERT_EQ(Logger::kStopped, logger_.state_);

  // Close the log file.
  log_file_.reset(NULL);

  // Read in the log contents.
  std::string contents;
  ASSERT_TRUE(file_util::ReadFileToString(log_file_path_, &contents));

  // Build the expected contents (append a newline to line2)
  std::string expected_contents(kLine1);
  expected_contents += kLine2;
  expected_contents += '\n';
  expected_contents += kLine3;

  // Compare the log contents.
  EXPECT_EQ(expected_contents, contents);
}

}  // namespace logger
}  // namespace trace
