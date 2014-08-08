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

#include "syzygy/trace/agent_logger/agent_logger.h"

#include "base/bind.h"
#include "base/callback.h"
#include "base/file_util.h"
#include "base/files/file_enumerator.h"
#include "base/files/file_path.h"
#include "base/files/scoped_temp_dir.h"
#include "base/strings/stringprintf.h"
#include "base/threading/thread.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/trace/agent_logger/agent_logger_rpc_impl.h"
#include "syzygy/trace/rpc/rpc_helpers.h"

namespace trace {
namespace agent_logger {

namespace {

using testing::_;
using testing::Return;
using trace::client::CreateRpcBinding;
using trace::client::InvokeRpc;
using trace::common::Service;

int __declspec(noinline) FunctionA(const base::Callback<void(void)>& callback) {
  callback.Run();
  return 1;
}

int __declspec(noinline) FunctionB(const base::Callback<void(void)>& callback) {
  return FunctionA(callback) + 1;
}

int __declspec(noinline) FunctionC(const base::Callback<void(void)>& callback) {
  return FunctionB(callback) + 1;
}

void __declspec(noinline) ExecuteCallbackWithKnownStack(
    const base::Callback<void(void)>& callback) {
  int value = FunctionC(callback);
  ASSERT_EQ(3, value);
}

bool TextContainsKnownStack(const std::string& text, size_t start_offset) {
  size_t function_a = text.find("FunctionA", start_offset);
  if (function_a == std::string::npos)
    return false;

  size_t function_b = text.find("FunctionB", function_a);
  if (function_b == std::string::npos)
    return false;

  size_t function_c = text.find("FunctionC", function_b);
  if (function_c == std::string::npos)
    return false;

  return true;
}

class TestLogger : public AgentLogger {
 public:
  using AgentLogger::destination_;
};

class LoggerTest : public testing::Test {
 public:
  MOCK_METHOD1(LoggerStartedCallback, bool(Service*));
  MOCK_METHOD1(LoggerInterruptedCallback, bool(Service*));
  MOCK_METHOD1(LoggerStoppedCallback, bool(Service*));

  LoggerTest()
      : io_thread_("LoggerTest IO Thread"), instance_manager_(&logger_) {
  }

  virtual void SetUp() OVERRIDE {
    ASSERT_NO_FATAL_FAILURE(testing::Test::SetUp());

    // Create a log file.
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    log_file_path_ = temp_dir_.path().AppendASCII("log.txt");
    ASSERT_TRUE(!log_file_path_.empty());
    log_file_.reset(base::OpenFile(log_file_path_, "wb"));
    ASSERT_TRUE(log_file_.get() != NULL);

    // Setup the instance ID.
    instance_id_ = base::StringPrintf(L"%d", ::GetCurrentProcessId());

    // Start the IO thread.
    ASSERT_TRUE(io_thread_.StartWithOptions(
        base::Thread::Options(base::MessageLoop::TYPE_IO, 0)));

    // Setup a logger to use.
    logger_.set_instance_id(instance_id_);
    logger_.set_minidump_dir(temp_dir_.path());
    logger_.set_destination(log_file_.get());
    logger_.set_started_callback(base::Bind(
        &LoggerTest::LoggerStartedCallback, base::Unretained(this)));
    logger_.set_interrupted_callback(base::Bind(
        &LoggerTest::LoggerInterruptedCallback, base::Unretained(this)));
    logger_.set_stopped_callback(base::Bind(
        &LoggerTest::LoggerStoppedCallback, base::Unretained(this)));

    // Validate that the Logger's constructor and setters have done their jobs.
    ASSERT_EQ(log_file_.get(), logger_.destination_);
    ASSERT_EQ(temp_dir_.path(), logger_.minidump_dir());
    ASSERT_TRUE(!logger_.instance_id().empty());
    ASSERT_TRUE(!logger_.started_callback().is_null());
    ASSERT_TRUE(!logger_.interrupted_callback().is_null());
    ASSERT_TRUE(!logger_.stopped_callback().is_null());
    ASSERT_EQ(AgentLogger::kUnused, logger_.state());

    // Start the logger.
    EXPECT_CALL(*this, LoggerStartedCallback(&logger_))
        .WillOnce(Return(true));
    ASSERT_TRUE(logger_.Start());
    ASSERT_EQ(AgentLogger::kRunning, logger_.state());

    // At some point we expect someone to stop the logger, and the logger
    // interrupted callback will fire.
    EXPECT_CALL(*this, LoggerInterruptedCallback(&logger_))
        .WillOnce(Return(true));
  }

  virtual void TearDown() OVERRIDE {
    if (logger_.state() != AgentLogger::kStopped) {
      ASSERT_TRUE(logger_.Stop());
      ASSERT_NO_FATAL_FAILURE(WaitForLoggerToFinish());
    }
  }

  void WaitForLoggerToFinish() {
    EXPECT_CALL(*this, LoggerStoppedCallback(&logger_))
        .WillOnce(Return(true));
    ASSERT_TRUE(logger_.Join());
    ASSERT_EQ(AgentLogger::kStopped, logger_.state());
  }

  void DoCaptureRemoteTrace(HANDLE process, std::vector<DWORD>* trace_data) {
    CONTEXT context = {};
    ::RtlCaptureContext(&context);
    ASSERT_TRUE(logger_.CaptureRemoteTrace(process, &context, trace_data));
  }

  static const char kLine1[];
  static const char kLine2[];
  static const char kLine3[];

  base::ScopedTempDir temp_dir_;
  base::FilePath log_file_path_;
  base::ScopedFILE log_file_;
  std::wstring instance_id_;
  base::Thread io_thread_;
  TestLogger logger_;
  RpcLoggerInstanceManager instance_manager_;
};

void DoRpcWriteWithContext(handle_t rpc_binding, const unsigned char* message) {
  CONTEXT rtl_context = {};
  ::RtlCaptureContext(&rtl_context);

  ExecutionContext exc_context = {};
  exc_context.edi = rtl_context.Edi;
  exc_context.esi = rtl_context.Esi;
  exc_context.ebx = rtl_context.Ebx;
  exc_context.edx = rtl_context.Edx;
  exc_context.ecx = rtl_context.Ecx;
  exc_context.eax = rtl_context.Eax;
  exc_context.ebp = rtl_context.Ebp;
  exc_context.eip = rtl_context.Eip;
  exc_context.seg_cs = rtl_context.SegCs;
  exc_context.eflags = rtl_context.EFlags;
  exc_context.esp = rtl_context.Esp;
  exc_context.seg_ss = rtl_context.SegSs;

  ASSERT_TRUE(
      LoggerClient_WriteWithContext(rpc_binding, message, &exc_context));
}

const char LoggerTest::kLine1[] = "This is line 1\n";
const char LoggerTest::kLine2[] = "This is line 2";  // Note no trailing '\n'.
const char LoggerTest::kLine3[] = "This is line 3\n";

inline const unsigned char* MakeUnsigned(const char* s) {
  return reinterpret_cast<const unsigned char*>(s);
}

void DoRpcCreateMiniDump(handle_t rpc_binding) {
  CONTEXT ctx = {};
  ::RtlCaptureContext(&ctx);
  EXCEPTION_RECORD exc_rec = {};
  exc_rec.ExceptionAddress = reinterpret_cast<void*>(ctx.Eip);
  exc_rec.ExceptionCode = EXCEPTION_ARRAY_BOUNDS_EXCEEDED;
  EXCEPTION_POINTERS exc_ptrs = { &exc_rec, &ctx };
  ASSERT_TRUE(
      LoggerClient_SaveMiniDump(rpc_binding,
                                ::GetCurrentThreadId(),
                                reinterpret_cast<unsigned long>(&exc_ptrs),
                                0));
}

}  // namespace

TEST_F(LoggerTest, StackTraceHandling) {
  HANDLE process = ::GetCurrentProcess();
  std::vector<DWORD> trace_data;
  ASSERT_NO_FATAL_FAILURE(ExecuteCallbackWithKnownStack(base::Bind(
      &LoggerTest::DoCaptureRemoteTrace,
      base::Unretained(this),
      process,
      &trace_data)));

  // Validate the returned textual stack trace.
  std::string text;
  ASSERT_TRUE(logger_.AppendTrace(
      process, trace_data.data(), trace_data.size(), &text));
  size_t function_a = text.find("FunctionA", 0);
  ASSERT_TRUE(function_a != std::string::npos);
  size_t function_b = text.find("FunctionB", function_a);
  ASSERT_TRUE(function_b != std::string::npos);
  size_t function_c = text.find("FunctionC", function_b);
  ASSERT_TRUE(function_c != std::string::npos);
}

TEST_F(LoggerTest, Write) {
  // Write the lines.
  ASSERT_TRUE(logger_.Write(kLine1));
  ASSERT_TRUE(logger_.Write(kLine2));
  ASSERT_TRUE(logger_.Write(kLine3));

  // Stop the logger.
  ASSERT_TRUE(logger_.Stop());
  ASSERT_NO_FATAL_FAILURE(WaitForLoggerToFinish());

  // Close the log file.
  log_file_.reset(NULL);

  // Read in the log contents.
  std::string contents;
  ASSERT_TRUE(base::ReadFileToString(log_file_path_, &contents));

  // Build the expected contents (append a newline to line2)
  std::string expected_contents(kLine1);
  expected_contents += kLine2;
  expected_contents += '\n';
  expected_contents += kLine3;

  // Compare the log contents.
  EXPECT_EQ(expected_contents, contents);
}

TEST_F(LoggerTest, RpcWrite) {
  // Connect to the logger over RPC.
  trace::client::ScopedRpcBinding rpc_binding;
  std::wstring endpoint(
      trace::client::GetInstanceString(kLoggerRpcEndpointRoot, instance_id_));
  ASSERT_TRUE(rpc_binding.Open(kLoggerRpcProtocol, endpoint));

  // Write to and stop the logger via RPC.
  ASSERT_TRUE(LoggerClient_Write(rpc_binding.Get(), MakeUnsigned(kLine1)));
  ASSERT_TRUE(LoggerClient_Write(rpc_binding.Get(), MakeUnsigned(kLine2)));
  ASSERT_TRUE(LoggerClient_Write(rpc_binding.Get(), MakeUnsigned(kLine3)));
  ASSERT_TRUE(LoggerClient_Stop(rpc_binding.Get()));
  ASSERT_TRUE(rpc_binding.Close());

  // Wait for the logger to finish shutting down.
  EXPECT_NO_FATAL_FAILURE(WaitForLoggerToFinish());

  // Close the log file.
  log_file_.reset(NULL);

  // Read in the log contents.
  std::string contents;
  ASSERT_TRUE(base::ReadFileToString(log_file_path_, &contents));

  // Build the expected contents (append a newline to line2)
  std::string expected_contents(kLine1);
  expected_contents += kLine2;
  expected_contents += '\n';
  expected_contents += kLine3;

  // Compare the log contents.
  EXPECT_EQ(expected_contents, contents);
}

TEST_F(LoggerTest, RpcWriteWithStack) {
  // Connect to the logger over RPC.
  trace::client::ScopedRpcBinding rpc_binding;
  std::wstring endpoint(
      trace::client::GetInstanceString(kLoggerRpcEndpointRoot, instance_id_));
  ASSERT_TRUE(rpc_binding.Open(kLoggerRpcProtocol, endpoint));

  HANDLE process = ::GetCurrentProcess();
  std::vector<DWORD> trace_data;
  ASSERT_NO_FATAL_FAILURE(ExecuteCallbackWithKnownStack(base::Bind(
      &LoggerTest::DoCaptureRemoteTrace,
      base::Unretained(this),
      process,
      &trace_data)));

  // Write to and stop the logger via RPC.
  ASSERT_TRUE(LoggerClient_WriteWithTrace(rpc_binding.Get(),
                                          MakeUnsigned(kLine1),
                                          trace_data.data(),
                                          trace_data.size()));
  ASSERT_TRUE(LoggerClient_Stop(rpc_binding.Get()));
  ASSERT_TRUE(rpc_binding.Close());

  // Wait for the logger to finish shutting down.
  EXPECT_NO_FATAL_FAILURE(WaitForLoggerToFinish());

  // Close the log file.
  log_file_.reset(NULL);

  // Read in the log contents.
  std::string text;
  ASSERT_TRUE(base::ReadFileToString(log_file_path_, &text));

  // Validate that we see the expected function chain.
  size_t line_1 = text.find(kLine1, 0);
  ASSERT_TRUE(line_1 != std::string::npos);
  ASSERT_TRUE(TextContainsKnownStack(text, line_1));
}

TEST_F(LoggerTest, RpcWriteWithContext) {
  // Connect to the logger over RPC.
  trace::client::ScopedRpcBinding rpc_binding;
  std::wstring endpoint(
      trace::client::GetInstanceString(kLoggerRpcEndpointRoot, instance_id_));
  ASSERT_TRUE(rpc_binding.Open(kLoggerRpcProtocol, endpoint));

  // Write to and stop the logger via RPC.
  ASSERT_NO_FATAL_FAILURE(ExecuteCallbackWithKnownStack(base::Bind(
      &DoRpcWriteWithContext,
      rpc_binding.Get(),
      MakeUnsigned(kLine2))));
  ASSERT_TRUE(LoggerClient_Stop(rpc_binding.Get()));
  ASSERT_TRUE(rpc_binding.Close());

  // Wait for the logger to finish shutting down.
  EXPECT_NO_FATAL_FAILURE(WaitForLoggerToFinish());

  // Close the log file.
  log_file_.reset(NULL);

  // Read in the log contents.
  std::string text;
  ASSERT_TRUE(base::ReadFileToString(log_file_path_, &text));

  // Validate that we see the expected function chain.
  size_t line_2 = text.find(kLine2, 0);
  ASSERT_TRUE(line_2 != std::string::npos);
  ASSERT_TRUE(TextContainsKnownStack(text, line_2));
}

TEST_F(LoggerTest, RpcGenerateMiniDump) {
  // Connect to the logger over RPC.
  trace::client::ScopedRpcBinding rpc_binding;
  std::wstring endpoint(
      trace::client::GetInstanceString(kLoggerRpcEndpointRoot, instance_id_));
  ASSERT_TRUE(rpc_binding.Open(kLoggerRpcProtocol, endpoint));

  // Write to and stop the logger via RPC.
  ASSERT_NO_FATAL_FAILURE(ExecuteCallbackWithKnownStack(base::Bind(
      &DoRpcCreateMiniDump,
      rpc_binding.Get())));
  ASSERT_TRUE(LoggerClient_Stop(rpc_binding.Get()));
  ASSERT_TRUE(rpc_binding.Close());

  // Wait for the logger to finish shutting down.
  EXPECT_NO_FATAL_FAILURE(WaitForLoggerToFinish());

  // We should have exactly one mini-dump in the temp directory.
  using base::FileEnumerator;
  FileEnumerator fe(temp_dir_.path(), false, FileEnumerator::FILES, L"*.dmp");
  base::FilePath mini_dump(fe.Next());
  EXPECT_FALSE(mini_dump.empty());
  EXPECT_TRUE(fe.Next().empty());

  // TODO(rogerm): Validate the stack-trace in the mini-dump.
}

}  // namespace agent_logger
}  // namespace trace
