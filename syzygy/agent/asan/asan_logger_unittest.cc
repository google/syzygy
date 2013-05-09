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

#include "syzygy/agent/asan/asan_logger.h"

#include <string>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/environment.h"
#include "base/file_util.h"
#include "base/string_util.h"
#include "base/stringprintf.h"
#include "base/utf_string_conversions.h"
#include "base/files/file_path.h"
#include "base/files/scoped_temp_dir.h"
#include "base/memory/scoped_ptr.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/trace/logger/logger.h"
#include "syzygy/trace/logger/logger_rpc_impl.h"
#include "syzygy/trace/protocol/call_trace_defs.h"

namespace agent {
namespace asan {

namespace {

using testing::Return;

class TestAsanLogger : public AsanLogger {
 public:
  using AsanLogger::instance_id_;
  using AsanLogger::rpc_binding_;
};

class AsanLoggerTest : public testing::Test {
 public:
  AsanLoggerTest() {
    EXPECT_TRUE(temp_dir_.CreateUniqueTempDir());
    temp_path_ = temp_dir_.path().Append(L"log.txt");

    // Setup the instance id.
    instance_id_ = base::StringPrintf(L"%d", ::GetCurrentProcessId());
  }

  MOCK_METHOD1(LoggerStoppedCallback, bool(trace::common::Service*));

 protected:
  base::ScopedTempDir temp_dir_;
  base::FilePath temp_path_;
  std::wstring instance_id_;
  TestAsanLogger client_;
};

}  // namespace

TEST_F(AsanLoggerTest, EndToEnd) {
  const std::string kMessage("This is the test message\n");

  {
    // Setup a log file destination.
    file_util::ScopedFILE destination(file_util::OpenFile(temp_path_, "wb"));

    // Start up the logging service.
    trace::logger::Logger server;
    trace::logger::RpcLoggerInstanceManager instance_manager(&server);
    server.set_instance_id(instance_id_);
    server.set_destination(destination.get());
    ASSERT_TRUE(server.Start());

    // Use the AsanLogger client.
    client_.set_instance_id(instance_id_);
    client_.Init();
    ASSERT_EQ(instance_id_, client_.instance_id_);
    ASSERT_TRUE(client_.rpc_binding_.Get() != NULL);
    client_.Write(kMessage);

    // Shutdown the logging service.
    ASSERT_TRUE(server.Stop());
    ASSERT_TRUE(server.Join());
  }

  std::string content;
  ASSERT_TRUE(file_util::ReadFileToString(temp_path_, &content));
  ASSERT_THAT(content, testing::EndsWith(kMessage));
}

TEST_F(AsanLoggerTest, Stop) {
  // Setup a log file destination.
  file_util::ScopedFILE destination(file_util::OpenFile(temp_path_, "wb"));

  // Start up the logging service.
  trace::logger::Logger server;
  trace::logger::RpcLoggerInstanceManager instance_manager(&server);
  server.set_instance_id(instance_id_);
  server.set_destination(destination.get());
  server.set_stopped_callback(
      base::Bind(&AsanLoggerTest::LoggerStoppedCallback,
                 base::Unretained(this)));
  ASSERT_TRUE(server.Start());

  // Use the AsanLogger client.
  client_.set_instance_id(instance_id_);
  client_.Init();
  ASSERT_EQ(instance_id_, client_.instance_id_);
  ASSERT_TRUE(client_.rpc_binding_.Get() != NULL);

  trace::common::Service* server_base = static_cast<trace::common::Service*>(
      &server);
  EXPECT_CALL(*this, LoggerStoppedCallback(server_base)).Times(1).
      WillOnce(Return(true));
  client_.Stop();
  ASSERT_TRUE(server.Join());
}

}  // namespace asan
}  // namespace agent
