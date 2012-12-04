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

#include "base/environment.h"
#include "base/file_path.h"
#include "base/file_util.h"
#include "base/scoped_temp_dir.h"
#include "base/stringprintf.h"
#include "base/utf_string_conversions.h"
#include "base/memory/scoped_ptr.h"
#include "gtest/gtest.h"
#include "syzygy/trace/logger/logger.h"
#include "syzygy/trace/logger/logger_rpc_impl.h"
#include "syzygy/trace/protocol/call_trace_defs.h"

namespace agent {
namespace asan {

namespace {

class TestAsanLogger : public AsanLogger {
 public:
  using AsanLogger::instance_id_;
  using AsanLogger::rpc_binding_;
};

class AsanLoggerTest : public testing::Test {
 public:
  virtual void TearDown() OVERRIDE {
    AsanLogger::SetInstance(NULL);
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
  }

  ScopedTempDir temp_dir_;
};

}  // namespace

TEST_F(AsanLoggerTest, Instance) {
  TestAsanLogger logger;
  ASSERT_TRUE(AsanLogger::Instance() == NULL);
  AsanLogger::SetInstance(&logger);
  EXPECT_TRUE(AsanLogger::Instance() == &logger);
}

TEST_F(AsanLoggerTest, EndToEnd) {
  // Setup the instance id.
  std::wstring instance_id(base::StringPrintf(L"%d", ::GetCurrentProcessId()));

  // The location to which we'll write log messages.
  FilePath temp_path(temp_dir_.path().Append(L"log.txt"));
  const std::string kMessage("This is the test message\n");

  {
    // Setup a log file destination.
    file_util::ScopedFILE destination(file_util::OpenFile(temp_path, "wb"));

    // Start up the logging service.
    trace::logger::Logger server;
    trace::logger::RpcLoggerInstanceManager instance_manager(&server);
    server.set_instance_id(instance_id);
    server.set_destination(destination.get());
    ASSERT_TRUE(server.Start());

    // Create and use the AsanLogger client.
    TestAsanLogger client;
    client.set_instance_id(instance_id);
    client.Init();
    ASSERT_EQ(instance_id, client.instance_id_);
    ASSERT_TRUE(client.rpc_binding_.Get() != NULL);
    client.Write(kMessage);

    // Shutdown the logging service.
    ASSERT_TRUE(server.Stop());
    ASSERT_TRUE(server.RunToCompletion());
  }

  std::string content;
  ASSERT_TRUE(file_util::ReadFileToString(temp_path, &content));
  ASSERT_EQ(kMessage, content);
}

}  // namespace asan
}  // namespace agent
