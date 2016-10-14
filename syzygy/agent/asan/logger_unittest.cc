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

#include "syzygy/agent/asan/logger.h"

#include <memory>
#include <string>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/environment.h"
#include "base/files/file_enumerator.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/agent/asan/runtime.h"
#include "syzygy/crashdata/crashdata.h"
#include "syzygy/trace/agent_logger/agent_logger.h"
#include "syzygy/trace/agent_logger/agent_logger_rpc_impl.h"
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
    base::ScopedFILE destination(base::OpenFile(temp_path_, "wb"));

    // Start up the logging service.
    trace::agent_logger::AgentLogger server;
    trace::agent_logger::RpcLoggerInstanceManager instance_manager(&server);
    server.set_instance_id(instance_id_);
    server.set_destination(destination.get());
    server.set_minidump_dir(temp_dir_.path());
    ASSERT_TRUE(server.Start());

    // Use the AsanLogger client.
    client_.set_instance_id(instance_id_);
    client_.set_log_as_text(true);
    client_.set_minidump_on_failure(true);
    client_.Init();
    ASSERT_EQ(instance_id_, client_.instance_id_);
    ASSERT_TRUE(client_.rpc_binding_.Get() != NULL);

    // Generate a minidump.
    CONTEXT ctx = {};
    ::RtlCaptureContext(&ctx);
    AsanErrorInfo info = {};
    crashdata::Value protobuf;
    crashdata::Dictionary* dict = crashdata::ValueGetDict(&protobuf);
    crashdata::LeafGetAddress(crashdata::DictAddLeaf("foo", dict))
        ->set_address(0xDABBAD00);
    crashdata::LeafGetAddress(crashdata::DictAddLeaf("bar", dict))
        ->set_address(0xDEADC0DE);
    std::string protobuf_str;
    ASSERT_TRUE(protobuf.SerializeToString(&protobuf_str));
    MemoryRanges memory_ranges;
    memory_ranges.push_back(
        std::make_pair(protobuf_str.data(), protobuf_str.size()));
    client_.SaveMinidumpWithProtobufAndMemoryRanges(&ctx, &info, protobuf_str,
                                                    memory_ranges);
    client_.Write(kMessage);

    // Shutdown the logging service.
    ASSERT_TRUE(server.Stop());
    ASSERT_TRUE(server.Join());
  }

  // Inspect the log file contents.
  std::string content;
  ASSERT_TRUE(base::ReadFileToString(temp_path_, &content));
  ASSERT_THAT(content, testing::EndsWith(kMessage));

  // We should have exactly one minidump in the temp directory.
  using base::FileEnumerator;
  FileEnumerator fe(temp_dir_.path(), false, FileEnumerator::FILES, L"*.dmp");
  base::FilePath minidump(fe.Next());
#ifndef _WIN64
  EXPECT_FALSE(minidump.empty());
#else
  // The 64 bit version of the logger doesn't support writing minidumps yet
  // because it relies on Kasko, which hasn't been ported to 64-bit. Make sure
  // that no PDB get produced until we switch the minidump generation to using
  // Crashpad.
  // TODO(sebmarchand): Add support for generating minidumps to the 64-bit
  // version of the logger.
  EXPECT_TRUE(minidump.empty());
#endif
  EXPECT_TRUE(fe.Next().empty());

  // TODO(rogerm): Inspect the contents of the minidump.
}

TEST_F(AsanLoggerTest, Stop) {
  // Setup a log file destination.
  base::ScopedFILE destination(base::OpenFile(temp_path_, "wb"));

  // Start up the logging service.
  trace::agent_logger::AgentLogger server;
  trace::agent_logger::RpcLoggerInstanceManager instance_manager(&server);
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
