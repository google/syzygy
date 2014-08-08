// Copyright 2013 Google Inc. All Rights Reserved.
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

#include "syzygy/trace/service/trace_file_writer.h"

#include "base/file_util.h"
#include "gtest/gtest.h"
#include "syzygy/common/align.h"
#include "syzygy/pe/unittest_util.h"
#include "syzygy/trace/protocol/call_trace_defs.h"
#include "syzygy/trace/service/process_info.h"

namespace trace {
namespace service {

namespace {

class TestTraceFileWriter : public TraceFileWriter {
 public:
  using TraceFileWriter::handle_;
};

class TraceFileWriterTest : public testing::PELibUnitTest {
 public:
  virtual void SetUp() OVERRIDE {
    testing::PELibUnitTest::SetUp();
    CreateTemporaryDir(&temp_dir);
    trace_path = temp_dir.AppendASCII("trace.dat");
  }

  base::FilePath temp_dir;
  base::FilePath trace_path;
};

}  // namespace

TEST_F(TraceFileWriterTest, GenerateTraceFileBaseName) {
  ProcessInfo pi;
  ASSERT_TRUE(pi.Initialize(::GetCurrentProcessId()));

  base::FilePath basename = TraceFileWriter::GenerateTraceFileBaseName(pi);
  EXPECT_FALSE(basename.empty());
}

TEST_F(TraceFileWriterTest, Constructor) {
  TestTraceFileWriter w;
  EXPECT_TRUE(w.path().empty());
  EXPECT_FALSE(w.handle_.IsValid());
  EXPECT_EQ(0u, w.block_size());
}

TEST_F(TraceFileWriterTest, OpenFailsForBadPath) {
  TestTraceFileWriter w;
  EXPECT_FALSE(w.Open(base::FilePath(
      L"Z:\\this\\path\\should\\not\\exist\\and\\open\\should\\fail.dat")));
  EXPECT_TRUE(w.path().empty());
  EXPECT_FALSE(w.handle_.IsValid());
  EXPECT_EQ(0u, w.block_size());
}

TEST_F(TraceFileWriterTest, OpenSucceeds) {
  TestTraceFileWriter w;
  EXPECT_TRUE(w.Open(trace_path));
  EXPECT_EQ(trace_path, w.path());
  EXPECT_TRUE(w.handle_.IsValid());
  EXPECT_LT(0u, w.block_size());
  EXPECT_TRUE(base::PathExists(trace_path));
}

TEST_F(TraceFileWriterTest, CloseSucceeds) {
  TestTraceFileWriter w;
  ASSERT_TRUE(w.Open(trace_path));

  EXPECT_TRUE(w.Close());
  EXPECT_TRUE(base::PathExists(trace_path));
}

TEST_F(TraceFileWriterTest, WriteHeader) {
  TestTraceFileWriter w;
  ASSERT_TRUE(w.Open(trace_path));

  ProcessInfo pi;
  ASSERT_TRUE(pi.Initialize(::GetCurrentProcessId()));
  EXPECT_TRUE(w.WriteHeader(pi));

  ASSERT_TRUE(w.Close());
  EXPECT_TRUE(base::PathExists(trace_path));

  int64 trace_file_size = 0;
  ASSERT_TRUE(base::GetFileSize(trace_path, &trace_file_size));
  EXPECT_LT(0, trace_file_size);
  EXPECT_EQ(0, trace_file_size % w.block_size());
}

TEST_F(TraceFileWriterTest, WriteRecordFailsTooShort) {
  TestTraceFileWriter w;
  ASSERT_TRUE(w.Open(trace_path));

  ProcessInfo pi;
  ASSERT_TRUE(pi.Initialize(::GetCurrentProcessId()));
  ASSERT_TRUE(w.WriteHeader(pi));

  uint8 data[2] = {};
  EXPECT_FALSE(w.WriteRecord(data, sizeof(data)));
}

TEST_F(TraceFileWriterTest, WriteRecordFailsInvalidRecordPrefix) {
  TestTraceFileWriter w;
  ASSERT_TRUE(w.Open(trace_path));

  ProcessInfo pi;
  ASSERT_TRUE(pi.Initialize(::GetCurrentProcessId()));
  ASSERT_TRUE(w.WriteHeader(pi));

  RecordPrefix record = {};
  EXPECT_FALSE(w.WriteRecord(&record, sizeof(record)));
}

TEST_F(TraceFileWriterTest, WriteRecordFailsOverwritten) {
  TestTraceFileWriter w;
  ASSERT_TRUE(w.Open(trace_path));

  ProcessInfo pi;
  ASSERT_TRUE(pi.Initialize(::GetCurrentProcessId()));
  ASSERT_TRUE(w.WriteHeader(pi));

  std::vector<uint8> data;
  data.resize(sizeof(RecordPrefix) + sizeof(TraceFileSegmentHeader) + 1);
  RecordPrefix* record = reinterpret_cast<RecordPrefix*>(data.data());
  TraceFileSegmentHeader* header = reinterpret_cast<TraceFileSegmentHeader*>(
      record + 1);
  record->size = sizeof(TraceFileSegmentHeader);
  record->type= TraceFileSegmentHeader::kTypeId;
  record->version.hi = TRACE_VERSION_HI;
  record->version.lo = TRACE_VERSION_LO;
  header->segment_length = 1;

  EXPECT_FALSE(w.WriteRecord(data.data(), data.size()));
}

TEST_F(TraceFileWriterTest, WriteRecordSucceeds) {
  TestTraceFileWriter w;
  ASSERT_TRUE(w.Open(trace_path));

  ProcessInfo pi;
  ASSERT_TRUE(pi.Initialize(::GetCurrentProcessId()));
  ASSERT_TRUE(w.WriteHeader(pi));

  std::vector<uint8> data;
  data.resize(sizeof(RecordPrefix) + sizeof(TraceFileSegmentHeader) + 1);
  RecordPrefix* record = reinterpret_cast<RecordPrefix*>(data.data());
  TraceFileSegmentHeader* header = reinterpret_cast<TraceFileSegmentHeader*>(
      record + 1);
  record->size = sizeof(TraceFileSegmentHeader);
  record->type= TraceFileSegmentHeader::kTypeId;
  record->version.hi = TRACE_VERSION_HI;
  record->version.lo = TRACE_VERSION_LO;
  header->segment_length = 1;

  data.resize(::common::AlignUp(data.size(), w.block_size()));
  EXPECT_TRUE(w.WriteRecord(data.data(), data.size()));

  ASSERT_TRUE(w.Close());
  EXPECT_TRUE(base::PathExists(trace_path));

  int64 trace_file_size = 0;
  ASSERT_TRUE(base::GetFileSize(trace_path, &trace_file_size));
  EXPECT_LT(0, trace_file_size);
  EXPECT_EQ(0, trace_file_size % w.block_size());
}

}  // namespace service
}  // namespace trace
