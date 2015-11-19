// Copyright 2015 Google Inc. All Rights Reserved.
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

#include "syzygy/poirot/minidump_processor.h"

#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/crashdata/json.h"
#include "syzygy/poirot/unittest_util.h"

namespace poirot {

namespace {

class TestMinidumpProcessor : public MinidumpProcessor {
 public:
  explicit TestMinidumpProcessor(base::FilePath minidump_path)
      : MinidumpProcessor(minidump_path) {}
  using MinidumpProcessor::input_minidump_;
  using MinidumpProcessor::processed_;
  using MinidumpProcessor::protobuf_value_;
};

}  // namespace

TEST(MinidumpProcessorTest, ProcessingFailsForInvalidFilePath) {
  base::FilePath minidump_path(testing::kMinidumpInvalidPath);
  TestMinidumpProcessor minidump_processor(minidump_path);
  EXPECT_FALSE(minidump_processor.ProcessDump());
}

TEST(MinidumpProcessorTest, ProcessingFailsForMinidumpWithNoKaskoStream) {
  base::FilePath minidump_path(testing::kMinidumpNoKaskoStream);
  TestMinidumpProcessor minidump_processor(minidump_path);
  EXPECT_FALSE(minidump_processor.ProcessDump());
}

TEST(MinidumpProcessorTest, ProcessingSucceedsForValidFile) {
  TestMinidumpProcessor minidump_processor(
      testing::GetSrcRelativePath(testing::kMinidumpUAF));
  EXPECT_TRUE(minidump_processor.ProcessDump());
  EXPECT_TRUE(minidump_processor.processed_);
}

TEST(MinidumpProcessorTest, GenerateJsonOutput) {
  TestMinidumpProcessor minidump_processor(
      testing::GetSrcRelativePath(testing::kMinidumpUAF));
  EXPECT_TRUE(minidump_processor.ProcessDump());
  EXPECT_TRUE(minidump_processor.processed_);
  std::string protobuf_value;
  EXPECT_TRUE(crashdata::ToJson(true, &minidump_processor.protobuf_value_,
                                &protobuf_value));
  EXPECT_FALSE(protobuf_value.empty());
  base::FilePath temp_file;
  EXPECT_TRUE(base::CreateTemporaryFile(&temp_file));
  {
    base::ScopedFILE out(base::OpenFile(temp_file, "wb"));
    EXPECT_TRUE(minidump_processor.GenerateJsonOutput(out.get()));
  }
  std::string file_data;
  EXPECT_TRUE(base::ReadFileToString(temp_file, &file_data));
  EXPECT_TRUE(base::DeleteFile(temp_file, false));
  EXPECT_STREQ(protobuf_value.c_str(), file_data.c_str());
}

}  // namespace poirot
