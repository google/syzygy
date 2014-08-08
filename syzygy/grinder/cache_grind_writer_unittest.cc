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

#include "syzygy/grinder/cache_grind_writer.h"

#include "base/file_util.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"

namespace grinder {

namespace {

class TestCoverageData : public CoverageData {
 public:
  void InitDummyData() {
    CoverageData::SourceFileCoverageDataMap::iterator source_it =
        source_file_coverage_data_map_.insert(
            std::make_pair(std::string("C:\\src\\foo.cc"),
                           CoverageData::SourceFileCoverageData())).first;

    source_it->second.line_execution_count_map.insert(
        std::make_pair(1, 1));
    source_it->second.line_execution_count_map.insert(
        std::make_pair(2, 1));
    source_it->second.line_execution_count_map.insert(
        std::make_pair(3, 0));
  }
};

}  // namespace

TEST(CacheGrindWriterTest, Write) {
  TestCoverageData coverage_data;
  ASSERT_NO_FATAL_FAILURE(coverage_data.InitDummyData());

  testing::ScopedTempFile temp;
  EXPECT_TRUE(WriteCacheGrindCoverageFile(coverage_data, temp.path()) );

  std::string actual_contents;
  EXPECT_TRUE(base::ReadFileToString(temp.path(), &actual_contents));

  std::string expected_contents =
      "positions: line\n"
      "events: Instrumented Executed\n"
      "fl=C:/src/foo.cc\n"
      "fn=all\n"
      "1 1 1\n"
      "+1 1 1\n"
      "+1 1 0\n";

  EXPECT_EQ(expected_contents, actual_contents);
}

}  // namespace grinder
