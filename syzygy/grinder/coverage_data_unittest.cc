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

#include "syzygy/grinder/coverage_data.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace grinder {

namespace {

using testing::ContainerEq;

class TestLineInfo : public LineInfo {
 public:
  using LineInfo::source_files_;
  using LineInfo::source_lines_;

  void InitDummyLineInfoFoo() {
    LineInfo::SourceFileSet::iterator file_it =
        source_files_.insert("foo.cc").first;
    const std::string* file_name = &(*file_it);

    source_lines_.push_back(LineInfo::SourceLine(
        file_name, 1, core::RelativeAddress(0), 1));
    source_lines_.push_back(LineInfo::SourceLine(
        file_name, 2, core::RelativeAddress(1), 1));
    source_lines_.push_back(LineInfo::SourceLine(
        file_name, 3, core::RelativeAddress(2), 1));

    // Visits lines 1 and 2.
    Visit(core::RelativeAddress(0), 2, 1);
  }
};

}  // namespace

// We provide this so that we can use ContainerEq. It must be outside of the
// anonymous namespace for this to compile.
bool operator==(const CoverageData::SourceFileCoverageData& lhs,
                const CoverageData::SourceFileCoverageData& rhs) {
  return lhs.line_execution_count_map == rhs.line_execution_count_map;
}

TEST(CoverageDataTest, Construct) {
  CoverageData coverage;
  EXPECT_TRUE(coverage.source_file_coverage_data_map().empty());
}

TEST(CoverageDataTest, Add) {
  TestLineInfo line_info;
  ASSERT_NO_FATAL_FAILURE(line_info.InitDummyLineInfoFoo());

  CoverageData coverage;
  EXPECT_TRUE(coverage.Add(line_info));

  CoverageData::SourceFileCoverageDataMap expected_coverage_info_map;
  CoverageData::LineExecutionCountMap& expected_line_exec =
      expected_coverage_info_map["foo.cc"].line_execution_count_map;
  expected_line_exec[1] = 1;
  expected_line_exec[2] = 1;
  expected_line_exec[3] = 0;

  EXPECT_THAT(expected_coverage_info_map,
              ContainerEq(coverage.source_file_coverage_data_map()));
}

}  // namespace grinder
