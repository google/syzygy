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

#include "syzygy/grinder/line_info.h"

#include "base/win/scoped_com_initializer.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/unittest_util.h"

namespace grinder {

namespace {

class TestLineInfo : public LineInfo {
 public:
  using LineInfo::source_files_;
  using LineInfo::source_lines_;

  void ResetVisitedLines() {
    for (size_t i = 0; i < source_lines_.size(); ++i) {
      source_lines_[i].visit_count = 0;
    }
  }

  void GetVisitedLines(std::vector<size_t>* visited_lines) const {
    DCHECK(visited_lines != NULL);
    visited_lines->clear();
    for (size_t i = 0; i < source_lines_.size(); ++i) {
      if (source_lines_[i].visit_count > 0)
        visited_lines->push_back(source_lines_[i].line_number);
    }
  }
};

class LineInfoTest : public testing::Test {
 public:
  virtual void SetUp() override {
    testing::Test::SetUp();

    pdb_path_ = testing::GetExeTestDataRelativePath(
        testing::kCoverageInstrumentedTestDllPdbName);


    std::wstring static_pdb_path(
        L"syzygy/grinder/test_data/coverage_instrumented_test_dll.pdb");
    static_pdb_path_ = testing::GetSrcRelativePath(static_pdb_path.c_str());
  }

  // Ensures that COM is initialized for tests in this fixture.
  base::win::ScopedCOMInitializer com_initializer_;

  base::FilePath pdb_path_;
  base::FilePath static_pdb_path_;
};

void PushBackSourceLine(TestLineInfo* line_info,
                        const std::string* source_file_name,
                        size_t line_number,
                        uint32_t address,
                        size_t size) {
  DCHECK(line_info != NULL);
  line_info->source_lines_.push_back(LineInfo::SourceLine(
      source_file_name,
      line_number,
      core::RelativeAddress(address),
      size));
}

#define EXPECT_LINES_VISITED(line_info, ...) \
    { \
      const size_t kLineNumbers[] = { __VA_ARGS__ }; \
      std::vector<size_t> visited, expected; \
      expected.assign(kLineNumbers, kLineNumbers + arraysize(kLineNumbers)); \
      line_info.GetVisitedLines(&visited); \
      std::sort(expected.begin(), expected.end()); \
      std::sort(visited.begin(), visited.end()); \
      EXPECT_THAT(expected, ::testing::ContainerEq(visited)); \
    }

#define EXPECT_NO_LINES_VISITED(line_info) \
    { \
      std::vector<size_t> visited; \
      line_info.GetVisitedLines(&visited); \
      EXPECT_EQ(0u, visited.size()); \
    }

}  // namespace

TEST_F(LineInfoTest, InitDynamicPdb) {
  TestLineInfo line_info;
  EXPECT_TRUE(line_info.Init(pdb_path_));
}

TEST_F(LineInfoTest, InitStaticPdb) {
  TestLineInfo line_info;
  EXPECT_TRUE(line_info.Init(static_pdb_path_));

  // The expected values were taken by running "pdb_dumper --dump-modules
  // syzygy/grinder/test_data/coverage_instrumented_test_dll.pdb" and running
  // through the following filters:
  // grep "line at" | sed 's/(.*$//' | uniq | sort | uniq | wc -l
  EXPECT_EQ(138u, line_info.source_files().size());
  // grep "line at" | wc -l
  EXPECT_EQ(8379u, line_info.source_lines().size());
}

TEST_F(LineInfoTest, Visit) {
  TestLineInfo line_info;

  // Create a single dummy source file.
  std::string source_file("foo.cc");

  // The first two entries have identical ranges, and map multiple lines to
  // those ranges.
  PushBackSourceLine(&line_info, &source_file, 1, 4096, 2);
  PushBackSourceLine(&line_info, &source_file, 2, 4096, 2);
  PushBackSourceLine(&line_info, &source_file, 3, 4098, 2);
  PushBackSourceLine(&line_info, &source_file, 5, 4100, 2);
  // Leave a gap between these two entries.
  PushBackSourceLine(&line_info, &source_file, 6, 4104, 6);
  PushBackSourceLine(&line_info, &source_file, 7, 4110, 2);

  // So, our line info looks like this:
  //  1,2   3    5         6    7        <-- line numbers
  // +----+----+----+----+----+----+
  // |0,1 | 2  | 3  |gap | 4  | 5  |     <-- source_lines_ indices
  // +----+----+----+----+----+----+
  // 4096 4098 4100 4102 4104 4110 4112  <-- address ranges

  // Visit a repeated BB (multiple lines).
  EXPECT_TRUE(line_info.Visit(core::RelativeAddress(4096), 2, 1));
  EXPECT_LINES_VISITED(line_info, 1, 2);

  // Visit a range spanning multiple BBs (we don't reset the previously
  // visited lines to ensure that stats are kept correctly across multiple
  // calls to LineInfo::Visit).
  EXPECT_TRUE(line_info.Visit(core::RelativeAddress(4098), 4, 1));
  EXPECT_LINES_VISITED(line_info, 1, 2, 3, 5);

  // Visit a gap and no blocks.
  line_info.ResetVisitedLines();
  EXPECT_TRUE(line_info.Visit(core::RelativeAddress(4102), 2, 1));
  EXPECT_NO_LINES_VISITED(line_info);

  // Visit a range spanning a gap (at the left) and a BB.
  line_info.ResetVisitedLines();
  EXPECT_TRUE(line_info.Visit(core::RelativeAddress(4102), 8, 1));
  EXPECT_LINES_VISITED(line_info, 6);

  // Visit a range spanning a gap (at the right) and a BB.
  line_info.ResetVisitedLines();
  EXPECT_TRUE(line_info.Visit(core::RelativeAddress(4100), 4, 1));
  EXPECT_LINES_VISITED(line_info, 5);

  // Visit a range spanning 2 BBs with a gap in the middle.
  line_info.ResetVisitedLines();
  EXPECT_TRUE(line_info.Visit(core::RelativeAddress(4100), 10, 1));
  EXPECT_LINES_VISITED(line_info, 5, 6);

  // Visit a range only partially spanning a single BB.
  line_info.ResetVisitedLines();
  EXPECT_TRUE(line_info.Visit(core::RelativeAddress(4100), 1, 1));
  EXPECT_LINES_VISITED(line_info, 5);

  // Visit a range partially spanning a BB on the left.
  line_info.ResetVisitedLines();
  EXPECT_TRUE(line_info.Visit(core::RelativeAddress(4108), 4, 1));
  EXPECT_LINES_VISITED(line_info, 6, 7);

  // Visit a range partially spanning a BB on the right.
  line_info.ResetVisitedLines();
  EXPECT_TRUE(line_info.Visit(core::RelativeAddress(4104), 7, 1));
  EXPECT_LINES_VISITED(line_info, 6, 7);
}

TEST_F(LineInfoTest, VisitCounterWorks) {
  TestLineInfo line_info;

  // Create a single dummy source file.
  std::string source_file("foo.cc");

  // Add a source line.
  PushBackSourceLine(&line_info, &source_file, 1, 4096, 2);
  LineInfo::SourceLines::const_iterator line_it =
      line_info.source_lines().begin();
  EXPECT_EQ(0u, line_it->visit_count);

  EXPECT_TRUE(line_info.Visit(core::RelativeAddress(4096), 2, 1));
  EXPECT_EQ(1u, line_it->visit_count);

  EXPECT_TRUE(line_info.Visit(core::RelativeAddress(4096), 2, 2));
  EXPECT_EQ(3u, line_it->visit_count);

  // Ensure our saturation addition works by trying to overflow.
  EXPECT_TRUE(line_info.Visit(core::RelativeAddress(4096), 2, 0xffffffff));
  EXPECT_EQ(0xffffffff, line_it->visit_count);
  EXPECT_TRUE(line_info.Visit(core::RelativeAddress(4096), 2, 10));
  EXPECT_EQ(0xffffffff, line_it->visit_count);
}

}  // namespace grinder
