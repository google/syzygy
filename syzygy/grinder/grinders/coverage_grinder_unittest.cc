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

#include "syzygy/grinder/grinders/coverage_grinder.h"

#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/unittest_util.h"

namespace grinder {
namespace grinders {

namespace {

class TestCoverageGrinder : public CoverageGrinder {
 public:
  using CoverageGrinder::parser_;
};

class CoverageGrinderTest : public testing::PELibUnitTest {
 public:
  typedef testing::PELibUnitTest Super;

  CoverageGrinderTest() : cmd_line_(base::FilePath(L"coverage_grinder.exe")) {
  }

  virtual void SetUp() OVERRIDE {
    Super::Test::SetUp();
  }

  void InitParser(trace::parser::ParseEventHandlerImpl* handler) {
    ASSERT_TRUE(handler != NULL);

    ASSERT_TRUE(parser_.Init(handler));

    base::FilePath trace_file =
        testing::GetExeTestDataRelativePath(testing::kCoverageTraceFiles[0]);

    ASSERT_TRUE(parser_.OpenTraceFile(trace_file));
  }

  void GrindAndOutputSucceeds(
      CoverageGrinder::OutputFormat expected_output_format) {
    TestCoverageGrinder grinder;
    grinder.ParseCommandLine(&cmd_line_);
    EXPECT_EQ(expected_output_format, grinder.output_format());

    ASSERT_NO_FATAL_FAILURE(InitParser(&grinder));
    grinder.SetParser(&parser_);
    ASSERT_TRUE(parser_.Consume());

    EXPECT_TRUE(grinder.Grind());

    testing::ScopedTempFile output_path;
    base::ScopedFILE output_file(base::OpenFile(output_path.path(), "wb"));
    ASSERT_TRUE(output_file.get() != NULL);

    EXPECT_TRUE(grinder.OutputData(output_file.get()));
    output_file.reset();

    int64 cache_grind_file_size = 0;
    ASSERT_TRUE(base::GetFileSize(output_path.path(), &cache_grind_file_size));
    EXPECT_LT(0u, cache_grind_file_size);
  }

  CommandLine cmd_line_;
  trace::parser::Parser parser_;
};

}  // namespace

TEST_F(CoverageGrinderTest, ParseEmptyCommandLineSucceeds) {
  TestCoverageGrinder grinder;
  EXPECT_TRUE(grinder.ParseCommandLine(&cmd_line_));
  EXPECT_EQ(CoverageGrinder::kLcovFormat, grinder.output_format());
}

TEST_F(CoverageGrinderTest, ParseInvalidOutputFormatFails) {
  TestCoverageGrinder grinder;
  cmd_line_.AppendSwitchASCII("output-format", "foobar");
  EXPECT_FALSE(grinder.ParseCommandLine(&cmd_line_));
}

TEST_F(CoverageGrinderTest, SetParserSucceeds) {
  TestCoverageGrinder grinder;

  grinder.ParseCommandLine(&cmd_line_);

  ASSERT_NO_FATAL_FAILURE(InitParser(&grinder));

  grinder.SetParser(&parser_);
  EXPECT_EQ(&parser_, grinder.parser_);
}

TEST_F(CoverageGrinderTest, GrindFailsOnNoCoverageEvents) {
  TestCoverageGrinder grinder;

  grinder.ParseCommandLine(&cmd_line_);

  ASSERT_NO_FATAL_FAILURE(InitParser(&grinder));
  grinder.SetParser(&parser_);

  EXPECT_FALSE(grinder.Grind());
}

TEST_F(CoverageGrinderTest, GrindAndOutputLcovDataSucceeds) {
  cmd_line_.AppendSwitchASCII("output-format", "lcov");
  ASSERT_NO_FATAL_FAILURE(GrindAndOutputSucceeds(CoverageGrinder::kLcovFormat));
  // TODO(chrisha): Validate the output is a valid LCOV file.
}

TEST_F(CoverageGrinderTest, GrindAndOutputCacheGrindDataSucceeds) {
  cmd_line_.AppendSwitchASCII("output-format", "cachegrind");
  ASSERT_NO_FATAL_FAILURE(GrindAndOutputSucceeds(
      CoverageGrinder::kCacheGrindFormat));
  // TODO(chrisha): Validate the output is a valid CacheGrind file.
}

}  // namespace grinders
}  // namespace grinder
