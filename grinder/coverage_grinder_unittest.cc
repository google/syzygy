// Copyright 2012 Google Inc.
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

#include "syzygy/grinder/coverage_grinder.h"

#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/unittest_util.h"

namespace grinder {

namespace {

static const wchar_t kCoverageTraceFile[] = L"coverage_traces/trace-1.bin";

class TestCoverageGrinder : public CoverageGrinder {
 public:
  using CoverageGrinder::parser_;
};

class CoverageGrinderTest : public testing::PELibUnitTest {
 public:
  typedef testing::PELibUnitTest Super;

  CoverageGrinderTest() : cmd_line_(FilePath(L"coverage_grinder.exe")) {
  }

  virtual void SetUp() OVERRIDE {
    Super::Test::SetUp();
  }

  void InitParser(trace::parser::ParseEventHandlerImpl* handler) {
    ASSERT_TRUE(handler != NULL);

    ASSERT_TRUE(parser_.Init(handler));

    FilePath trace_file =
        testing::GetExeTestDataRelativePath(kCoverageTraceFile);

    ASSERT_TRUE(parser_.OpenTraceFile(trace_file));
  }

 protected:
  CommandLine cmd_line_;
  trace::parser::Parser parser_;
};

}  // namespace

TEST_F(CoverageGrinderTest, ParseCommandLineSucceeds) {
  TestCoverageGrinder grinder;
  EXPECT_TRUE(grinder.ParseCommandLine(&cmd_line_));
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

TEST_F(CoverageGrinderTest, GrindAndOutputDataSucceeds) {
  TestCoverageGrinder grinder;
  grinder.ParseCommandLine(&cmd_line_);

  ASSERT_NO_FATAL_FAILURE(InitParser(&grinder));
  grinder.SetParser(&parser_);
  ASSERT_TRUE(parser_.Consume());

  EXPECT_TRUE(grinder.Grind());

  FilePath temp_dir;
  ASSERT_NO_FATAL_FAILURE(CreateTemporaryDir(&temp_dir));

  FilePath output_path;
  file_util::ScopedFILE output_file(
      file_util::CreateAndOpenTemporaryFileInDir(temp_dir, &output_path));
  ASSERT_TRUE(output_file.get() != NULL);

  EXPECT_TRUE(grinder.OutputData(output_file.get()));
  output_file.reset();

  int64 lcov_file_size = 0;
  ASSERT_TRUE(file_util::GetFileSize(output_path, &lcov_file_size));
  EXPECT_LT(0u, lcov_file_size);
}

}  // namespace grinder
