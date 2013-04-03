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

#include "syzygy/grinder/profile_grinder.h"

#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/unittest_util.h"

namespace grinder {

namespace {

const wchar_t kProfileTraceFile[] = L"profile_traces/trace-1.bin";

class TestProfileGrinder : public ProfileGrinder {
 public:
  using ProfileGrinder::parser_;
};

class ProfileGrinderTest : public testing::PELibUnitTest {
 public:
  typedef testing::PELibUnitTest Super;

  ProfileGrinderTest() : cmd_line_(base::FilePath(L"profile_grinder.exe")) {
  }

  virtual void SetUp() OVERRIDE {
    Super::Test::SetUp();
    cmd_line_.AppendSwitchASCII("mode", "profile");
  }

  void InitParser(trace::parser::ParseEventHandlerImpl* handler) {
    ASSERT_TRUE(handler != NULL);

    ASSERT_TRUE(parser_.Init(handler));

    base::FilePath trace_file =
        testing::GetExeTestDataRelativePath(kProfileTraceFile);

    ASSERT_TRUE(parser_.OpenTraceFile(trace_file));
  }

  void GrindAndOutputSucceeds() {
    TestProfileGrinder grinder;
    grinder.ParseCommandLine(&cmd_line_);

    ASSERT_NO_FATAL_FAILURE(InitParser(&grinder));
    grinder.SetParser(&parser_);
    ASSERT_TRUE(parser_.Consume());

    EXPECT_TRUE(grinder.Grind());

    testing::ScopedTempFile output_path;
    file_util::ScopedFILE output_file(
        file_util::OpenFile(output_path.path(), "wb"));
    ASSERT_TRUE(output_file.get() != NULL);

    EXPECT_TRUE(grinder.OutputData(output_file.get()));
    output_file.reset();

    int64 cache_grind_file_size = 0;
    ASSERT_TRUE(file_util::GetFileSize(output_path.path(),
                                       &cache_grind_file_size));
    EXPECT_LT(0u, cache_grind_file_size);
  }

  CommandLine cmd_line_;
  trace::parser::Parser parser_;
};

}  // namespace

TEST_F(ProfileGrinderTest, ParseEmptyCommandLineSucceeds) {
  TestProfileGrinder grinder;
  EXPECT_TRUE(grinder.ParseCommandLine(&cmd_line_));
  EXPECT_FALSE(grinder.thread_parts());
}

TEST_F(ProfileGrinderTest, ParseThreadPartsSwitchOnCommandLine) {
  TestProfileGrinder grinder;
  cmd_line_.AppendSwitch("thread-parts");
  EXPECT_TRUE(grinder.ParseCommandLine(&cmd_line_));
}

TEST_F(ProfileGrinderTest, SetParserSucceeds) {
  TestProfileGrinder grinder;
  grinder.ParseCommandLine(&cmd_line_);

  ASSERT_NO_FATAL_FAILURE(InitParser(&grinder));

  grinder.SetParser(&parser_);
  EXPECT_EQ(&parser_, grinder.parser_);
}

TEST_F(ProfileGrinderTest, GrindAndOutputCacheGrindDataSucceeds) {
  ASSERT_NO_FATAL_FAILURE(GrindAndOutputSucceeds());
  // TODO(etienneb): Validate the output is a valid CacheGrind file.
}

}  // namespace grinder
