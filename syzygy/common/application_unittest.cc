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

#include "syzygy/common/application.h"

#include <shellapi.h>

#include "base/file_util.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace common {

using ::testing::Return;
using ::testing::StrictMock;
using ::testing::_;

namespace {

// Helper class to make sure that a test that plays with the log level doesn't
// change it for other tests.
class ScopedLogLevelSaver {
 public:
  ScopedLogLevelSaver() : level_(logging::GetMinLogLevel()) {}
  ~ScopedLogLevelSaver() { logging::SetMinLogLevel(level_); }
  int level() const { return level_; }
 private:
  int level_;
};

// A mock application implementation class
class MockAppImpl : public AppImplBase {
 public:
  MockAppImpl(FILE* in, FILE* out, FILE* err) : AppImplBase(in, out, err) {}

  MOCK_METHOD1(ParseCommandLine, bool(const CommandLine*));
  MOCK_METHOD0(SetUp, bool());
  MOCK_METHOD0(Run, int());
  MOCK_METHOD0(TearDown, bool());
};


// A basic test fixture that sets up a copy of the command line.
// TODO(rogerm): Move this to a reusable location as a common fixture base
//     once we start writing mass app unit tests?
class ApplicationTest : public testing::Test {
 protected:
  ApplicationTest() : cmd_line_(CommandLine::NO_PROGRAM) {
  }

  virtual void SetUp() OVERRIDE {
    const CommandLine* orig_cmd_line = CommandLine::ForCurrentProcess();
    ASSERT_TRUE(orig_cmd_line != NULL);
    cmd_line_ = *orig_cmd_line;

    in_.reset(file_util::OpenFile("NUL", "r"));
    out_.reset(file_util::OpenFile("NUL", "w"));
    err_.reset(file_util::OpenFile("NUL", "w"));
    ASSERT_TRUE(in_.get() != NULL);
    ASSERT_TRUE(out_.get() != NULL);
    ASSERT_TRUE(err_.get() != NULL);
  }

  CommandLine cmd_line_;
  file_util::ScopedFILE in_;
  file_util::ScopedFILE out_;
  file_util::ScopedFILE err_;
};

// Handy types we'll use below.
typedef Application<AppImplBase, INIT_LOGGING_YES> BaseApp;
typedef Application<StrictMock<MockAppImpl>, INIT_LOGGING_NO> MockApp;

}  // namespace

TEST_F(ApplicationTest, ScopedLogLevelSaver) {
  // Validate that the ScopedLogLevelSaver, defined above, works.
  int old_level = logging::GetMinLogLevel();
  int new_level = old_level - 1;

  {
    ScopedLogLevelSaver log_level_saver;
    logging::SetMinLogLevel(new_level);
    ASSERT_EQ(new_level, logging::GetMinLogLevel());
  }

  ASSERT_EQ(old_level, logging::GetMinLogLevel());
}

TEST_F(ApplicationTest, AppImplBaseDefault) {
  // The command line for this process has already been set we can pass
  // whatever we want to Main and it will end up using the the current
  // command line.
  const CommandLine* current_command_line = CommandLine::ForCurrentProcess();
  ASSERT_TRUE(current_command_line != NULL);

  BaseApp test_app;
  BaseApp::Implementation& impl = test_app.implementation();

  // Check the default command line and streams.
  EXPECT_EQ(current_command_line, test_app.command_line());
  EXPECT_EQ(stdin, impl.in());
  EXPECT_EQ(stdout, impl.out());
  EXPECT_EQ(stderr, impl.err());

  // Validate the accessors.
  impl.set_in(in_.get());
  impl.set_out(out_.get());
  impl.set_err(err_.get());
  EXPECT_EQ(in_.get(), impl.in());
  EXPECT_EQ(out_.get(), impl.out());
  EXPECT_EQ(err_.get(), impl.err());

  EXPECT_EQ(0, test_app.Run());
}

TEST_F(ApplicationTest, AppImplBaseCustom) {
  BaseApp test_app(&cmd_line_, in_.get(), out_.get(), err_.get());
  BaseApp::Implementation& impl = test_app.implementation();

  EXPECT_EQ(&cmd_line_, test_app.command_line());
  EXPECT_EQ(in_.get(), impl.in());
  EXPECT_EQ(out_.get(), impl.out());
  EXPECT_EQ(err_.get(), impl.err());

  EXPECT_EQ(0, test_app.Run());
}

TEST_F(ApplicationTest, AppImplBaseVerbosity) {
  cmd_line_.AppendSwitchASCII("verbose", "2");
  BaseApp test_app(&cmd_line_, in_.get(), out_.get(), err_.get());

  ASSERT_EQ(0, test_app.Run());
  ASSERT_EQ(-2, logging::GetMinLogLevel());
}

TEST_F(ApplicationTest, MockAppFailsCommandLineParsing) {
  MockApp mock_app(&cmd_line_, in_.get(), out_.get(), err_.get());
  MockAppImpl& mock_impl = mock_app.implementation();

  EXPECT_CALL(mock_impl, ParseCommandLine(_))
      .WillOnce(Return(false));
  EXPECT_NE(0, mock_app.Run());
}

TEST_F(ApplicationTest, MockAppFailsSetup) {
  MockApp mock_app(&cmd_line_, in_.get(), out_.get(), err_.get());
  MockAppImpl& mock_impl = mock_app.implementation();

  EXPECT_CALL(mock_impl, ParseCommandLine(_))
      .WillOnce(Return(true));
  EXPECT_CALL(mock_impl, SetUp())
      .WillOnce(Return(false));
  EXPECT_NE(0, mock_app.Run());
}

TEST_F(ApplicationTest, MockAppFailsRun) {
  MockApp mock_app(&cmd_line_, in_.get(), out_.get(), err_.get());
  MockAppImpl& mock_impl = mock_app.implementation();

  EXPECT_CALL(mock_impl, ParseCommandLine(_))
      .WillOnce(Return(true));
  EXPECT_CALL(mock_impl, SetUp())
      .WillOnce(Return(true));
  EXPECT_CALL(mock_impl, Run())
      .WillOnce(Return(2));
  EXPECT_CALL(mock_impl, TearDown());
  EXPECT_EQ(2, mock_app.Run());
}

}  // namespace common
