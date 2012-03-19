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
#include "syzygy/common/unittest_util.h"

namespace common {

using ::testing::Return;
using ::testing::ScopedLogLevelSaver;
using ::testing::StrictMock;
using ::testing::_;

namespace {

// A mock application implementation class
class MockAppImpl : public AppImplBase {
 public:
  MOCK_METHOD1(ParseCommandLine, bool(const CommandLine*));
  MOCK_METHOD0(SetUp, bool());
  MOCK_METHOD0(Run, int());
  MOCK_METHOD0(TearDown, bool());
};

// Handy types we'll use below.
typedef Application<AppImplBase, INIT_LOGGING_YES> BaseApp;
typedef Application<StrictMock<MockAppImpl>, INIT_LOGGING_NO> MockApp;

// A basic test fixture that sets up dummy standard streams.
class ApplicationTest : public testing::ApplicationTestBase {
 protected:
  ApplicationTest() : cmd_line_(FilePath(L"test.exe")) {
  }

  template<typename App>
  void RerouteAppStreams(App* app) {
    ASSERT_TRUE(app != NULL);

    // Validate that app's streams were initialized properly.
    ASSERT_EQ(stdin, app->in());
    ASSERT_EQ(stdout, app->out());
    ASSERT_EQ(stderr, app->err());

    // Route test_app_ streams to
    app->set_in(in());
    app->set_out(out());
    app->set_err(err());

    ASSERT_EQ(in(), app->in());
    ASSERT_EQ(out(), app->out());
    ASSERT_EQ(err(), app->err());
  }

  virtual void SetUp() OVERRIDE {
    testing::Test::SetUp();

    // Validate test streams were created.
    ASSERT_TRUE(in() != NULL);
    ASSERT_TRUE(out() != NULL);
    ASSERT_TRUE(err() != NULL);

    // Reroute the test application streams.
    RerouteAppStreams(&test_app_);
    RerouteAppStreams(&mock_app_);
  }

  CommandLine cmd_line_;
  BaseApp test_app_;
  MockApp mock_app_;
};


}  // namespace

TEST_F(ApplicationTest, AppImplBaseDefault) {
  // The command line for this process has already been set we can pass
  // whatever we want to Main and it will end up using the the current
  // command line.
  const CommandLine* current_command_line = CommandLine::ForCurrentProcess();
  ASSERT_TRUE(current_command_line != NULL);

  // Check the default command line and streams.
  EXPECT_EQ(current_command_line, test_app_.command_line());

  // Validate the accessors.
  test_app_.set_command_line(&cmd_line_);
  EXPECT_EQ(&cmd_line_, test_app_.command_line());

  EXPECT_EQ(0, test_app_.Run());
}

TEST_F(ApplicationTest, AppImplBaseVerbosity) {
  ScopedLogLevelSaver log_level_saver;

  cmd_line_.AppendSwitchASCII("verbose", "2");
  test_app_.set_command_line(&cmd_line_);

  ASSERT_EQ(0, test_app_.Run());
  ASSERT_EQ(-2, logging::GetMinLogLevel());
}

TEST_F(ApplicationTest, MockAppFailsCommandLineParsing) {
  MockAppImpl& mock_impl = mock_app_.implementation();

  EXPECT_CALL(mock_impl, ParseCommandLine(_))
      .WillOnce(Return(false));
  EXPECT_NE(0, mock_app_.Run());
}

TEST_F(ApplicationTest, MockAppFailsSetup) {
  MockAppImpl& mock_impl = mock_app_.implementation();

  EXPECT_CALL(mock_impl, ParseCommandLine(_))
      .WillOnce(Return(true));
  EXPECT_CALL(mock_impl, SetUp())
      .WillOnce(Return(false));
  EXPECT_NE(0, mock_app_.Run());
}

TEST_F(ApplicationTest, MockAppFailsRun) {
  MockAppImpl& mock_impl = mock_app_.implementation();

  EXPECT_CALL(mock_impl, ParseCommandLine(_))
      .WillOnce(Return(true));
  EXPECT_CALL(mock_impl, SetUp())
      .WillOnce(Return(true));
  EXPECT_CALL(mock_impl, Run())
      .WillOnce(Return(2));
  EXPECT_CALL(mock_impl, TearDown());
  EXPECT_EQ(2, mock_app_.Run());
}

}  // namespace common
