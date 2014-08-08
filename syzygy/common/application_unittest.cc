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

const char kTestAppImplName[] = "Test Application (Unit Test)";

// A test application that simply makes the AppImplBase concrete.
class TestAppImpl : public AppImplBase {
 public:
  TestAppImpl() : AppImplBase(kTestAppImplName) {
  }
};

// A mock application implementation class
class MockAppImpl : public AppImplBase {
 public:
  MockAppImpl() : AppImplBase("Mock Application (Unit Test)") {
  }

  MOCK_METHOD1(ParseCommandLine, bool(const CommandLine*));
  MOCK_METHOD0(SetUp, bool());
  MOCK_METHOD0(Run, int());
  MOCK_METHOD0(TearDown, bool());
};

// Handy types we'll use below.
typedef Application<TestAppImpl, INIT_LOGGING_YES> TestApp;
typedef Application<StrictMock<MockAppImpl>, INIT_LOGGING_NO> MockApp;

// A basic test fixture that sets up dummy standard streams.
class ApplicationTest : public testing::ApplicationTestBase {
 protected:
  ApplicationTest() : cmd_line_(base::FilePath(L"test.exe")) {
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
  TestApp test_app_;
  MockApp mock_app_;
};

bool CreateEmptyFile(const base::FilePath& path) {
  base::ScopedFILE f(base::OpenFile(path, "wb"));
  if (f.get() == NULL)
    return false;
  return true;
}

}  // namespace

TEST_F(ApplicationTest, AppImplBaseDefault) {
  // The command line for this process has already been set we can pass
  // whatever we want to Main and it will end up using the current
  // command line.
  const CommandLine* current_command_line = CommandLine::ForCurrentProcess();
  ASSERT_TRUE(current_command_line != NULL);

  // Validate the application name.
  EXPECT_EQ(kTestAppImplName, test_app_.name());

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

TEST_F(ApplicationTest, AbsolutePath) {
  AppImplBase& app_impl = test_app_.implementation();
  base::FilePath current_dir;
  ASSERT_TRUE(base::GetCurrentDirectory(&current_dir));

  const base::FilePath kRelativePath(L"foo\\bar\\file.txt");
  const base::FilePath kAbsolutePath(current_dir.Append(kRelativePath));

  EXPECT_EQ(base::FilePath(), app_impl.AbsolutePath(base::FilePath()));
  EXPECT_EQ(kAbsolutePath, app_impl.AbsolutePath(kRelativePath));
  EXPECT_EQ(kAbsolutePath, app_impl.AbsolutePath(kAbsolutePath));
}

TEST_F(ApplicationTest, AppendMatchingPaths) {
  // Create some files to match against.
  base::FilePath temp_dir;
  ASSERT_NO_FATAL_FAILURE(CreateTemporaryDir(&temp_dir));
  ASSERT_TRUE(CreateEmptyFile(temp_dir.Append(L"a.txt")));
  ASSERT_TRUE(CreateEmptyFile(temp_dir.Append(L"b.txt")));
  ASSERT_TRUE(CreateEmptyFile(temp_dir.Append(L"c.txt")));
  ASSERT_TRUE(CreateEmptyFile(temp_dir.Append(L"a.bin")));

  // Should get false on no match.
  std::vector<base::FilePath> no_matching_paths;
  ASSERT_FALSE(TestAppImpl::AppendMatchingPaths(temp_dir.Append(L"d.*"),
                                                &no_matching_paths));
  EXPECT_TRUE(no_matching_paths.empty());

  // Match a pattern where the extension is a wildcard.
  std::vector<base::FilePath> a_star_paths;
  ASSERT_TRUE(TestAppImpl::AppendMatchingPaths(temp_dir.Append(L"a.*"),
              &a_star_paths));
  EXPECT_THAT(a_star_paths,
              testing::ElementsAre(temp_dir.Append(L"a.bin"),
                                   temp_dir.Append(L"a.txt")));

  // Match a pattern where the extension is set but the root name is a wildcard.
  std::vector<base::FilePath> star_txt_paths;
  ASSERT_TRUE(TestAppImpl::AppendMatchingPaths(temp_dir.Append(L"*.txt"),
                                               &star_txt_paths));
  EXPECT_THAT(star_txt_paths,
              testing::ElementsAre(temp_dir.Append(L"a.txt"),
                                   temp_dir.Append(L"b.txt"),
                                   temp_dir.Append(L"c.txt")));
}

TEST_F(ApplicationTest, GetDeprecatedSwitch) {
  const std::string kFoo("foo");
  const std::string kBar("bar");
  const std::string kMissing("missing");
  const base::FilePath kFooPath(L"C:\\foo");
  const base::FilePath kBarPath(L"C:\\bar");
  ASSERT_NE(kFoo, kBar);
  ASSERT_NE(kFooPath, kBarPath);

  base::FilePath path;
  EXPECT_TRUE(TestAppImpl::GetDeprecatedSwitch(
      &cmd_line_, kFoo, kBar, &CommandLine::GetSwitchValuePath, &path));
  EXPECT_TRUE(path.empty());

  cmd_line_.AppendSwitchPath(kFoo, kFooPath);
  cmd_line_.AppendSwitchPath(kBar, kBarPath);

  EXPECT_FALSE(TestAppImpl::GetDeprecatedSwitch(
      &cmd_line_, kFoo, kBar, &CommandLine::GetSwitchValuePath, &path));

  EXPECT_TRUE(TestAppImpl::GetDeprecatedSwitch(
      &cmd_line_, kFoo, kMissing, &CommandLine::GetSwitchValuePath, &path));
  EXPECT_EQ(kFooPath, path);

  EXPECT_TRUE(TestAppImpl::GetDeprecatedSwitch(
      &cmd_line_, kMissing, kBar, &CommandLine::GetSwitchValuePath, &path));
  EXPECT_EQ(kBarPath, path);
}

}  // namespace common
