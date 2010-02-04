// Copyright 2010 Google Inc.
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
#include "sawbuck/viewer/filtered_log_view.h"

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/message_loop.h"
#include "gtest/gtest.h"
#include "gmock/gmock.h"

namespace {

using testing::_;
using testing::AtLeast;
using testing::Return;
using testing::SetArgumentPointee;
using testing::StrictMock;

class TestingFilteredLogView: public FilteredLogView {
 public:
  explicit TestingFilteredLogView(ILogView* original)
      : FilteredLogView(original) {
  }

  CancelableTask* task() const { return task_; }
};

class MockILogViewEvents: public ILogViewEvents {
 public:
  MOCK_METHOD0(LogViewChanged, void());
};

class MockILogView: public ILogView {
 public:
  MOCK_METHOD0(GetNumRows, int());

  MOCK_METHOD1(GetSeverity, int(int row));
  MOCK_METHOD1(GetProcessId, DWORD(int row));
  MOCK_METHOD1(GetThreadId, DWORD(int row));
  MOCK_METHOD1(GetTime, base::Time(int row));
  MOCK_METHOD1(GetFileName, std::string(int row));
  MOCK_METHOD1(GetLine, int(int row));
  MOCK_METHOD1(GetMessage, std::string(int row));
  MOCK_METHOD2(GetStackTrace, void(int row, std::vector<void*>* trace));

  MOCK_METHOD2(Register, void(ILogViewEvents* event_sink,
                              int* registration_cookie));
  MOCK_METHOD1(Unregister, void(int registration_cookie));
};

class FilteredLogViewTest: public testing::Test {
 public:
  static const int kRegCookie = 42;

  void ExpectCreation(int num_rows) {
    EXPECT_CALL(mock_view_, Register(_, _))
        .WillOnce(SetArgumentPointee<1>(kRegCookie));
    EXPECT_CALL(mock_view_, GetNumRows())
        .WillOnce(Return(num_rows));
  }

  void ExpectUnregistration() {
    EXPECT_CALL(mock_view_, Unregister(kRegCookie)).Times(1);
  }

 protected:
  MessageLoop message_loop_;
  StrictMock<MockILogView> mock_view_;
  StrictMock<MockILogViewEvents> mock_view_events_;
};

TEST_F(FilteredLogViewTest, Construction) {
  ExpectCreation(0);
  TestingFilteredLogView filtered(&mock_view_);

  EXPECT_TRUE(filtered.task() == NULL);
  EXPECT_EQ(0, filtered.GetNumRows());

  ExpectUnregistration();
}

TEST_F(FilteredLogViewTest, Register) {
  ExpectCreation(0);
  TestingFilteredLogView filtered(&mock_view_);

  int cookie = 0;
  filtered.Register(&mock_view_events_, &cookie);
  EXPECT_NE(0, cookie);

  ExpectUnregistration();
}

TEST_F(FilteredLogViewTest, DestroyWithTaskPending) {
  ExpectCreation(0);

  // Create a short-lived view on an empty view.
  {
    TestingFilteredLogView filtered(&mock_view_);
    EXPECT_TRUE(filtered.task() == NULL);
    filtered.LogViewChanged();
    EXPECT_TRUE(filtered.task() != NULL);

    ExpectUnregistration();
  }

  // We hope not to crash here.
  message_loop_.RunAllPending();

  ExpectCreation(1000);

  // Create a short-lived view on a non-empty view.
  {
    TestingFilteredLogView filtered(&mock_view_);
    EXPECT_TRUE(filtered.task() != NULL);

    ExpectUnregistration();
  }

  // We hope not to crash here.
  message_loop_.RunAllPending();
}

TEST_F(FilteredLogViewTest, IdentityFilter) {
  ExpectCreation(0);
  TestingFilteredLogView filtered(&mock_view_);

  int cookie = 0;
  filtered.Register(&mock_view_events_, &cookie);

  const int kNumRows = 12345;
  EXPECT_CALL(mock_view_, GetNumRows())
      .WillRepeatedly(Return(kNumRows));
  EXPECT_CALL(mock_view_events_, LogViewChanged())
      .Times(AtLeast(1));

  EXPECT_EQ(0, filtered.GetNumRows());
  filtered.LogViewChanged();
  EXPECT_EQ(0, filtered.GetNumRows());

  EXPECT_CALL(mock_view_, GetMessage(_))
      .WillRepeatedly(Return("foo"));

  message_loop_.RunAllPending();

  EXPECT_EQ(kNumRows, filtered.GetNumRows());

  ExpectUnregistration();
}

TEST_F(FilteredLogViewTest, Filtering) {
  const int kNumRows = 12345;
  ExpectCreation(kNumRows);

  TestingFilteredLogView filtered(&mock_view_);
  EXPECT_EQ(0, filtered.GetNumRows());

  EXPECT_CALL(mock_view_, GetNumRows())
      .WillRepeatedly(Return(kNumRows));
  EXPECT_CALL(mock_view_, GetMessage(_))
      .WillRepeatedly(Return("I'm not included"));
  EXPECT_CALL(mock_view_, GetMessage(kNumRows / 3))
      .WillRepeatedly(Return("I'm Included"));
  EXPECT_CALL(mock_view_, GetMessage(kNumRows / 2))
      .WillRepeatedly(Return("I'm Included but also Excluded"));

  // Run the identity filter to start with.
  message_loop_.RunAllPending();
  EXPECT_EQ(kNumRows, filtered.GetNumRows());

  // Set the exlusion regexpr and test that we reset the view.
  filtered.SetInclusionRegexp("Included");
  EXPECT_EQ(0, filtered.GetNumRows());

  // Run the filter.
  message_loop_.RunAllPending();
  ASSERT_EQ(2, filtered.GetNumRows());
  EXPECT_STREQ("I'm Included", filtered.GetMessage(0).c_str());
  EXPECT_STREQ("I'm Included but also Excluded",
               filtered.GetMessage(1).c_str());

  // Now add the exclusion regexpr and test for reset.
  filtered.SetExclusionRegexp("Excluded");
  EXPECT_EQ(0, filtered.GetNumRows());

  // Run the filter.
  message_loop_.RunAllPending();
  ASSERT_EQ(1, filtered.GetNumRows());
  EXPECT_STREQ("I'm Included", filtered.GetMessage(0).c_str());

  ExpectUnregistration();
}

}  // namespace

int main(int argc, char** argv) {
  testing::InitGoogleTest(&argc, argv);

  base::AtExitManager at_exit;
  CommandLine::Init(argc, argv);

  RUN_ALL_TESTS();
}
