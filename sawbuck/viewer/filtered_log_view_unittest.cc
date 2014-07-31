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

#include "base/run_loop.h"
#include "base/message_loop/message_loop.h"
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "sawbuck/viewer/mock_log_view_interfaces.h"

namespace {

using testing::_;
using testing::AtLeast;
using testing::Return;
using testing::SetArgumentPointee;
using testing::StrictMock;


class TestingFilteredLogView: public FilteredLogView {
 public:
  explicit TestingFilteredLogView(ILogView* original,
                                  const std::vector<Filter>& filters)
      : FilteredLogView(original, filters) {
  }

  const FilterCallback& task() const { return task_; }
};

class FilteredLogViewTest: public testing::Test {
 public:
  static const int kRegCookie = 42;

  void ExpectCreation(int num_rows) {
    EXPECT_CALL(mock_view_, Register(_, _))
        .WillOnce(SetArgumentPointee<1>(kRegCookie));
  }

  void ExpectUnregistration() {
    EXPECT_CALL(mock_view_, Unregister(kRegCookie)).Times(1);
  }

  void RunMessageLoopToIdle() {
    base::RunLoop run_loop;

    run_loop.RunUntilIdle();
  }

 protected:
  std::vector<Filter> filters_;
  base::MessageLoop message_loop_;
  StrictMock<testing::MockILogView> mock_view_;
  StrictMock<testing::MockILogViewEvents> mock_view_events_;
};

TEST_F(FilteredLogViewTest, Construction) {
  ExpectCreation(0);
  TestingFilteredLogView filtered(&mock_view_, filters_);

  EXPECT_EQ(0, filtered.GetNumRows());

  ExpectUnregistration();
}

TEST_F(FilteredLogViewTest, Register) {
  ExpectCreation(0);
  TestingFilteredLogView filtered(&mock_view_, filters_);

  int cookie = 0;
  filtered.Register(&mock_view_events_, &cookie);
  EXPECT_NE(0, cookie);

  ExpectUnregistration();
}

TEST_F(FilteredLogViewTest, DestroyWithTaskPending) {
  ExpectCreation(0);

  // Create a short-lived view on an empty view.
  {
    TestingFilteredLogView filtered(&mock_view_, filters_);
    EXPECT_TRUE(!filtered.task().IsCancelled());

    ExpectUnregistration();
  }

  // We hope not to crash here.
  RunMessageLoopToIdle();

  ExpectCreation(1000);

  // Create a short-lived view on a non-empty view.
  {
    TestingFilteredLogView filtered(&mock_view_, filters_);
    EXPECT_TRUE(!filtered.task().IsCancelled());

    ExpectUnregistration();
  }

  // We hope not to crash here.
  RunMessageLoopToIdle();
}

TEST_F(FilteredLogViewTest, IdentityFilter) {
  ExpectCreation(0);
  TestingFilteredLogView filtered(&mock_view_, filters_);

  int cookie = 0;
  filtered.Register(&mock_view_events_, &cookie);

  const int kNumRows = 12345;
  EXPECT_CALL(mock_view_, GetNumRows())
      .WillRepeatedly(Return(kNumRows));
  EXPECT_CALL(mock_view_events_, LogViewNewItems())
      .Times(AtLeast(1));

  EXPECT_EQ(0, filtered.GetNumRows());
  filtered.LogViewNewItems();
  EXPECT_EQ(0, filtered.GetNumRows());

  EXPECT_CALL(mock_view_, GetMessage(_))
      .WillRepeatedly(Return("foo"));

  RunMessageLoopToIdle();

  EXPECT_EQ(kNumRows, filtered.GetNumRows());

  ExpectUnregistration();
}

TEST_F(FilteredLogViewTest, Filtering) {
  const int kNumRows = 3;
  ExpectCreation(kNumRows);

  TestingFilteredLogView filtered(&mock_view_, filters_);
  EXPECT_EQ(0, filtered.GetNumRows());

  EXPECT_CALL(mock_view_, GetNumRows())
      .WillRepeatedly(Return(kNumRows));
  EXPECT_CALL(mock_view_, GetMessage(0))
      .WillRepeatedly(Return("I'm not included"));
  EXPECT_CALL(mock_view_, GetMessage(1))
      .WillRepeatedly(Return("I'm Included"));
  EXPECT_CALL(mock_view_, GetMessage(2))
      .WillRepeatedly(Return("I'm Included but also Excluded"));

  // Run the identity filter to start with.
  RunMessageLoopToIdle();
  EXPECT_EQ(kNumRows, filtered.GetNumRows());

  // Define some filters.
  std::vector<Filter> filters;
  Filter include_nothing(Filter::MESSAGE, Filter::CONTAINS, Filter::INCLUDE,
                         L"NothingIncluded");
  Filter include(Filter::MESSAGE, Filter::CONTAINS, Filter::INCLUDE,
                 L"I'm incl");
  Filter exclude(Filter::MESSAGE, Filter::CONTAINS, Filter::EXCLUDE,
                 L"Excluded");

  // Include nothing.
  filters.push_back(include_nothing);
  filtered.SetFilters(filters);
  EXPECT_EQ(0, filtered.GetNumRows());

  // Run the filter.
  RunMessageLoopToIdle();
  ASSERT_EQ(0, filtered.GetNumRows());

  // Also include some:
  filters.push_back(include);
  filtered.SetFilters(filters);
  EXPECT_EQ(0, filtered.GetNumRows());

  // Run the filter.
  RunMessageLoopToIdle();
  ASSERT_EQ(2, filtered.GetNumRows());

  EXPECT_STREQ("I'm Included", filtered.GetMessage(0).c_str());
  EXPECT_STREQ("I'm Included but also Excluded",
               filtered.GetMessage(1).c_str());

  // Now add the exclusion regexpr and test for reset.
  filters.push_back(exclude);
  filtered.SetFilters(filters);
  EXPECT_EQ(0, filtered.GetNumRows());

  // Run the filter.
  RunMessageLoopToIdle();
  ASSERT_EQ(1, filtered.GetNumRows());
  EXPECT_STREQ("I'm Included", filtered.GetMessage(0).c_str());

  ExpectUnregistration();
}

class MockFilteredLogView : public TestingFilteredLogView {
 public:
  explicit MockFilteredLogView(ILogView* original,
                               const std::vector<Filter>& filters)
      : TestingFilteredLogView(original, filters) {
  }
  MOCK_METHOD0(RestartFiltering, void());
};

TEST_F(FilteredLogViewTest, ClearAll) {
  ExpectCreation(0);
  StrictMock<MockFilteredLogView> filtered(&mock_view_, filters_);

  EXPECT_CALL(mock_view_, ClearAll()).Times(1);
  filtered.ClearAll();

  int reg_cookie = 0;
  filtered.Register(&mock_view_events_, &reg_cookie);

  EXPECT_CALL(mock_view_events_, LogViewCleared()).Times(1);
  EXPECT_CALL(filtered, RestartFiltering()).Times(1);
  filtered.LogViewCleared();

  int other_reg_cookie = 0;
  StrictMock<testing::MockILogViewEvents> other_mock_view_events;
  filtered.Register(&other_mock_view_events, &other_reg_cookie);

  EXPECT_CALL(other_mock_view_events, LogViewCleared()).Times(1);
  EXPECT_CALL(mock_view_events_, LogViewCleared()).Times(1);
  EXPECT_CALL(filtered, RestartFiltering()).Times(1);
  filtered.LogViewCleared();

  filtered.Unregister(reg_cookie);
  EXPECT_CALL(other_mock_view_events, LogViewCleared()).Times(1);
  EXPECT_CALL(filtered, RestartFiltering()).Times(1);
  filtered.LogViewCleared();

  filtered.Unregister(other_reg_cookie);
  EXPECT_CALL(filtered, RestartFiltering()).Times(1);
  filtered.LogViewCleared();
  ExpectUnregistration();
}

}  // namespace
