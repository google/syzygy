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
#include "sawbuck/viewer/log_list_view.h"

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "sawbuck/viewer/mock_log_view_interfaces.h"

namespace {

using testing::NotNull;
using testing::StrictMock;

class LogListViewTest : public testing::Test {
 protected:
  MessageLoop message_loop_;
};

class MockLogListView : public LogListView {
 public:
  MockLogListView() : LogListView(NULL) {
  }

  MOCK_METHOD0(DeleteAllItems, BOOL());
};

class TestingLogListView : public StrictMock<MockLogListView> {
 public:
  using LogListView::OnClearAll;
};

TEST_F(LogListViewTest, ClearAll) {
  TestingLogListView test_log_list_view;
  StrictMock<testing::MockILogView> mock_log_view;
  EXPECT_CALL(mock_log_view, Register(&test_log_list_view, NotNull())).Times(1);
  test_log_list_view.SetLogView(&mock_log_view);

  EXPECT_CALL(mock_log_view, ClearAll()).Times(1);
  test_log_list_view.OnClearAll(0, 0, CWindow());

  EXPECT_CALL(test_log_list_view, DeleteAllItems()).Times(1);
  test_log_list_view.LogViewCleared();
}

}  // namespace
