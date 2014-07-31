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
#include "sawbuck/viewer/viewer_window.h"

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "sawbuck/viewer/mock_log_view_interfaces.h"

namespace {

using testing::StrictMock;

class ViewerWindowTest : public testing::Test {
 protected:
  base::MessageLoop message_loop_;
};

TEST_F(ViewerWindowTest, ClearAll) {
  ViewerWindow viewer_window;

  int reg_cookie1 = 0;
  StrictMock<testing::MockILogViewEvents> mock_event_sink1;
  viewer_window.Register(&mock_event_sink1, &reg_cookie1);

  EXPECT_CALL(mock_event_sink1, LogViewCleared()).Times(1);
  viewer_window.ClearAll();

  int reg_cookie2 = 0;
  StrictMock<testing::MockILogViewEvents> mock_event_sink2;
  viewer_window.Register(&mock_event_sink2, &reg_cookie2);

  EXPECT_CALL(mock_event_sink1, LogViewCleared()).Times(1);
  EXPECT_CALL(mock_event_sink2, LogViewCleared()).Times(1);
  viewer_window.ClearAll();

  viewer_window.Unregister(reg_cookie1);
  EXPECT_CALL(mock_event_sink2, LogViewCleared()).Times(1);
  viewer_window.ClearAll();

  viewer_window.Unregister(reg_cookie2);
  viewer_window.ClearAll();
}

}  // namespace
