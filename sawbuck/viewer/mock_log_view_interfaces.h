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
#ifndef SAWBUCK_VIEWER_MOCK_LOG_VIEW_INTERFACES_H_
#define SAWBUCK_VIEWER_MOCK_LOG_VIEW_INTERFACES_H_

#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "sawbuck/viewer/log_list_view.h"

namespace testing {

class MockILogViewEvents: public ILogViewEvents {
 public:
  MOCK_METHOD0(LogViewNewItems, void());
  MOCK_METHOD0(LogViewCleared, void());
};

class MockILogView: public ILogView {
 public:
  MOCK_METHOD0(GetNumRows, int());
  MOCK_METHOD0(ClearAll, void());

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

}  // namespace testing

#endif  // SAWBUCK_VIEWER_MOCK_LOG_VIEW_INTERFACES_H_
