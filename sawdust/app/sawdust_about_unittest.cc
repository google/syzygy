// Copyright 2011 Google Inc.
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
#include "sawdust/app/sawdust_about.h"

#include <map>
#include <set>

#include "base/file_path.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "sawdust/tracer/configuration.h"
#include "sawdust/tracer/controller.h"

using testing::_;
using testing::DoAll;
using testing::Return;
using testing::SetArgumentPointee;

namespace {

class MockTracerInfoFunctions : public TracerController {
 public:
  MOCK_CONST_METHOD0(IsRunning, bool());
  MOCK_CONST_METHOD1(GetCurrentEventLogFileName, bool(FilePath*));
  MOCK_CONST_METHOD1(GetCurrentKernelEventLogFileName, bool(FilePath*));
};

class MockTracerConfiguration : public TracerConfiguration {
 public:
  MOCK_CONST_METHOD1(GetTracedApplication, bool(std::wstring*));
  MOCK_CONST_METHOD2(GetUploadPath, bool(std::wstring*, bool* assume_remote));
};

TEST(SawdustAbout, StringForRunningLog) {
  MockTracerInfoFunctions mock_controller;
  MockTracerConfiguration mock_config;
  std::wstring response;
  std::wstring running_app(L"SawdustItself");
  FilePath kernel_log(L"C:\\A fake path\\nested a bit\\with_a_file.log");
  FilePath app_log(L"C:\\Another fake path\\nested a bit\\with_a_file.log");
  std::wstring upload_path(L"http://127.0.0.1/looking_for?what");

  EXPECT_CALL(mock_controller, IsRunning()).WillOnce(Return(true));
  EXPECT_CALL(mock_controller, GetCurrentEventLogFileName(_)).
      WillOnce(DoAll(SetArgumentPointee<0>(app_log), Return(true)));
  EXPECT_CALL(mock_controller, GetCurrentKernelEventLogFileName(_)).
      WillOnce(DoAll(SetArgumentPointee<0>(kernel_log), Return(true)));
  EXPECT_CALL(mock_config, GetTracedApplication(_)).
      WillOnce(DoAll(SetArgumentPointee<0>(running_app), Return(true)));
  EXPECT_CALL(mock_config, GetUploadPath(_, _)).
      WillOnce(DoAll(SetArgumentPointee<0>(upload_path),
                     SetArgumentPointee<1>(true),
                     Return(true)));
  AboutSawdustDialog::GetAppStateDescription(
      mock_controller, mock_config, &response);

  // Make sure all bits made it there.
  ASSERT_NE(response.find(running_app), std::wstring::npos);
  ASSERT_NE(response.find(kernel_log.value()), std::wstring::npos);
  ASSERT_NE(response.find(app_log.value()), std::wstring::npos);
  ASSERT_NE(response.find(upload_path), std::wstring::npos);
}

TEST(SawdustAbout, StringForIdleLog) {
  MockTracerInfoFunctions mock_controller;
  MockTracerConfiguration mock_config;
  std::wstring response;
  std::wstring running_app(L"SawdustItself");
  std::wstring upload_path(L"D:\\My own local\\target path\\with_filename.zip");

  EXPECT_CALL(mock_controller, IsRunning()).WillOnce(Return(false));
  EXPECT_CALL(mock_controller, GetCurrentEventLogFileName(_)).Times(0);
  EXPECT_CALL(mock_controller, GetCurrentKernelEventLogFileName(_)).Times(0);
  EXPECT_CALL(mock_config, GetTracedApplication(_)).
      WillOnce(DoAll(SetArgumentPointee<0>(running_app), Return(true)));
  EXPECT_CALL(mock_config, GetUploadPath(_, _)).
      WillOnce(DoAll(SetArgumentPointee<0>(upload_path),
                     SetArgumentPointee<1>(false),
                     Return(true)));
  AboutSawdustDialog::GetAppStateDescription(
      mock_controller, mock_config, &response);

  // Make sure all bits made it there.
  ASSERT_NE(response.find(running_app), std::wstring::npos);
  ASSERT_NE(response.find(upload_path), std::wstring::npos);
}

}  // namespace
