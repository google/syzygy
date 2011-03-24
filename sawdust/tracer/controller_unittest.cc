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
#include "sawdust/tracer/controller.h"

#include <map>
#include <string>

#include "base/json/json_writer.h"
#include "base/logging.h"
#include "base/scoped_ptr.h"
#include "base/scoped_temp_dir.h"
#include "base/values.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "sawdust/tracer/configuration.h"
#include "sawdust/tracer/tracer_unittest_util.h"

using testing::_;
using testing::Return;
using testing::SetArgumentPointee;
using testing::StrEq;

namespace {

class MockTracerController : public TracerController {
 public:
  MOCK_METHOD3(StartLogging, HRESULT(base::win::EtwTraceController*,
                                     base::win::EtwTraceProperties*,
                                     const wchar_t*));
  MOCK_METHOD2(EnableProviders, void(
      const TracerConfiguration::ProviderDefinitions&,
      TracerConfiguration::ProviderDefinitions*));
  MOCK_CONST_METHOD1(VerifyAndStopIfRunning, bool(const wchar_t*));
  MOCK_METHOD1(StopKernelLogging, bool(FilePath*));
  MOCK_METHOD2(StopLogging, HRESULT(TracerConfiguration::ProviderDefinitions*,
                                    FilePath*));
};

class TracerControllerTest : public testing::Test {
 public:
  typedef std::map<std::wstring, std::wstring> PathMapType;
  static const wchar_t kFakeWorkingDir[];

  void SetUp() {
    configurations_.reset(
        LoadJsonDataFile(L"controller_unittest_configs.json"));
    ASSERT_TRUE(configurations_ != NULL);
    ASSERT_TRUE(configurations_->IsType(Value::TYPE_DICTIONARY));
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
  }

  void RetrieveConfiguration(const std::string& section_key,
                             TracerConfiguration* configuration) {
    DictionaryValue* config_dictionary =
        static_cast<DictionaryValue*>(configurations_.get());

    DictionaryValue* return_config = NULL;

    ASSERT_TRUE(config_dictionary->GetDictionary(section_key, &return_config));
    ASSERT_TRUE(return_config != NULL);

    std::string json_text, error_string;
    base::JSONWriter::Write(return_config, false, &json_text);

    ASSERT_FALSE(json_text.empty());
    ASSERT_TRUE(configuration->Initialize(json_text,
                                          temp_dir_.path(),
                                          &error_string));
  }

  HRESULT InterceptStartLogging(base::win::EtwTraceController* controller,
                                base::win::EtwTraceProperties* properties,
                                const wchar_t* logger) {
    intercepted_logger_paths_.insert(
        PathMapType::value_type(logger, properties->GetLoggerFileName()));
    return S_OK;
  }

  void InterceptEnableProviders(
      const TracerConfiguration::ProviderDefinitions& requested,
      TracerConfiguration::ProviderDefinitions* enabled) {
    intercepted_providers_ = requested;
    *enabled = intercepted_providers_;
  }

  scoped_ptr<Value> configurations_;
  ScopedTempDir temp_dir_;
  PathMapType intercepted_logger_paths_;
  TracerConfiguration::ProviderDefinitions intercepted_providers_;
};

TEST_F(TracerControllerTest, TestWithDefaultSettings) {
  TracerConfiguration config;
  ASSERT_NO_FATAL_FAILURE(RetrieveConfiguration("all-default", &config));

  // Expectations with default config:
  // 1) only application logging enabled (kernel off).
  // 2) Writing to a temp file below the temp_dir_.
  MockTracerController controller;
  EXPECT_CALL(controller, VerifyAndStopIfRunning(_)).
      WillRepeatedly(Return(true));
  EXPECT_CALL(controller, StartLogging(_, _,
      StrEq(TracerController::kSawdustTraceSessionName))).
        WillOnce(Invoke(this, &TracerControllerTest::InterceptStartLogging));
  EXPECT_CALL(controller, EnableProviders(_, _)).Times(1);

  ASSERT_HRESULT_SUCCEEDED(controller.Start(config));

  // Check if logging to the right files.
  ASSERT_FALSE(intercepted_logger_paths_.find(
      TracerController::kSawdustTraceSessionName) ==
          intercepted_logger_paths_.end());
  FilePath app_file(intercepted_logger_paths_.find(
      TracerController::kSawdustTraceSessionName)->second);

  EXPECT_CALL(controller, StopKernelLogging(_)).WillOnce(Return(false));
  EXPECT_CALL(controller, StopLogging(_, _)).WillOnce(DoAll(
      SetArgumentPointee<0>(TracerConfiguration::ProviderDefinitions()),
      SetArgumentPointee<1>(app_file),
      Return(false)));
  ASSERT_HRESULT_SUCCEEDED(controller.Stop());
  app_file.clear();
  ASSERT_TRUE(controller.GetCompletedEventLogFileName(&app_file));
  ASSERT_TRUE(temp_dir_.path().IsParent(app_file));
}

TEST_F(TracerControllerTest, TestWithKernelEnabled) {
  TracerConfiguration config;
  ASSERT_NO_FATAL_FAILURE(RetrieveConfiguration("kernel-enabled", &config));

  // Expectations:
  // 1) both logging operations engaged.
  // 2) Auto-generated file names below the temp_dir_.
  MockTracerController controller;
  EXPECT_CALL(controller, VerifyAndStopIfRunning(_)).
      WillRepeatedly(Return(true));
  EXPECT_CALL(controller, StartLogging(_, _, StrEq(KERNEL_LOGGER_NAME))).
      WillOnce(Invoke(this, &TracerControllerTest::InterceptStartLogging));
  EXPECT_CALL(controller, StartLogging(_, _,
      StrEq(TracerController::kSawdustTraceSessionName))).
          WillOnce(Invoke(this, &TracerControllerTest::InterceptStartLogging));
  EXPECT_CALL(controller, EnableProviders(_, _)).
      WillOnce(Invoke(this, &TracerControllerTest::InterceptEnableProviders));

  ASSERT_HRESULT_SUCCEEDED(controller.Start(config));

  // Check if logging to the right files.
  ASSERT_FALSE(intercepted_logger_paths_.find(
      TracerController::kSawdustTraceSessionName) ==
          intercepted_logger_paths_.end());
  FilePath app_file(intercepted_logger_paths_.find(
      TracerController::kSawdustTraceSessionName)->second);

  ASSERT_FALSE(intercepted_logger_paths_.find(KERNEL_LOGGER_NAME) ==
               intercepted_logger_paths_.end());
  FilePath kernel_file(
      intercepted_logger_paths_.find(KERNEL_LOGGER_NAME)->second);

  EXPECT_CALL(controller, StopKernelLogging(_)).WillOnce(DoAll(
      SetArgumentPointee<0>(kernel_file), Return(true)));
  EXPECT_CALL(controller, StopLogging(_, _)).WillOnce(DoAll(
      SetArgumentPointee<0>(TracerConfiguration::ProviderDefinitions()),
      SetArgumentPointee<1>(app_file),
      Return(true)));
  ASSERT_HRESULT_SUCCEEDED(controller.Stop());

  app_file.clear();
  kernel_file.clear();
  ASSERT_TRUE(controller.GetCompletedEventLogFileName(&app_file));
  ASSERT_TRUE(temp_dir_.path().IsParent(app_file));
  ASSERT_TRUE(controller.GetCompletedKernelEventLogFileName(&kernel_file));
  ASSERT_TRUE(temp_dir_.path().IsParent(kernel_file));
  ASSERT_EQ(intercepted_providers_.size(), 5);
}

TEST_F(TracerControllerTest, TestWithKernelAndPaths) {
  TracerConfiguration config;
  ASSERT_NO_FATAL_FAILURE(
      RetrieveConfiguration("complete-definition", &config));

  FilePath app_file, kernel_file;
  ASSERT_TRUE(config.GetLogFileName(&app_file));
  ASSERT_TRUE(config.GetKernelLogFileName(&kernel_file));

  // Expectations: both logs will be created and set to write to files given
  // in settings.
  MockTracerController controller;
  EXPECT_CALL(controller, VerifyAndStopIfRunning(_)).
      WillRepeatedly(Return(true));
  EXPECT_CALL(controller, StartLogging(_, _, StrEq(KERNEL_LOGGER_NAME))).
      WillOnce(Invoke(this, &TracerControllerTest::InterceptStartLogging));
  EXPECT_CALL(controller, StartLogging(_, _,
      StrEq(TracerController::kSawdustTraceSessionName))).
          WillOnce(Invoke(this, &TracerControllerTest::InterceptStartLogging));
  EXPECT_CALL(controller, EnableProviders(_, _)).
      WillOnce(Invoke(this, &TracerControllerTest::InterceptEnableProviders));

  ASSERT_HRESULT_SUCCEEDED(controller.Start(config));

  // Check if logging to the right files.
  ASSERT_FALSE(intercepted_logger_paths_.find(
      TracerController::kSawdustTraceSessionName) ==
          intercepted_logger_paths_.end());
  ASSERT_FALSE(intercepted_logger_paths_.find(KERNEL_LOGGER_NAME) ==
               intercepted_logger_paths_.end());

  EXPECT_CALL(controller, StopKernelLogging(_)).WillOnce(DoAll(
      SetArgumentPointee<0>(kernel_file), Return(true)));
  EXPECT_CALL(controller, StopLogging(_, _)).WillOnce(DoAll(
      SetArgumentPointee<0>(TracerConfiguration::ProviderDefinitions()),
      SetArgumentPointee<1>(app_file),
      Return(true)));
  ASSERT_HRESULT_SUCCEEDED(controller.Stop());

  FilePath ret_app_path, ret_kernel_path;
  ASSERT_TRUE(controller.GetCompletedEventLogFileName(&ret_app_path));
  ASSERT_EQ(app_file, ret_app_path);
  ASSERT_TRUE(controller.GetCompletedKernelEventLogFileName(&ret_kernel_path));
  ASSERT_EQ(kernel_file, ret_kernel_path);
  ASSERT_EQ(intercepted_providers_.size(), 1);
}

}  // namespace
