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
#include "sawdust/app/report.h"

#include <iostream>  // NOLINT - streams used as abstracts, without formatting.
#include <string>
#include <vector>

#include "base/file_path.h"
#include "base/file_util.h"
#include "base/scoped_temp_dir.h"
#include "base/utf_string_conversions.h"
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
  MOCK_CONST_METHOD1(GetCompletedEventLogFileName, bool(FilePath*));
  MOCK_CONST_METHOD1(GetCompletedKernelEventLogFileName, bool(FilePath*));
};

class MockTracerConfiguration : public TracerConfiguration {
 public:
  MOCK_CONST_METHOD0(IsKernelLoggingEnabled, bool());
  MOCK_CONST_METHOD1(GetRegistryQuery, bool(std::vector<std::wstring>*));
};


// The custom mock class (can't use standard mocking mechanism) substitutes
// the entire public interface with functions that do nothing interesting.
class MockRegistryExtractor : public RegistryExtractor {
 public:
  virtual int Initialize(const std::vector<std::wstring>& input_container) {
    // Just return the query itself.
    std::string return_container;
    for (std::vector<std::wstring>::const_iterator it = input_container.begin();
         it != input_container.end(); ++it) {
      return_container += WideToUTF8(*it);
      return_container += L'\n';
    }
    mock_data_as_stream_.str(return_container);
    return input_container.size();
  }
  std::istream& Data() { return mock_data_as_stream_; }
  void MarkCompleted() { mock_data_as_stream_.seekg(0); }

  const char* Title() const { return "FakeRegistryExtract.txt"; }
 private:
  std::istringstream mock_data_as_stream_;
};

class MockSystemInfoExtractor : public SystemInfoExtractor {
 public:
  virtual void Initialize(bool include_env_variables) {
    std::string return_container(
        "This content is completely bogus.\n All similarities to the real "
        "thing are completely coincidental.");
    mock_data_as_stream_.str(return_container);
  }

  std::istream& Data() { return mock_data_as_stream_; }
  void MarkCompleted() { mock_data_as_stream_.seekg(0); }

  const char* Title() const { return "FakeSystemInformation.txt"; }
 private:
  std::istringstream mock_data_as_stream_;
};

class TestingReportContent : public ReportContent {
 private:
  SystemInfoExtractor* CreateInfoExtractor() {
    return new MockSystemInfoExtractor();
  }

  RegistryExtractor* CreateRegistryExtractor() {
    return new MockRegistryExtractor();
  }
};

// Base class for all upload tests.
class ReportContentTest : public testing::Test {
 public:
  void SetUp() {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    srand(static_cast<unsigned>(time(NULL)));
    kernel_fake_file_ = temp_dir_.path().Append(L"Kernel.log");
    app_fake_file_ = temp_dir_.path().Append(L"Application.log");
    CreateTestFile(kernel_fake_file_ , 10000);
    CreateTestFile(app_fake_file_ , 5000);
  }

 protected:
  void CreateTestFile(const FilePath& path, int length) {
    scoped_array<int> random_buffer(new int[length]);
    std::generate(random_buffer.get(), random_buffer.get() + length, rand);
    char* as_char = reinterpret_cast<char*>(random_buffer.get());

    size_t buffer_size = length *
        sizeof(random_buffer[0]) / sizeof(as_char[0]);
    file_util::WriteFile(path, as_char, buffer_size);
  }

  ScopedTempDir temp_dir_;
  FilePath kernel_fake_file_;
  FilePath app_fake_file_;
};

TEST_F(ReportContentTest, CompleteReportDump) {
  MockTracerInfoFunctions mock_controller;
  MockTracerConfiguration mock_config;
  std::vector<std::wstring> fake_reg_query;
  fake_reg_query.push_back(L"Line one with nothing useful.");
  fake_reg_query.push_back(L"Line two with nothing useful.");
  fake_reg_query.push_back(L"Another line that doesn't look right.");
  fake_reg_query.push_back(L"HKEY_LOCAL_MACHINE\\Software\\Google\\Yay!");

  EXPECT_CALL(mock_controller, GetCompletedEventLogFileName(_)).
      WillOnce(DoAll(SetArgumentPointee<0>(app_fake_file_), Return(true)));
  EXPECT_CALL(mock_controller, GetCompletedKernelEventLogFileName(_)).
      WillOnce(DoAll(SetArgumentPointee<0>(kernel_fake_file_), Return(true)));
  EXPECT_CALL(mock_config, IsKernelLoggingEnabled()).WillOnce(Return(true));
  EXPECT_CALL(mock_config, GetRegistryQuery(_)).
      WillOnce(DoAll(SetArgumentPointee<0>(fake_reg_query), Return(true)));

  TestingReportContent test_object;
  ASSERT_HRESULT_SUCCEEDED(test_object.Initialize(mock_controller,
                                                  mock_config));

  // Having initialized the content, we can now walk through it.
  int entry_counter = 0;
  IReportContentEntry* entry = NULL;
  HRESULT hr = test_object.GetNextEntry(&entry);
  while (hr == S_OK) {
    entry_counter++;
    std::istream& data = entry->Data();

    // Read just a chunk.
    char buffer[15];
    std::streamsize bytes_read = data.read(buffer, sizeof(buffer)).gcount();
    ASSERT_EQ(bytes_read, sizeof(buffer));
    hr = test_object.GetNextEntry(&entry);
  }
  ASSERT_HRESULT_SUCCEEDED(hr);
  ASSERT_EQ(entry_counter, 4);
}

TEST_F(ReportContentTest, PartialReportDump) {
  MockTracerInfoFunctions mock_controller;
  MockTracerConfiguration mock_config;

  EXPECT_CALL(mock_controller, GetCompletedEventLogFileName(_)).
      WillOnce(DoAll(SetArgumentPointee<0>(app_fake_file_), Return(true)));
  EXPECT_CALL(mock_controller, GetCompletedKernelEventLogFileName(_)).Times(0);
  EXPECT_CALL(mock_config, IsKernelLoggingEnabled()).WillOnce(Return(false));
  EXPECT_CALL(mock_config, GetRegistryQuery(_)).WillOnce(Return(false));

  TestingReportContent test_object;
  ASSERT_HRESULT_SUCCEEDED(test_object.Initialize(mock_controller,
                                                  mock_config));

  // Having initialized the content, we can now walk through it.
  int entry_counter = 0;
  IReportContentEntry* entry = NULL;
  HRESULT hr = test_object.GetNextEntry(&entry);
  while (hr == S_OK) {
    entry_counter++;
    std::istream& data = entry->Data();

    // Read just a chunk.
    char buffer[15];
    std::streamsize bytes_read = data.read(buffer, sizeof(buffer)).gcount();
    ASSERT_EQ(bytes_read, sizeof(buffer));
    hr = test_object.GetNextEntry(&entry);
  }
  ASSERT_HRESULT_SUCCEEDED(hr);
  ASSERT_EQ(entry_counter, 2);
}

}  // namespace
