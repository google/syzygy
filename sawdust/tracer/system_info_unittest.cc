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
#include "sawdust/tracer/system_info.h"

#include <algorithm>
#include <string>

#include "base/logging.h"
#include "base/scoped_ptr.h"
#include "gtest/gtest.h"
#include "sawdust/tracer/tracer_unittest_util.h"

namespace {

const char kTestDataForEnvVars[] =
    "VAR1=jklasjklsjkldkklas1212312klaskl\"\n"
    "VAR2=A very curious variable value\n"
    "SYSTEM=UNKNOWN or something else\n"
    "ABCDE=\n"
    "TEST=123456789\n"
    "MORE=C:\\Windows\\Look at me here\\\n";

class TestingSystemInfoExtractor : public SystemInfoExtractor {
 public:
  static void CallFromSystemInfo(const SYSTEM_INFO& data,
                                 std::string* out_string) {
    FromSystemInfo(data, out_string);
  }

  // Invokes ListEnvironmentStrings, feeding it the content of |in_table|
  // rearranged to look like GetEnvironmentStrings return value.
  // |in_table| is a list of \n separated KEY=VALUE pairs. Test values cannot
  // contain /n.
  static void CallListEnvironmentStrings(const std::string& in_table,
                                         std::string* out_string) {
    scoped_array<wchar_t> string_table(
        CreateNullNullTerminatedDescription(in_table, NULL));
    EXPECT_TRUE(string_table != NULL);
    if (string_table != NULL)
      ListEnvironmentStrings(string_table.get(), out_string);
  }

  // List of headers expected in the output text.
  const std::list<std::string>& ListHeaders() {
    if (headers_.empty()) {
      headers_.push_back(kHeaderMem);
      headers_.push_back(kHeaderSysName);
      headers_.push_back(kHeaderSysInfo);
      headers_.push_back(kHeaderSysInfo2);
      headers_.push_back(kHeaderPageSize);
      headers_.push_back(kHeaderProcs);
      headers_.push_back(kHeaderProcRev);
      headers_.push_back(kHeaderProcMask);
    }
    return headers_;
  }

  void GetData(std::string* ret_data) {
    const TestingSystemInfoExtractor::StreamType& real_data =
        static_cast<const TestingSystemInfoExtractor::StreamType&>(Data());

    *ret_data = real_data.str();
  }

 private:
  void AppendEnvironmentStrings(std::string* out_string) {
    // Test version feeds the usual constant (reformatted) to
    // ListEnvironmentStrings.
    CallListEnvironmentStrings(kTestDataForEnvVars, out_string);
  }

  std::list<std::string> headers_;
};

// Exercises the function formatting the output of GetEnvironmentStrings.
TEST(SystemInfoExtractorTest, ListEnvironmentStrings) {
  std::string source_data(kTestDataForEnvVars);
  std::string comparison_data;
  TestingSystemInfoExtractor::CallListEnvironmentStrings(source_data,
                                                         &comparison_data);
  ASSERT_EQ(source_data, comparison_data);
}

// Exercises the function formatting results of GetSystemInfo and
// GetNativeSystemInfo.
TEST(SystemInfoExtractorTest, FormatSystemInfo) {
  SYSTEM_INFO sys_info;
  memset(&sys_info, 0, sizeof(sys_info));
  sys_info.wProcessorArchitecture = PROCESSOR_ARCHITECTURE_INTEL;
  sys_info.dwPageSize = 2048;
  sys_info.dwNumberOfProcessors = 4;
  std::string formatted_string;
  TestingSystemInfoExtractor::CallFromSystemInfo(sys_info, &formatted_string);
  ASSERT_NE(std::string::npos, formatted_string.find("x86"));
  ASSERT_NE(std::string::npos, formatted_string.find("processors:\t4"));

  formatted_string.clear();
  sys_info.wProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64;
  TestingSystemInfoExtractor::CallFromSystemInfo(sys_info, &formatted_string);
  ASSERT_NE(std::string::npos, formatted_string.find("x64"));
  ASSERT_NE(std::string::npos, formatted_string.find("Page size:\t2048"));

  formatted_string.clear();
  sys_info.wProcessorArchitecture = PROCESSOR_ARCHITECTURE_UNKNOWN;
  TestingSystemInfoExtractor::CallFromSystemInfo(sys_info, &formatted_string);
  ASSERT_NE(std::string::npos, formatted_string.find("unknown"));
}

TEST(SystemInfoExtractorTest, FullInitializationTest) {
  TestingSystemInfoExtractor test_instance;
  test_instance.Initialize(true);

  {
    std::string formatted_data;
    test_instance.GetData(&formatted_data);
    const std::list<std::string>& headers = test_instance.ListHeaders();
    for (std::list<std::string>::const_iterator word_it = headers.begin();
         word_it != headers.end(); ++word_it) {
      ASSERT_NE(std::string::npos, formatted_data.find(*word_it));
    }
    ASSERT_NE(std::string::npos, formatted_data.find(kTestDataForEnvVars));
    test_instance.MarkCompleted();
  }

  test_instance.Initialize(false);
  {
    std::string formatted_data;
    test_instance.GetData(&formatted_data);

    const std::list<std::string>& headers = test_instance.ListHeaders();
    for (std::list<std::string>::const_iterator word_it = headers.begin();
         word_it != headers.end(); ++word_it) {
      ASSERT_NE(std::string::npos, formatted_data.find(*word_it));
    }
    ASSERT_EQ(std::string::npos, formatted_data.find(kTestDataForEnvVars));
    test_instance.MarkCompleted();
  }
}

}  // namespace
