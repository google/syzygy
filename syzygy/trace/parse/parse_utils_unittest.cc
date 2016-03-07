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

#include "syzygy/trace/parse/parse_utils.h"

#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/common/buffer_writer.h"

namespace trace {
namespace parser {

namespace {

class ParseTraceFileHeaderBlobTest : public ::testing::Test {
 public:
  virtual void SetUp() {
    // Ensure the buffer is big enough for the header but no blob.
    buffer_.resize(offsetof(TraceFileHeader, blob_data));

    // We don't actually care about the initial values of the header, as the
    // blob parser only cares about header_size.
    SetHeaderSize();
  }

  TraceFileHeader* GetHeader() {
    return reinterpret_cast<TraceFileHeader*>(&buffer_[0]);
  }

  void SetHeaderSize() { GetHeader()->header_size = buffer_.size(); }

  bool TestParseTraceFileHeaderBlob(const TraceFileHeader& header) {
    SetHeaderSize();
    return ParseTraceFileHeaderBlob(header, NULL, NULL, NULL);
  }

  std::vector<uint8_t> buffer_;
};

}  // namespace

TEST(ParseEnvironmentStringsTest, Succeeds) {
  wchar_t kEnvString[] = L"KEY0=value0\0KEY1=value1\0";
  TraceEnvironmentStrings env_strings;
  EXPECT_TRUE(ParseEnvironmentStrings(kEnvString, &env_strings));

  TraceEnvironmentStrings expected_env_strings;
  expected_env_strings.push_back(std::make_pair(std::wstring(L"KEY0"),
                                                std::wstring(L"value0")));
  expected_env_strings.push_back(std::make_pair(std::wstring(L"KEY1"),
                                                std::wstring(L"value1")));
  EXPECT_THAT(env_strings, ::testing::ContainerEq(expected_env_strings));
}

TEST_F(ParseTraceFileHeaderBlobTest, FailsOnTruncatedHeader) {
  // Make the header too small.
  GetHeader()->header_size--;

  EXPECT_FALSE(TestParseTraceFileHeaderBlob(*GetHeader()));
}

TEST_F(ParseTraceFileHeaderBlobTest, FailsOnShortData) {
  ::common::VectorBufferWriter writer(&buffer_);
  ASSERT_TRUE(writer.Consume(buffer_.size()));

  for (size_t i = 0; i < 8; ++i) {
    EXPECT_FALSE(TestParseTraceFileHeaderBlob(*GetHeader()));
    ASSERT_TRUE(writer.Write<uint8_t>(0));
    SetHeaderSize();
  }

  EXPECT_TRUE(TestParseTraceFileHeaderBlob(*GetHeader()));
}

TEST_F(ParseTraceFileHeaderBlobTest, FailsOnExtraData) {
  ::common::VectorBufferWriter writer(&buffer_);
  ASSERT_TRUE(writer.Consume(buffer_.size()));

  // We get a trailing zero for free simply from the string literal.
  const wchar_t kData[] = L"a string\0another string\0env1\0env2\0";
  ASSERT_TRUE(writer.Write(arraysize(kData), kData));

  EXPECT_TRUE(TestParseTraceFileHeaderBlob(*GetHeader()));

  const wchar_t kExtraData[] = L"extra data";
  ASSERT_TRUE(writer.WriteString(kExtraData));
  EXPECT_FALSE(TestParseTraceFileHeaderBlob(*GetHeader()));
}

TEST_F(ParseTraceFileHeaderBlobTest, SucceedsOnGoodData) {
  ::common::VectorBufferWriter writer(&buffer_);
  ASSERT_TRUE(writer.Consume(buffer_.size()));

  const wchar_t kModulePath[] = L"C:\\path\\to\\some\\module.dll";
  const wchar_t kCommandLine[] = L"module.exe --foo --bar=bar";
  // The second trailing zero comes for free.
  const wchar_t kEnvironment[] = L"=foobar\0KEY1=value1\0KEY2=value2\0";

  ASSERT_TRUE(writer.WriteString(kModulePath));
  ASSERT_TRUE(writer.WriteString(kCommandLine));
  ASSERT_TRUE(writer.Write(arraysize(kEnvironment), kEnvironment));

  SetHeaderSize();

  std::wstring module_path;
  std::wstring command_line;
  TraceEnvironmentStrings env_strings;
  EXPECT_TRUE(ParseTraceFileHeaderBlob(*GetHeader(), &module_path,
                                       &command_line, &env_strings));

  EXPECT_EQ(std::wstring(kModulePath), module_path);
  EXPECT_EQ(std::wstring(kCommandLine), command_line);

  TraceEnvironmentStrings expected_env_strings;
  expected_env_strings.push_back(std::make_pair(std::wstring(L""),
                                                std::wstring(L"foobar")));
  expected_env_strings.push_back(std::make_pair(std::wstring(L"KEY1"),
                                                std::wstring(L"value1")));
  expected_env_strings.push_back(std::make_pair(std::wstring(L"KEY2"),
                                                std::wstring(L"value2")));
  EXPECT_THAT(env_strings, ::testing::ContainerEq(expected_env_strings));
}

}  // namespace parser
}  // namespace trace
