// Copyright 2016 Google Inc. All Rights Reserved.
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

#include "syzygy/agent/asan/reporters/breakpad_reporter.h"

#include "base/bind.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace agent {
namespace asan {
namespace reporters {

namespace {

using testing::_;

class LenientMockBreakpadFunctions {
 public:
  LenientMockBreakpadFunctions() {}
  virtual ~LenientMockBreakpadFunctions() {}

  MOCK_METHOD1(CrashForException, int(EXCEPTION_POINTERS* info));
  MOCK_METHOD2(SetCrashKeyValuePair, void(const char* key,
                                          const char* value));
  MOCK_METHOD2(SetCrashKeyValueImpl, void(const wchar_t* key,
                                          const wchar_t* value));
 private:
  DISALLOW_COPY_AND_ASSIGN(LenientMockBreakpadFunctions);
};
using MockBreakpadFunctions = testing::StrictMock<LenientMockBreakpadFunctions>;

}  // namespace

class BreakpadReporterTest : public testing::Test {
 public:
  BreakpadReporterTest() {}
  virtual ~BreakpadReporterTest() {}

  void BindCrashForException() {
    breakpad_functions_.crash_for_exception.set_callback(
        base::Bind(&MockBreakpadFunctions::CrashForException,
                   base::Unretained(&mock_)));
  }

  void BindSetCrashKeyValuePair() {
    breakpad_functions_.set_crash_key_value_pair.set_callback(
        base::Bind(&MockBreakpadFunctions::SetCrashKeyValuePair,
                   base::Unretained(&mock_)));
  }

  void BindSetCrashKeyValueImpl() {
    breakpad_functions_.set_crash_key_value_impl.set_callback(
        base::Bind(&MockBreakpadFunctions::SetCrashKeyValueImpl,
                   base::Unretained(&mock_)));
  }

  // Binds the normal set of functions.
  void BindNormal() {
    BindCrashForException();
    BindSetCrashKeyValueImpl();
  }

  void CreateReporter() {
    reporter_.reset(new BreakpadReporter(breakpad_functions_));
  }

  std::unique_ptr<BreakpadReporter> reporter_;
  BreakpadReporter::BreakpadFunctions breakpad_functions_;
  MockBreakpadFunctions mock_;
};

TEST_F(BreakpadReporterTest, CreateFails) {
  // This should fail because the unittest executable doesn't satisfy the
  // expected exports.
  reporter_ = BreakpadReporter::Create();
  EXPECT_TRUE(reporter_.get() == nullptr);
}

TEST_F(BreakpadReporterTest, AreValid) {
  // No functions being set is invalid.
  EXPECT_FALSE(BreakpadReporter::AreValid(breakpad_functions_));

  // Missing CrashForException.
  BindSetCrashKeyValueImpl();
  EXPECT_FALSE(BreakpadReporter::AreValid(breakpad_functions_));

  // One crash key function and CrashForException is valid.
  BindCrashForException();
  EXPECT_TRUE(BreakpadReporter::AreValid(breakpad_functions_));

  // Two crash key functions is invalid.
  BindSetCrashKeyValuePair();
  EXPECT_FALSE(BreakpadReporter::AreValid(breakpad_functions_));

  // One crash key function and CrashForException is valid.
  breakpad_functions_.set_crash_key_value_impl.Reset();
  EXPECT_TRUE(BreakpadReporter::AreValid(breakpad_functions_));

  // Missing CrashForException.
  breakpad_functions_.crash_for_exception.Reset();
  EXPECT_FALSE(BreakpadReporter::AreValid(breakpad_functions_));
}

TEST_F(BreakpadReporterTest, BasicProperties) {
  BindNormal();
  CreateReporter();

  EXPECT_TRUE(reporter_->GetName() != nullptr);
  EXPECT_EQ(ReporterInterface::FEATURE_CRASH_KEYS, reporter_->GetFeatures());
}

TEST_F(BreakpadReporterTest, SetCrashKeyValuePair) {
  BindCrashForException();
  BindSetCrashKeyValuePair();
  CreateReporter();

  EXPECT_CALL(mock_, SetCrashKeyValuePair(testing::StrEq("key"),
                                          testing::StrEq("value")));
  EXPECT_TRUE(reporter_->SetCrashKey("key", "value"));
}

TEST_F(BreakpadReporterTest, SetCrashKeyValueImpl) {
  BindCrashForException();
  BindSetCrashKeyValueImpl();
  CreateReporter();

  EXPECT_CALL(mock_, SetCrashKeyValueImpl(testing::StrEq(L"key"),
                                          testing::StrEq(L"value")));
  EXPECT_TRUE(reporter_->SetCrashKey("key", "value"));
}

TEST_F(BreakpadReporterTest, SetMemoryRangesFails) {
  BindNormal();
  CreateReporter();

  ReporterInterface::MemoryRanges memory_ranges;
  memory_ranges.push_back(ReporterInterface::MemoryRange(
      reinterpret_cast<const char*>(0xBAADCA57), 42));
  EXPECT_FALSE(reporter_->SetMemoryRanges(memory_ranges));
}

TEST_F(BreakpadReporterTest, SetCustomStreamFails) {
  BindNormal();
  CreateReporter();

  // No streams are supported, not even the crashdata protobuf.
  std::string s("hey");
  EXPECT_FALSE(reporter_->SetCustomStream(
      ReporterInterface::kCrashdataProtobufStreamType + 1,
      reinterpret_cast<const uint8_t*>(s.data()),
      s.size()));
  EXPECT_FALSE(reporter_->SetCustomStream(
      ReporterInterface::kCrashdataProtobufStreamType,
      reinterpret_cast<const uint8_t*>(s.data()),
      s.size()));
}

TEST_F(BreakpadReporterTest, DumpWithoutCrashFails) {
  BindNormal();
  CreateReporter();

  CONTEXT dummy_context = {};
  EXPECT_FALSE(reporter_->DumpWithoutCrash(dummy_context));
}

TEST_F(BreakpadReporterTest, DumpAndCrash) {
  BindNormal();
  CreateReporter();

  EXCEPTION_POINTERS* dummy_pointers = reinterpret_cast<EXCEPTION_POINTERS*>(
      0xBAADF00D);
  EXPECT_CALL(mock_, CrashForException(testing::Eq(dummy_pointers)));
  reporter_->DumpAndCrash(dummy_pointers);
}

}  // namespace reporters
}  // namespace asan
}  // namespace agent
