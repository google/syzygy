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

#include "syzygy/agent/asan/reporters/kasko_reporter.h"

#include "base/bind.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace agent {
namespace asan {
namespace reporters {

namespace {

using testing::_;

static const char* kDummyAddress =
    reinterpret_cast<const char*>(0xBAADCA57);
static EXCEPTION_POINTERS* kDummyExceptionPointers =
    reinterpret_cast<EXCEPTION_POINTERS*>(0xBAADF00D);

class LenientMockKaskoFunctions {
 public:
  LenientMockKaskoFunctions() {}
  virtual ~LenientMockKaskoFunctions() {}

  MOCK_METHOD3(ReportCrashWithProtobuf, void(EXCEPTION_POINTERS* info,
                                             const char* protobuf,
                                             size_t protobuf_length));
  MOCK_METHOD5(ReportCrashWithProtobufAndMemoryRanges,
               void(EXCEPTION_POINTERS* info,
                    const char* protobuf,
                    size_t protobuf_length,
                    const void* const* base_addresses,
                    const size_t* lengths));
  MOCK_METHOD2(SetCrashKeyValueImpl, void(const wchar_t* key,
                                          const wchar_t* value));
 private:
  DISALLOW_COPY_AND_ASSIGN(LenientMockKaskoFunctions);
};
using MockKaskoFunctions = testing::StrictMock<LenientMockKaskoFunctions>;

}  // namespace

class KaskoReporterTest : public testing::Test {
 public:
  KaskoReporterTest() {}
  virtual ~KaskoReporterTest() {}

  void BindReportCrashWithProtobuf() {
    kasko_functions_.report_crash_with_protobuf.set_callback(
        base::Bind(&MockKaskoFunctions::ReportCrashWithProtobuf,
                   base::Unretained(&mock_)));
  }

  void BindReportCrashWithProtobufAndMemoryRanges() {
    kasko_functions_.report_crash_with_protobuf_and_memory_ranges.set_callback(
        base::Bind(&MockKaskoFunctions::ReportCrashWithProtobufAndMemoryRanges,
                   base::Unretained(&mock_)));
  }

  void BindSetCrashKeyValueImpl() {
    kasko_functions_.set_crash_key_value_impl.set_callback(
        base::Bind(&MockKaskoFunctions::SetCrashKeyValueImpl,
                   base::Unretained(&mock_)));
  }

  void BindAll() {
    BindReportCrashWithProtobuf();
    BindReportCrashWithProtobufAndMemoryRanges();
    BindSetCrashKeyValueImpl();
  }

  void CreateReporter() {
    reporter_.reset(new KaskoReporter(kasko_functions_));
  }

  // @name Access to KaskoReporter internals.
  // @{
  static bool SupportsEarlyCrashKeys() {
    return KaskoReporter::SupportsEarlyCrashKeys();
  }
  const std::vector<const void*>& range_bases() const {
    return reporter_->range_bases_;
  }
  const std::vector<size_t>& range_lengths() const {
    return reporter_->range_lengths_;
  }
  const std::string& protobuf() const {
    return reporter_->protobuf_;
  }
  // @}

  std::unique_ptr<KaskoReporter> reporter_;
  KaskoReporter::KaskoFunctions kasko_functions_;
  MockKaskoFunctions mock_;
};

TEST_F(KaskoReporterTest, CreateFails) {
  // This should fail because the unittest executable doesn't satisfy the
  // expected exports.
  reporter_ = KaskoReporter::Create();
  EXPECT_TRUE(reporter_.get() == nullptr);
}

TEST_F(KaskoReporterTest, SupportsEarlyCrashKeysFails) {
  EXPECT_FALSE(SupportsEarlyCrashKeys());
}

TEST_F(KaskoReporterTest, AreValid) {
  EXPECT_FALSE(KaskoReporter::AreValid(kasko_functions_));
  BindSetCrashKeyValueImpl();
  EXPECT_FALSE(KaskoReporter::AreValid(kasko_functions_));
  BindReportCrashWithProtobuf();
  EXPECT_TRUE(KaskoReporter::AreValid(kasko_functions_));
  BindReportCrashWithProtobufAndMemoryRanges();
  EXPECT_TRUE(KaskoReporter::AreValid(kasko_functions_));
  kasko_functions_.set_crash_key_value_impl.Reset();
  EXPECT_FALSE(KaskoReporter::AreValid(kasko_functions_));
}

TEST_F(KaskoReporterTest, BasicPropertiesWithMemoryRanges) {
  BindAll();
  CreateReporter();

  EXPECT_TRUE(reporter_->GetName() != nullptr);
  EXPECT_EQ(ReporterInterface::FEATURE_CRASH_KEYS |
      ReporterInterface::FEATURE_MEMORY_RANGES |
      ReporterInterface::FEATURE_CUSTOM_STREAMS,
      reporter_->GetFeatures());
}

TEST_F(KaskoReporterTest, BasicPropertiesWithoutMemoryRanges) {
  BindReportCrashWithProtobuf();
  BindSetCrashKeyValueImpl();
  CreateReporter();

  EXPECT_TRUE(reporter_->GetName() != nullptr);
  EXPECT_EQ(ReporterInterface::FEATURE_CRASH_KEYS |
      ReporterInterface::FEATURE_CUSTOM_STREAMS,
      reporter_->GetFeatures());
}

TEST_F(KaskoReporterTest, SetCrashKey) {
  BindAll();
  CreateReporter();

  EXPECT_CALL(mock_, SetCrashKeyValueImpl(testing::StrEq(L"key"),
                                          testing::StrEq(L"value")));
  EXPECT_TRUE(reporter_->SetCrashKey("key", "value"));
}

TEST_F(KaskoReporterTest, SetMemoryRangesFails) {
  BindReportCrashWithProtobuf();
  BindSetCrashKeyValueImpl();
  CreateReporter();

  ReporterInterface::MemoryRanges memory_ranges;
  memory_ranges.push_back(ReporterInterface::MemoryRange(kDummyAddress, 42));
  EXPECT_FALSE(reporter_->SetMemoryRanges(memory_ranges));
}

TEST_F(KaskoReporterTest, SetMemoryRangesSucceeds) {
  BindAll();
  CreateReporter();

  ReporterInterface::MemoryRanges memory_ranges;
  memory_ranges.push_back(ReporterInterface::MemoryRange(kDummyAddress, 42));
  EXPECT_TRUE(reporter_->SetMemoryRanges(memory_ranges));
  EXPECT_THAT(range_bases(),
              testing::ElementsAre(reinterpret_cast<const void*>(kDummyAddress),
                                   reinterpret_cast<const void*>(nullptr)));
  EXPECT_THAT(range_lengths(), testing::ElementsAre(42, 0));
}

TEST_F(KaskoReporterTest, SetCustomStream) {
  BindAll();
  CreateReporter();

  std::string s("hey");
  EXPECT_FALSE(reporter_->SetCustomStream(
      ReporterInterface::kCrashdataProtobufStreamType + 1,
      reinterpret_cast<const uint8_t*>(s.data()),
      s.size()));
  EXPECT_TRUE(reporter_->SetCustomStream(
      ReporterInterface::kCrashdataProtobufStreamType,
      reinterpret_cast<const uint8_t*>(s.data()),
      s.size()));
  EXPECT_THAT(protobuf(), testing::StrEq(s));
}

TEST_F(KaskoReporterTest, DumpWithoutCrashFails) {
  BindAll();
  CreateReporter();

  CONTEXT dummy_context = {};
  EXPECT_FALSE(reporter_->DumpWithoutCrash(dummy_context));
}

TEST_F(KaskoReporterTest, DumpWithoutMemoryRanges) {
  BindReportCrashWithProtobuf();
  BindSetCrashKeyValueImpl();
  CreateReporter();

  std::string s("hey");
  ASSERT_TRUE(reporter_->SetCustomStream(
      ReporterInterface::kCrashdataProtobufStreamType,
      reinterpret_cast<const uint8_t*>(s.data()),
      s.size() + 1));

  EXPECT_CALL(mock_, ReportCrashWithProtobuf(
      testing::Eq(kDummyExceptionPointers),
      testing::Eq(protobuf().data()),
      testing::Eq(protobuf().size())));
  reporter_->DumpAndCrash(kDummyExceptionPointers);
}

TEST_F(KaskoReporterTest, DumpWithMemoryRanges) {
  BindAll();
  CreateReporter();

  std::string s("hey");
  ASSERT_TRUE(reporter_->SetCustomStream(
      ReporterInterface::kCrashdataProtobufStreamType,
      reinterpret_cast<const uint8_t*>(s.data()),
      s.size() + 1));

  ReporterInterface::MemoryRanges memory_ranges;
  memory_ranges.push_back(ReporterInterface::MemoryRange(kDummyAddress, 42));
  ASSERT_TRUE(reporter_->SetMemoryRanges(memory_ranges));

  EXPECT_CALL(mock_, ReportCrashWithProtobufAndMemoryRanges(
      testing::Eq(kDummyExceptionPointers),
      testing::Eq(protobuf().data()),
      testing::Eq(protobuf().size()),
      testing::Eq(range_bases().data()),
      testing::Eq(range_lengths().data())));
  reporter_->DumpAndCrash(kDummyExceptionPointers);
}

}  // namespace reporters
}  // namespace asan
}  // namespace agent
