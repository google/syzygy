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

#include "syzygy/agent/asan/reporters/crashpad_reporter.h"

#include "base/bind.h"
#include "base/strings/stringprintf.h"
#include "gtest/gtest.h"

namespace agent {
namespace asan {
namespace reporters {

class CrashpadReporterTest : public testing::Test {
 public:
  CrashpadReporterTest() {}
  virtual ~CrashpadReporterTest() {}

  void CreateReporter() {
    // Create a reporter with a dummy CrashpadInfo, and that isn't actually
    // connected to a Crashpad server.
    crashpad_info_.reset(new crashpad::CrashpadInfo());
    reporter_.reset(new CrashpadReporter(crashpad_info_.get()));
  }

  const crashpad::CrashpadInfo* crashpad_info() {
    return reporter_->crashpad_info_;
  }

  const crashpad::SimpleAddressRangeBag* crash_ranges() {
    return reporter_->crash_ranges_.get();
  }

  const crashpad::SimpleStringDictionary* crash_keys() {
    return reporter_->crash_keys_.get();
  }

  std::unique_ptr<crashpad::CrashpadInfo> crashpad_info_;
  std::unique_ptr<CrashpadReporter> reporter_;
};

TEST_F(CrashpadReporterTest, CreateFails) {
  // This should fail because the unittest executable doesn't have crashpad
  // reporter integration.
  reporter_ = CrashpadReporter::Create();
  EXPECT_TRUE(reporter_.get() == nullptr);
}

TEST_F(CrashpadReporterTest, BasicProperties) {
  CreateReporter();

  EXPECT_TRUE(reporter_->GetName() != nullptr);
  EXPECT_EQ(ReporterInterface::FEATURE_CRASH_KEYS |
              ReporterInterface::FEATURE_EARLY_CRASH_KEYS |
              ReporterInterface::FEATURE_MEMORY_RANGES |
              ReporterInterface::FEATURE_CUSTOM_STREAMS |
              ReporterInterface::FEATURE_DUMP_WITHOUT_CRASH,
            reporter_->GetFeatures());
}

TEST_F(CrashpadReporterTest, SetCrashKey) {
  CreateReporter();
  EXPECT_EQ(0u, crash_keys()->GetCount());

  static const char kKey[] = "key";
  static const char kValue[] = "value";
  reporter_->SetCrashKey(kKey, kValue);
  EXPECT_EQ(1u, crash_keys()->GetCount());
  EXPECT_STREQ(kValue, crash_keys()->GetValueForKey(kKey));
}

TEST_F(CrashpadReporterTest, SetCrashKeyFailsWhenFull) {
  CreateReporter();
  EXPECT_EQ(0u, crash_keys()->GetCount());

  for (size_t i = 0; i < crashpad::SimpleAddressRangeBag::num_entries; ++i) {
    std::string key = base::StringPrintf("key%d", i);
    ASSERT_TRUE(reporter_->SetCrashKey(key.c_str(), key.c_str()));
    ASSERT_EQ(i + 1, crash_keys()->GetCount());
    ASSERT_STREQ(key.c_str(), crash_keys()->GetValueForKey(key.c_str()));
  }

  EXPECT_FALSE(reporter_->SetCrashKey("hey", "there"));
}

TEST_F(CrashpadReporterTest, SetMemoryRanges) {
  CreateReporter();
  EXPECT_TRUE(crash_ranges() == nullptr);

  ReporterInterface::MemoryRanges ranges;
  ranges.push_back(ReporterInterface::MemoryRange(
      reinterpret_cast<const char*>(0xDEADF00D), 10));
  EXPECT_TRUE(reporter_->SetMemoryRanges(ranges));
  ASSERT_TRUE(crash_ranges() != nullptr);
  EXPECT_EQ(1u, crash_ranges()->GetCount());

  ranges.push_back(ReporterInterface::MemoryRange(
      reinterpret_cast<const char*>(0xBAADBEEF), 20));
  EXPECT_TRUE(reporter_->SetMemoryRanges(ranges));
  ASSERT_TRUE(crash_ranges() != nullptr);
  EXPECT_EQ(2u, crash_ranges()->GetCount());
}

TEST_F(CrashpadReporterTest, SetMemoryRangesFailsWhenTooMany) {
  CreateReporter();
  EXPECT_TRUE(crash_ranges() == nullptr);

  ReporterInterface::MemoryRanges ranges;
  for (size_t i = 0; i <= crashpad::SimpleAddressRangeBag::num_entries; ++i) {
    const char* addr = reinterpret_cast<const char*>(0xDEADF00D) + 100 * i;
    ranges.push_back(ReporterInterface::MemoryRange(addr, 10));
  }

  EXPECT_FALSE(reporter_->SetMemoryRanges(ranges));
  ASSERT_TRUE(crash_ranges() != nullptr);
  EXPECT_EQ(crashpad::SimpleAddressRangeBag::num_entries,
            crash_ranges()->GetCount());
}

}  // namespace reporters
}  // namespace asan
}  // namespace agent
