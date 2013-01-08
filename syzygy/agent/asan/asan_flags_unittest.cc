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

#include "syzygy/agent/asan/asan_flags.h"

#include <string>

#include "base/command_line.h"
#include "base/environment.h"
#include "base/string_number_conversions.h"
#include "base/utf_string_conversions.h"
#include "base/memory/scoped_ptr.h"
#include "gtest/gtest.h"
#include "syzygy/agent/asan/asan_heap.h"

namespace agent {
namespace asan {

namespace {

// A derived class to expose protected members for unit-testing.
class TestFlagsManager : public FlagsManager {
 public:
  using FlagsManager::kSyzyAsanEnvVar;
  using FlagsManager::kQuarantineSize;
  using FlagsManager::kCompressionReportingPeriod;
};

class FlagsManagerTest : public testing::Test {
 public:
  FlagsManagerTest() : current_command_line_(CommandLine::NO_PROGRAM) {
  }

  void SetUp() OVERRIDE {
    scoped_ptr<base::Environment> env(base::Environment::Create());
    ASSERT_TRUE(env.get() != NULL);
    env->UnSetVar(TestFlagsManager::kSyzyAsanEnvVar);
  }

 protected:
  typedef testing::Test Super;

  // Update the asan environment variable with the current command-line.
  void UpdateEnvVar() {
    scoped_ptr<base::Environment> env(base::Environment::Create());
    ASSERT_TRUE(env.get() != NULL);
    std::string current_command_line_str =
        WideToUTF8(current_command_line_.GetCommandLineString());
    EXPECT_TRUE(env->SetVar(TestFlagsManager::kSyzyAsanEnvVar,
                            current_command_line_str));
  }

  // Our test flags manager instance.
  TestFlagsManager flags_manager_;

  // The value of the command-line that we want to test.
  CommandLine current_command_line_;
};

}  // namespace

TEST_F(FlagsManagerTest, Instance) {
  ASSERT_TRUE(flags_manager_.Instance() != NULL);
}

TEST_F(FlagsManagerTest, InitializeFlagsWithEnvVar) {
  ASSERT_TRUE(flags_manager_.Instance() != NULL);
  ASSERT_TRUE(flags_manager_.Instance()->InitializeFlagsWithEnvVar());
}

TEST_F(FlagsManagerTest, SetDefaultQuarantineMaxSize) {
  // Initialize the flags with the original command line.
  ASSERT_TRUE(flags_manager_.Instance()->InitializeFlagsWithEnvVar());

  // Double the max size of the quarantine.
  unsigned int quarantine_max_size =
      HeapProxy::GetDefaultQuarantineMaxSize() * 2;
  // Increments the quarantine max size if it was set to 0.
  if (quarantine_max_size == 0)
    quarantine_max_size++;
  DCHECK_GT(quarantine_max_size, 0U);
  std::string quarantine_max_size_str = base::UintToString(quarantine_max_size);
  current_command_line_.AppendSwitchASCII(TestFlagsManager::kQuarantineSize,
                                          quarantine_max_size_str);

  // Update the asan environment variable and re-parse the flags.
  ASSERT_NO_FATAL_FAILURE(UpdateEnvVar());
  ASSERT_TRUE(flags_manager_.Instance()->InitializeFlagsWithEnvVar());

  // Ensure that the quarantine max size has been modified.
  EXPECT_EQ(HeapProxy::GetDefaultQuarantineMaxSize(), quarantine_max_size);
}

TEST_F(FlagsManagerTest, SetCompressionReportingPeriod) {
  // Initialize the flags with the original command line.
  ASSERT_TRUE(flags_manager_.Instance()->InitializeFlagsWithEnvVar());

  ASSERT_EQ(StackCaptureCache::GetDefaultCompressionReportingPeriod(),
            StackCaptureCache::GetCompressionReportingPeriod());

  size_t new_period =
      StackCaptureCache::GetDefaultCompressionReportingPeriod() + 1024;
  std::string new_period_str = base::UintToString(new_period);
  current_command_line_.AppendSwitchASCII(
      TestFlagsManager::kCompressionReportingPeriod, new_period_str);

  // Update the asan environment variable and re-parse the flags.
  ASSERT_NO_FATAL_FAILURE(UpdateEnvVar());
  ASSERT_TRUE(flags_manager_.Instance()->InitializeFlagsWithEnvVar());

  // Ensure that the quarantine max size has been modified.
  EXPECT_EQ(new_period, StackCaptureCache::GetCompressionReportingPeriod());
}

}  // namespace asan
}  // namespace agent
