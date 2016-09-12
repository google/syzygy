// Copyright 2015 Google Inc. All Rights Reserved.
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

#include "syzygy/agent/asan/registry_cache.h"

#include "base/base_paths.h"
#include "base/file_version_info_win.h"
#include "base/path_service.h"
#include "base/rand_util.h"
#include "base/files/file_path.h"
#include "base/test/test_reg_util_win.h"
#include "base/win/registry.h"
#include "gtest/gtest.h"
#include "syzygy/agent/asan/block.h"
#include "syzygy/agent/asan/heap_checker.h"
#include "syzygy/agent/common/stack_capture.h"

namespace agent {
namespace asan {

namespace {

using registry_util::RegistryOverrideManager;

// A derived class to expose protected members for unit-testing.
class TestRegistryCache : public RegistryCache {
 public:
  using RegistryCache::max_days_in_registry_;
  using RegistryCache::max_entries_per_version_;
  using RegistryCache::max_modules_;
  using RegistryCache::max_versions_;
  using RegistryCache::registry_cache_key_;
  using RegistryCache::module_key_name_;
  using RegistryCache::AddOrUpdateStackId;
  using RegistryCache::RegValueIter;
  using RegistryCache::RegKeyIter;
  using RegistryCache::StackId;
  static const wchar_t kTestRegistryName[];

  TestRegistryCache() : RegistryCache(kTestRegistryName) {}
  TestRegistryCache(const wchar_t registry_name[],
                    size_t max_days_in_registry,
                    size_t max_entries_per_version,
                    size_t max_modules,
                    size_t max_versions)
      : RegistryCache(registry_name,
                      max_days_in_registry,
                      max_entries_per_version,
                      max_modules,
                      max_versions) {}
};

const wchar_t TestRegistryCache::kTestRegistryName[] = L"TEST";

class RegistryCacheTest : public testing::Test {
 public:
  void SetUp() override {
    // Setup the "global" state.
    registry_key_ = TestRegistryCache::kRegistryBaseKey;
    registry_key_ += TestRegistryCache::kTestRegistryName;
    override_manager_.OverrideRegistry(TestRegistryCache::kRegistryRootKey);
  }

  base::Time RecentTime() const {
    return base::Time::Now() -
        base::TimeDelta::FromDays(
            static_cast<uint32_t>(registry_cache_.max_days_in_registry_ / 2));
  }

  base::Time OldTime() const {
    return base::Time::Now() -
        base::TimeDelta::FromDays(
            static_cast<uint32_t>(registry_cache_.max_days_in_registry_ + 9));
  }

  // Returns the number of keys that exist in a registry location.
  // @param root The root key of the registry.
  // @param location The location in the registry.
  // @return Number of keys.
  int GetKeyCount(const HKEY root, const std::wstring& location) const {
    int count = 0;
    TestRegistryCache::RegKeyIter iter(root, location.c_str());
    while (iter.Valid()) {
      ++count;
      ++iter;
    }
    return count;
  }

 protected:
  TestRegistryCache registry_cache_;
  RegistryOverrideManager override_manager_;
  base::win::RegKey key_;
  base::string16 registry_key_;
};

}  // namespace

TEST_F(RegistryCacheTest, Constructors) {
  // Default constructor.
  EXPECT_EQ(RegistryCache::kDefaultMaxDaysInRegistry,
            registry_cache_.max_days_in_registry_);
  EXPECT_EQ(RegistryCache::kDefaultMaxEntriesPerVersion,
            registry_cache_.max_entries_per_version_);
  EXPECT_EQ(RegistryCache::kDefaultMaxModules,
            registry_cache_.max_modules_);
  EXPECT_EQ(RegistryCache::kDefaultMaxVersions,
            registry_cache_.max_versions_);

  TestRegistryCache registry_cache2(L"TESTING", 10, 20, 30, 40);
  EXPECT_EQ(10, registry_cache2.max_days_in_registry_);
  EXPECT_EQ(20, registry_cache2.max_entries_per_version_);
  EXPECT_EQ(30, registry_cache2.max_modules_);
  EXPECT_EQ(40, registry_cache2.max_versions_);
  EXPECT_EQ(L"TESTING", registry_cache2.registry_cache_key_.substr(
      registry_cache2.registry_cache_key_.size() - 7));
}

TEST_F(RegistryCacheTest, RemoveOldEntries) {
  base::Time recent_time = RecentTime();
  base::Time old_time = OldTime();
  key_.Create(TestRegistryCache::kRegistryRootKey,
              (registry_key_ + L"\\Application 1\\v1").c_str(), KEY_ALL_ACCESS);
  ASSERT_TRUE(key_.Valid());

  TestRegistryCache::StackId stack_id_old = 4567890;
  key_.WriteValue(base::Int64ToString16(old_time.ToInternalValue()).c_str(),
                  &stack_id_old, sizeof(stack_id_old), REG_BINARY);
  TestRegistryCache::StackId stack_id_recent = 9876543;
  key_.WriteValue(base::Int64ToString16(recent_time.ToInternalValue()).c_str(),
                  &stack_id_recent, sizeof(stack_id_recent), REG_BINARY);

  registry_cache_.Init();

  // Only the recent entry should be left.
  EXPECT_EQ(1, key_.GetValueCount());
  TestRegistryCache::StackId value;
  DWORD dsize = sizeof(value);
  DWORD dtype = 0;
  key_.ReadValue(base::Int64ToString16(recent_time.ToInternalValue()).c_str(),
                 &value, &dsize, &dtype);
  EXPECT_EQ(sizeof(stack_id_recent), dsize);
  EXPECT_EQ(stack_id_recent, value);
}

TEST_F(RegistryCacheTest, RemoveEmptyKeys) {
  base::Time recent_time = RecentTime();
  key_.Create(TestRegistryCache::kRegistryRootKey,
              (registry_key_ + L"\\Application 1\\v1").c_str(), KEY_ALL_ACCESS);
  ASSERT_TRUE(key_.Valid());
  key_.Create(TestRegistryCache::kRegistryRootKey,
              (registry_key_ + L"\\Application 2\\v1").c_str(), KEY_ALL_ACCESS);
  ASSERT_TRUE(key_.Valid());
  const TestRegistryCache::StackId stack_id = 4567890;
  key_.WriteValue(base::Int64ToString16(recent_time.ToInternalValue()).c_str(),
                  &stack_id, sizeof(stack_id), REG_BINARY);
  key_.Close();

  registry_cache_.Init();

  key_.Open(TestRegistryCache::kRegistryRootKey,
            (registry_key_ + L"\\Application 1\\v1").c_str(), KEY_ALL_ACCESS);
  EXPECT_FALSE(key_.Valid());
  key_.Open(TestRegistryCache::kRegistryRootKey,
            (registry_key_ + L"\\Application 1").c_str(), KEY_ALL_ACCESS);
  EXPECT_FALSE(key_.Valid());
  key_.Open(TestRegistryCache::kRegistryRootKey,
            (registry_key_ + L"\\Application 2\\v1").c_str(), KEY_ALL_ACCESS);
  EXPECT_TRUE(key_.Valid());
}

TEST_F(RegistryCacheTest, MaximumNbKeys) {
  const int delta = 42;
  key_.Create(TestRegistryCache::kRegistryRootKey,
              (registry_key_ + L"\\Application 1\\v1").c_str(), KEY_ALL_ACCESS);
  ASSERT_TRUE(key_.Valid());
  TestRegistryCache::StackId stack_id;
  // Start with current time and add increment for each iteration of the loop,
  // instead of using Time::now() each time. Avoids having possible duplicates
  // if the iteration runs too fast.
  base::Time start_time = base::Time::Now();
  for (int i = 0; i < TestRegistryCache::kDefaultMaxEntriesPerVersion + delta;
       i++) {
    stack_id = base::RandUint64();
    base::Time time = start_time + base::TimeDelta::FromMilliseconds(i);
    key_.WriteValue(base::Int64ToString16(time.ToInternalValue()).c_str(),
                    &stack_id, sizeof(stack_id), REG_BINARY);
  }
  EXPECT_EQ(TestRegistryCache::kDefaultMaxEntriesPerVersion + delta,
            key_.GetValueCount());
  registry_cache_.Init();
  EXPECT_EQ(TestRegistryCache::kDefaultMaxEntriesPerVersion,
            key_.GetValueCount());
}

TEST_F(RegistryCacheTest, MaximumNbVersions) {
  const int delta = 42;
  const std::wstring app_base_key(registry_key_ + L"\\App");
  TestRegistryCache::StackId stack_id;
  key_.Create(TestRegistryCache::kRegistryRootKey, app_base_key.c_str(),
              KEY_ALL_ACCESS);
  ASSERT_TRUE(key_.Valid());
  key_.Close();
  // Create a lot of version numbers under a single module (more than
  // |kMaxVersions|). The number of keys should be brought down to
  // |kMaxVersions| after the cleaning process.
  for (int i = 0; i < TestRegistryCache::kDefaultMaxVersions + delta; i++) {
    key_.Create(TestRegistryCache::kRegistryRootKey,
                (app_base_key + L"\\v" + base::IntToString16(i)).c_str(),
                KEY_ALL_ACCESS);
    ASSERT_TRUE(key_.Valid());
    stack_id = base::RandUint64();
    key_.WriteValue(
        base::Int64ToString16(base::Time::Now().ToInternalValue()).c_str(),
        &stack_id, sizeof(stack_id), REG_BINARY);
    ASSERT_EQ(1, key_.GetValueCount());
    key_.Close();
  }
  EXPECT_EQ(TestRegistryCache::kDefaultMaxVersions + delta,
            GetKeyCount(TestRegistryCache::kRegistryRootKey, app_base_key));
  registry_cache_.Init();
  EXPECT_EQ(TestRegistryCache::kDefaultMaxVersions,
            GetKeyCount(TestRegistryCache::kRegistryRootKey, app_base_key));
}

TEST_F(RegistryCacheTest, MaximumNbModules) {
  const int delta = 42;
  TestRegistryCache::StackId stack_id;
  key_.Create(TestRegistryCache::kRegistryRootKey, (registry_key_).c_str(),
              KEY_ALL_ACCESS);
  ASSERT_TRUE(key_.Valid());
  key_.Close();
  // Create a lot of modules (more than |kMaxModules|). The number of keys
  // should be brought down to |kMaxModules| after the cleaning process.
  for (int i = 0; i < TestRegistryCache::kDefaultMaxModules + delta; i++) {
    key_.Create(
        TestRegistryCache::kRegistryRootKey,
        (registry_key_ + L"\\App" + base::IntToString16(i) + L"\\v1").c_str(),
        KEY_ALL_ACCESS);
    ASSERT_TRUE(key_.Valid());
    stack_id = base::RandUint64();
    key_.WriteValue(
        base::Int64ToString16(base::Time::Now().ToInternalValue()).c_str(),
        &stack_id, sizeof(stack_id), REG_BINARY);
    ASSERT_EQ(1, key_.GetValueCount());
    key_.Close();
  }
  EXPECT_EQ(TestRegistryCache::kDefaultMaxModules + delta,
            GetKeyCount(TestRegistryCache::kRegistryRootKey, registry_key_));
  registry_cache_.Init();
  EXPECT_EQ(TestRegistryCache::kDefaultMaxModules,
            GetKeyCount(TestRegistryCache::kRegistryRootKey, registry_key_));
}

TEST_F(RegistryCacheTest, DoesIdExist) {
  // Called a 1st time to initialize |module_key_name_|.
  registry_cache_.Init();

  base::Time recent_time = RecentTime();
  key_.Create(TestRegistryCache::kRegistryRootKey,
              registry_cache_.module_key_name_.c_str(), KEY_ALL_ACCESS);
  ASSERT_TRUE(key_.Valid());

  const TestRegistryCache::StackId stack_id = 4567890;
  key_.WriteValue(base::Int64ToString16(recent_time.ToInternalValue()).c_str(),
                  &stack_id, sizeof(stack_id), REG_BINARY);

  // Called a 2nd time to force the loading of the new value from registry.
  registry_cache_.Init();

  EXPECT_TRUE(registry_cache_.DoesIdExist(stack_id));
}

TEST_F(RegistryCacheTest, AddOrUpdateStackId) {
  const TestRegistryCache::StackId stack_id_1 = 123456;
  const TestRegistryCache::StackId stack_id_2 = 3456236;

  registry_cache_.Init();
  key_.Create(TestRegistryCache::kRegistryRootKey,
              registry_cache_.module_key_name_.c_str(), KEY_ALL_ACCESS);
  ASSERT_TRUE(key_.Valid());
  ASSERT_EQ(0, key_.GetValueCount());
  registry_cache_.AddOrUpdateStackId(stack_id_1);
  TestRegistryCache::RegValueIter iter(
      TestRegistryCache::kRegistryRootKey,
      registry_cache_.module_key_name_.c_str());
  ASSERT_TRUE(iter.Valid());
  std::wstring original_name = iter.Name();
  ASSERT_EQ(1, key_.GetValueCount());
  registry_cache_.AddOrUpdateStackId(stack_id_2);
  ASSERT_EQ(2, key_.GetValueCount());
  registry_cache_.AddOrUpdateStackId(stack_id_1);
  ASSERT_EQ(2, key_.GetValueCount());

  // Validate that the original value corresponding to |stack_id_1| doesn't
  // exist anymore (meaning that it was updated), while validating that the two
  // existing values correspond to both stack_ids.
  TestRegistryCache::RegValueIter iter2(
      TestRegistryCache::kRegistryRootKey,
      registry_cache_.module_key_name_.c_str());
  ASSERT_TRUE(iter2.Valid());
  bool stack_id_1_exists = false;
  bool stack_id_2_exists = false;
  for (; iter2.Valid(); ++iter2) {
    ASSERT_EQ(sizeof(TestRegistryCache::StackId), iter2.ValueSize());
    ASSERT_NE(original_name, iter2.Name());
    const TestRegistryCache::StackId* ptr_value =
        reinterpret_cast<const TestRegistryCache::StackId*>(iter2.Value());
    if (*ptr_value == stack_id_1) {
      EXPECT_FALSE(stack_id_1_exists);
      stack_id_1_exists = true;
    } else if (*ptr_value == stack_id_2) {
      EXPECT_FALSE(stack_id_2_exists);
      stack_id_2_exists = true;
    }
  }
  EXPECT_TRUE(stack_id_1_exists);
  EXPECT_TRUE(stack_id_2_exists);
}

TEST_F(RegistryCacheTest, RemoveStackId) {
  // Called a 1st time to initialize |module_key_name_|.
  registry_cache_.Init();

  base::Time recent_time = RecentTime();
  key_.Create(TestRegistryCache::kRegistryRootKey,
    registry_cache_.module_key_name_.c_str(), KEY_ALL_ACCESS);
  ASSERT_TRUE(key_.Valid());

  const TestRegistryCache::StackId stack_id = 4567890;
  key_.WriteValue(base::Int64ToString16(recent_time.ToInternalValue()).c_str(),
    &stack_id, sizeof(stack_id), REG_BINARY);

  // Called a 2nd time to force the loading of the new value from registry.
  registry_cache_.Init();

  EXPECT_FALSE(registry_cache_.RemoveStackId(123456));
  EXPECT_TRUE(registry_cache_.RemoveStackId(stack_id));
  EXPECT_FALSE(registry_cache_.RemoveStackId(stack_id));
}

TEST_F(RegistryCacheTest, DeleteRegistryTree) {
  RegistryCache registry_cache2(L"AnotherRegistry");
  RegistryCache registry_cache3(L"YetAnotherName");
  registry_cache_.Init();
  registry_cache2.Init();
  registry_cache3.Init();

  key_.Create(TestRegistryCache::kRegistryRootKey,
              TestRegistryCache::kRegistryBaseKey,
              KEY_ALL_ACCESS);

  ASSERT_TRUE(key_.Valid());
  ASSERT_EQ(3U, GetKeyCount(TestRegistryCache::kRegistryRootKey,
                            TestRegistryCache::kRegistryBaseKey));
  RegistryCache::DeleteRegistryTree(L"AnotherRegistry");
  ASSERT_EQ(2U, GetKeyCount(TestRegistryCache::kRegistryRootKey,
                            TestRegistryCache::kRegistryBaseKey));

  TestRegistryCache::RegKeyIter iter(TestRegistryCache::kRegistryRootKey,
                                     TestRegistryCache::kRegistryBaseKey);
  ASSERT_TRUE(iter.Valid());
  EXPECT_EQ(L"YetAnotherName", std::wstring(iter.Name()));
  ++iter;
  ASSERT_TRUE(iter.Valid());
  EXPECT_EQ(L"TEST", std::wstring(iter.Name()));
}

}  // namespace asan
}  // namespace agent
