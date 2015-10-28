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

#include "syzygy/refinery/symbols/simple_cache.h"

#include "base/bind.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "gtest/gtest.h"

namespace refinery {

namespace {

const wchar_t kCacheKeyOne[] = L"cache-key-one";

class SimpleEntry : public base::RefCounted<SimpleEntry> {
 public:
  explicit SimpleEntry(int value) : value_(value) {}

  bool operator==(const SimpleEntry& other) const {
    return value_ == other.value_;
  }

 private:
  friend class base::RefCounted<SimpleEntry>;
  ~SimpleEntry() {}

  int value_;

  DISALLOW_COPY_AND_ASSIGN(SimpleEntry);
};

class SimpleCacheLoadingTest : public testing::Test {
 public:
  void SetUp() override {
    Test::SetUp();
    load_cnt_ = 0;
  }

  bool FailToLoad(scoped_refptr<SimpleEntry>* entry) {
    CHECK(entry);
    load_cnt_++;
    return false;
  }

  bool Load(scoped_refptr<SimpleEntry>* entry) {
    CHECK(entry);
    *entry = new SimpleEntry(43);
    load_cnt_++;
    return true;
  }

  int load_cnt() { return load_cnt_; }

 private:
  int load_cnt_;
};

}  // namespace

TEST(SimpleCacheTest, BasicTest) {
  SimpleCache<SimpleEntry> cache;

  // Empty cache - retrieval fails.
  scoped_refptr<SimpleEntry> retrieved;
  ASSERT_FALSE(cache.Get(kCacheKeyOne, &retrieved));
  ASSERT_EQ(nullptr, retrieved.get());

  // Store and retrieve.
  scoped_refptr<SimpleEntry> entry_one = new SimpleEntry(42);
  cache.Store(kCacheKeyOne, entry_one);
  ASSERT_TRUE(cache.Get(kCacheKeyOne, &retrieved));
  ASSERT_EQ(*entry_one, *retrieved);
}

TEST_F(SimpleCacheLoadingTest, LoadingFailsTest) {
  SimpleCache<SimpleEntry> cache;
  ASSERT_EQ(0, load_cnt());

  // The entry is not in the cache.
  scoped_refptr<SimpleEntry> retrieved;
  ASSERT_FALSE(cache.Get(kCacheKeyOne, &retrieved));
  ASSERT_EQ(0, load_cnt());

  // GetOrLoad that fails to load.
  SimpleCache<SimpleEntry>::LoadingCallback load_cb =
      base::Bind(&SimpleCacheLoadingTest::FailToLoad, base::Unretained(this));
  cache.GetOrLoad(kCacheKeyOne, load_cb, &retrieved);
  ASSERT_EQ(nullptr, retrieved.get());
  ASSERT_EQ(1, load_cnt());

  // Second call uses the cached value.
  cache.GetOrLoad(kCacheKeyOne, load_cb, &retrieved);
  ASSERT_EQ(nullptr, retrieved.get());
  ASSERT_EQ(1, load_cnt());

  // There should now be a negative entry in the cache.
  ASSERT_TRUE(cache.Get(kCacheKeyOne, &retrieved));
  ASSERT_EQ(nullptr, retrieved.get());
  ASSERT_EQ(1, load_cnt());
}

TEST_F(SimpleCacheLoadingTest, LoadingSucceedsTest) {
  SimpleCache<SimpleEntry> cache;

  // The entry is not in the cache.
  scoped_refptr<SimpleEntry> retrieved;
  ASSERT_FALSE(cache.Get(kCacheKeyOne, &retrieved));
  ASSERT_EQ(0, load_cnt());

  // GetOrLoad that succeeds to load.
  SimpleCache<SimpleEntry>::LoadingCallback load_cb =
      base::Bind(&SimpleCacheLoadingTest::Load, base::Unretained(this));
  cache.GetOrLoad(kCacheKeyOne, load_cb, &retrieved);
  scoped_refptr<SimpleEntry> expected = new SimpleEntry(43);
  ASSERT_EQ(*expected, *retrieved);
  ASSERT_EQ(1, load_cnt());

  // Second call uses the cached value.
  cache.GetOrLoad(kCacheKeyOne, load_cb, &retrieved);
  ASSERT_EQ(*expected, *retrieved);
  ASSERT_EQ(1, load_cnt());

  // The entry should be in the cache.
  retrieved = nullptr;
  ASSERT_TRUE(cache.Get(kCacheKeyOne, &retrieved));
  ASSERT_EQ(*expected, *retrieved);
  ASSERT_EQ(1, load_cnt());
}


}  // namespace refinery
