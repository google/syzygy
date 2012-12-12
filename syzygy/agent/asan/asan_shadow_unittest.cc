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

#include "syzygy/agent/asan/asan_shadow.h"

#include "base/rand_util.h"
#include "gtest/gtest.h"
#include "syzygy/common/align.h"

namespace agent {
namespace asan {

namespace {

// A derived class to expose protected members for unit-testing.
class TestShadow : public Shadow {
 public:
  using Shadow::Reset;
};

}  // namespace

TEST(ShadowTest, PoisonUnpoisonAccess) {
  // Reset the shadow memory.
  TestShadow::Reset();
  for (size_t i = 0; i < 100; ++i) {
    // Use a random 8-byte aligned end address.
    const size_t size = base::RandInt(1, 16384);
    const uint8* end_addr =
        reinterpret_cast<const uint8*>(base::RandInt(65536, 10*1024*1024) * 8);
    const uint8* start_addr = end_addr - size;

    for (size_t i = 0; i < size; ++i) {
      EXPECT_TRUE(Shadow::IsAccessible(start_addr + i));
    }

    Shadow::Poison(start_addr, size);
    for (size_t i = 0; i < size; ++i) {
      EXPECT_FALSE(Shadow::IsAccessible(start_addr + i));
    }
    EXPECT_TRUE(Shadow::IsAccessible(start_addr - 1));
    EXPECT_TRUE(Shadow::IsAccessible(start_addr + size));

    const size_t aligned_size = common::AlignUp(size, 8);
    const uint8* aligned_start_addr = end_addr - aligned_size;
    Shadow::Unpoison(aligned_start_addr, aligned_size);
    for (size_t i = 0; i < size; ++i) {
      EXPECT_TRUE(Shadow::IsAccessible(start_addr + i));
    }
  }
}

}  // namespace asan
}  // namespace agent
