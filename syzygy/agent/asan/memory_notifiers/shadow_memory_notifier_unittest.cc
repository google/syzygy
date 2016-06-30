// Copyright 2014 Google Inc. All Rights Reserved.
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

#include "syzygy/agent/asan/memory_notifiers/shadow_memory_notifier.h"

#include <memory>

#include "gtest/gtest.h"
#include "syzygy/agent/asan/shadow.h"

namespace agent {
namespace asan {
namespace memory_notifiers {

namespace {

class ShadowMemoryNotifierTest : public testing::Test {
 public:
  virtual void SetUp() override {
    shadow_.SetUp();
  }

  virtual void TearDown() override {
    shadow_.TearDown();
  }

  Shadow shadow_;
};

}  // namespace

TEST_F(ShadowMemoryNotifierTest, ShadowStateTransitionsWithNotification) {
  // A buffer to use. This is allocated dynamically to ensure it has 8 byte
  // alignment.
  const size_t kBufferSize = 1024;
  std::unique_ptr<uint8_t[]> buffer(new uint8_t[kBufferSize]);

  ShadowMemoryNotifier n(&shadow_);
  n.NotifyInternalUse(buffer.get(), kBufferSize);
  EXPECT_FALSE(shadow_.IsAccessible(buffer.get()));
  EXPECT_FALSE(shadow_.IsAccessible(buffer.get() + 10));
  EXPECT_TRUE(shadow_.IsAccessible(buffer.get() + kBufferSize));
  for (size_t i = 0; i < kBufferSize; ++i) {
    EXPECT_EQ(kAsanMemoryMarker,
              shadow_.GetShadowMarkerForAddress(buffer.get() + i));
  }

  n.NotifyFutureHeapUse(buffer.get(), kBufferSize);
  EXPECT_FALSE(shadow_.IsAccessible(buffer.get()));
  EXPECT_FALSE(shadow_.IsAccessible(buffer.get() + 10));
  EXPECT_TRUE(shadow_.IsAccessible(buffer.get() + kBufferSize));
  for (size_t i = 0; i < kBufferSize; ++i) {
    EXPECT_EQ(kAsanReservedMarker,
              shadow_.GetShadowMarkerForAddress(buffer.get() + i));
  }

  n.NotifyReturnedToOS(buffer.get(), kBufferSize);
  EXPECT_TRUE(shadow_.IsAccessible(buffer.get()));
  EXPECT_TRUE(shadow_.IsAccessible(buffer.get() + 10));
  EXPECT_TRUE(shadow_.IsAccessible(buffer.get() + kBufferSize));
  for (size_t i = 0; i < kBufferSize; ++i) {
    EXPECT_EQ(kHeapAddressableMarker,
              shadow_.GetShadowMarkerForAddress(buffer.get() + i));
  }

  EXPECT_TRUE(shadow_.IsClean());
}

}  // namespace memory_notifiers
}  // namespace asan
}  // namespace agent
