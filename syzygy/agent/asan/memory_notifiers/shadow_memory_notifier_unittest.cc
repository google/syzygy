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

#include "gtest/gtest.h"
#include "syzygy/agent/asan/shadow.h"

namespace agent {
namespace asan {
namespace memory_notifiers {

TEST(ShadowMemoryNotifierTest, ShadowStateTransitionsWithNotification) {
  // A buffer to use.
  char kBuffer[1024] = {};

  // Unpoison the memory so that the test starts from clean data.
  Shadow::Unpoison(kBuffer, sizeof(kBuffer));

  ShadowMemoryNotifier n;
  n.NotifyInternalUse(kBuffer, sizeof(kBuffer));
  EXPECT_FALSE(Shadow::IsAccessible(kBuffer));
  EXPECT_FALSE(Shadow::IsAccessible(kBuffer + 10));
  EXPECT_TRUE(Shadow::IsAccessible(kBuffer + sizeof(kBuffer)));
  for (size_t i = 0; i < sizeof(kBuffer); ++i) {
    EXPECT_EQ(Shadow::kAsanMemoryByte,
              Shadow::GetShadowMarkerForAddress(kBuffer + i));
  }

  n.NotifyFutureHeapUse(kBuffer, sizeof(kBuffer));
  EXPECT_FALSE(Shadow::IsAccessible(kBuffer));
  EXPECT_FALSE(Shadow::IsAccessible(kBuffer + 10));
  EXPECT_TRUE(Shadow::IsAccessible(kBuffer + sizeof(kBuffer)));
  for (size_t i = 0; i < sizeof(kBuffer); ++i) {
    EXPECT_EQ(Shadow::kAsanReservedByte,
              Shadow::GetShadowMarkerForAddress(kBuffer + i));
  }

  n.NotifyReturnedToOS(kBuffer, sizeof(kBuffer));
  EXPECT_TRUE(Shadow::IsAccessible(kBuffer));
  EXPECT_TRUE(Shadow::IsAccessible(kBuffer + 10));
  EXPECT_TRUE(Shadow::IsAccessible(kBuffer + sizeof(kBuffer)));
  for (size_t i = 0; i < sizeof(kBuffer); ++i) {
    EXPECT_EQ(Shadow::kHeapAddressableByte,
              Shadow::GetShadowMarkerForAddress(kBuffer + i));
  }

  // Clean up behind ourselves.
  Shadow::Unpoison(kBuffer, sizeof(kBuffer));
}

}  // namespace memory_notifiers
}  // namespace asan
}  // namespace agent
