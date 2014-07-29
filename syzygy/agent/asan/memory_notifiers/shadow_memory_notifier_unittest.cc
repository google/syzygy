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

#include "base/memory/scoped_ptr.h"
#include "gtest/gtest.h"
#include "syzygy/agent/asan/shadow.h"

namespace agent {
namespace asan {
namespace memory_notifiers {

TEST(ShadowMemoryNotifierTest, ShadowStateTransitionsWithNotification) {
  // A buffer to use. This is allocated dynamically to ensure it has 8 byte
  // alignment.
  const size_t kBufferSize = 1024;
  scoped_ptr<uint8> buffer(new uint8[kBufferSize]);

  // Unpoison the memory so that the test starts from clean data.
  Shadow::Unpoison(buffer.get(), kBufferSize);

  ShadowMemoryNotifier n;
  n.NotifyInternalUse(buffer.get(), kBufferSize);
  EXPECT_FALSE(Shadow::IsAccessible(buffer.get()));
  EXPECT_FALSE(Shadow::IsAccessible(buffer.get() + 10));
  EXPECT_TRUE(Shadow::IsAccessible(buffer.get() + kBufferSize));
  for (size_t i = 0; i < kBufferSize; ++i) {
    EXPECT_EQ(Shadow::kAsanMemoryByte,
              Shadow::GetShadowMarkerForAddress(buffer.get() + i));
  }

  n.NotifyFutureHeapUse(buffer.get(), kBufferSize);
  EXPECT_FALSE(Shadow::IsAccessible(buffer.get()));
  EXPECT_FALSE(Shadow::IsAccessible(buffer.get() + 10));
  EXPECT_TRUE(Shadow::IsAccessible(buffer.get() + kBufferSize));
  for (size_t i = 0; i < kBufferSize; ++i) {
    EXPECT_EQ(Shadow::kAsanReservedByte,
              Shadow::GetShadowMarkerForAddress(buffer.get() + i));
  }

  n.NotifyReturnedToOS(buffer.get(), kBufferSize);
  EXPECT_TRUE(Shadow::IsAccessible(buffer.get()));
  EXPECT_TRUE(Shadow::IsAccessible(buffer.get() + 10));
  EXPECT_TRUE(Shadow::IsAccessible(buffer.get() + kBufferSize));
  for (size_t i = 0; i < kBufferSize; ++i) {
    EXPECT_EQ(Shadow::kHeapAddressableByte,
              Shadow::GetShadowMarkerForAddress(buffer.get() + i));
  }

  // Clean up behind ourselves.
  Shadow::Unpoison(buffer.get(), kBufferSize);
}

}  // namespace memory_notifiers
}  // namespace asan
}  // namespace agent
