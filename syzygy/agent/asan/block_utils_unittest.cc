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

#include "syzygy/agent/asan/block_utils.h"

#include "gtest/gtest.h"
#include "syzygy/agent/asan/asan_logger.h"
#include "syzygy/agent/asan/unittest_util.h"

namespace agent {
namespace asan {

namespace {

typedef testing::TestWithAsanRuntime BlockUtilTest;

}  // namespace

TEST_F(BlockUtilTest, IsBlockCorruptInvalidMagicNumber) {
  const size_t kAllocSize = 100;
  testing::FakeAsanBlock fake_block(kShadowRatioLog, runtime_.stack_cache());
  EXPECT_TRUE(fake_block.InitializeBlock(kAllocSize));

  fake_block.block_info.header->magic = ~kBlockHeaderMagic;
  EXPECT_TRUE(IsBlockCorrupt(fake_block.block_info.block, NULL));
  fake_block.block_info.header->magic = kBlockHeaderMagic;
  EXPECT_FALSE(IsBlockCorrupt(fake_block.block_info.block, NULL));
}

TEST_F(BlockUtilTest, IsBlockCorruptInvalidChecksum) {
  const size_t kAllocSize = 100;
  static const size_t kChecksumRepeatCount = 10;

  // This can fail because of a checksum collision. However, we run it a
  // handful of times to keep the chances as small as possible.
  for (size_t i = 0; i < kChecksumRepeatCount; ++i) {
    testing::FakeAsanBlock fake_block(kShadowRatioLog, runtime_.stack_cache());
    EXPECT_TRUE(fake_block.InitializeBlock(kAllocSize));
    EXPECT_TRUE(fake_block.MarkBlockAsQuarantined());

    // Change some of the block content and verify that the block is now being
    // seen as corrupt.
    size_t original_checksum = fake_block.block_info.header->checksum;
    uint8 original_value = fake_block.block_info.body[0];
    fake_block.block_info.body[0]++;

    // Try again for all but the last attempt if this appears to have failed.
    if (!IsBlockCorrupt(fake_block.block_info.body, NULL) &&
        i + 1 < kChecksumRepeatCount) {
      continue;
    }

    ASSERT_TRUE(IsBlockCorrupt(fake_block.block_info.body, NULL));
    fake_block.block_info.body[0] = original_value;
    ASSERT_FALSE(IsBlockCorrupt(fake_block.block_info.body, NULL));
    break;
  }
}

}  // namespace asan
}  // namespace agent
