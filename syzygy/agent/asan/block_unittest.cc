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

#include "syzygy/agent/asan/block.h"

#include <memory>
#include <set>
#include <vector>

#include "windows.h"

#include "gtest/gtest.h"
#include "syzygy/agent/asan/page_protection_helpers.h"
#include "syzygy/agent/asan/runtime.h"
#include "syzygy/agent/asan/unittest_util.h"

namespace agent {
namespace asan {

namespace {

using testing::_;

BlockLayout BuildBlockLayout(uint32_t block_alignment,
                             uint32_t block_size,
                             uint32_t header_size,
                             uint32_t header_padding_size,
                             uint32_t body_size,
                             uint32_t trailer_padding_size,
                             uint32_t trailer_size) {
  BlockLayout layout = { block_alignment, block_size, header_size,
      header_padding_size, body_size, trailer_padding_size, trailer_size };
  return layout;
}

// Checks that the given block is valid, and initialized as expected.
void IsValidBlockImpl(const BlockInfo& block, bool just_initialized) {
  EXPECT_EQ(0u, block.block_size % kShadowRatio);

  // Validate the layout of the block.
  EXPECT_TRUE(block.header != nullptr);
  EXPECT_EQ(0u, block.block_size % kShadowRatio);
  EXPECT_EQ(0u, block.header_padding_size % kShadowRatio);
  EXPECT_EQ(block.RawHeader() + sizeof(BlockHeader),
            block.RawHeaderPadding());
  EXPECT_EQ(block.RawHeaderPadding() + block.header_padding_size,
            block.RawBody());
  EXPECT_EQ(block.RawBody() + block.body_size,
            block.RawTrailerPadding());
  EXPECT_EQ(block.RawTrailerPadding() + block.trailer_padding_size,
            block.RawTrailer());
  EXPECT_EQ(block.RawHeader() + block.block_size,
            block.RawTrailer() + sizeof(BlockTrailer));

  // Validate the actual contents of the various parts of the block.

  // Check the header.
  EXPECT_EQ(kBlockHeaderMagic, block.header->magic);
  EXPECT_LT(0u, block.header->body_size);
  EXPECT_EQ(block.header->body_size, block.body_size);
  if (just_initialized) {
    EXPECT_EQ(0u, block.header->checksum);
    EXPECT_EQ(NULL, block.header->alloc_stack);
    EXPECT_EQ(NULL, block.header->free_stack);
    EXPECT_EQ(ALLOCATED_BLOCK, block.header->state);
  }

  // Check the header padding.
  if (block.header->has_header_padding) {
    EXPECT_LE(kShadowRatio, block.header_padding_size);
    EXPECT_EQ(block.header_padding_size,
              *reinterpret_cast<const uint32_t*>(block.header_padding));
    EXPECT_EQ(block.header_padding_size,
              *reinterpret_cast<const uint32_t*>(block.RawHeaderPadding() +
                                                 block.header_padding_size -
                                                 sizeof(uint32_t)));
    for (uint32_t i = sizeof(uint32_t);
         i < block.header_padding_size - sizeof(uint32_t); ++i) {
      EXPECT_EQ(kBlockHeaderPaddingByte, block.RawHeaderPadding(i));
    }
  }

  // Check the trailer padding.
  uint32_t start_of_trailer_iteration = 0;
  if (block.header->has_excess_trailer_padding) {
    start_of_trailer_iteration = 4;
    EXPECT_EQ(block.trailer_padding_size,
              *reinterpret_cast<const uint32_t*>(block.trailer_padding));
  }
  for (uint32_t i = start_of_trailer_iteration; i < block.trailer_padding_size;
       ++i) {
    EXPECT_EQ(kBlockTrailerPaddingByte, block.RawTrailerPadding(i));
  }

  // Check the trailer.
  EXPECT_NE(0u, block.trailer->alloc_tid);
  EXPECT_GE(::GetTickCount(), block.trailer->alloc_ticks);
  if (just_initialized) {
    EXPECT_EQ(0u, block.trailer->free_tid);
    EXPECT_EQ(0u, block.trailer->free_ticks);
  }
}

void IsValidInitializedBlock(const BlockInfo& block) {
  IsValidBlockImpl(block, true);
}

void IsValidBlock(const BlockInfo& block) {
  IsValidBlockImpl(block, false);
}

class BlockTest : public testing::OnExceptionCallbackTest {
 public:
  using Super = testing::OnExceptionCallbackTest;

  void SetUp() override {
    Super::SetUp();
    shadow_.SetUp();
  }

  void TearDown() override {
    shadow_.TearDown();
    Super::TearDown();
  }

  Shadow shadow_;
};

}  // namespace

bool operator==(const BlockLayout& bl1, const BlockLayout& bl2) {
  return ::memcmp(&bl1, &bl2, sizeof(BlockLayout)) == 0;
}

bool operator==(const BlockInfo& bi1, const BlockInfo& bi2) {
  return ::memcmp(&bi1, &bi2, sizeof(BlockInfo)) == 0;
}

TEST_F(BlockTest, BlockPlanLayout) {
  BlockLayout layout = {};

#ifndef _WIN64
  // Zero sized allocations should work fine.
  EXPECT_TRUE(BlockPlanLayout(8, 8, 0, 0, 0, &layout));
  EXPECT_EQ(BuildBlockLayout(8, 40, 16, 0, 0, 4, 20), layout);

  EXPECT_TRUE(BlockPlanLayout(8, 8, 60, 32, 32, &layout));
  EXPECT_EQ(BuildBlockLayout(8, 128, 16, 16, 60, 16, 20), layout);

  EXPECT_TRUE(BlockPlanLayout(8, 8, 60, 0, 0, &layout));
  EXPECT_EQ(BuildBlockLayout(8, 96, 16, 0, 60, 0, 20), layout);

  EXPECT_TRUE(BlockPlanLayout(8, 8, 64, 0, 0, &layout));
  EXPECT_EQ(BuildBlockLayout(8, 104, 16, 0, 64, 4, 20), layout);

  EXPECT_TRUE(BlockPlanLayout(8, 8, 61, 0, 0, &layout));
  EXPECT_EQ(BuildBlockLayout(8, 104, 16, 0, 61, 7, 20), layout);

  // Plan a layout that would use guard pages.
  EXPECT_TRUE(BlockPlanLayout(4096, 8, 100, 4096, 4096, &layout));
  EXPECT_EQ(BuildBlockLayout(4096, 3 * 4096, 16, 8072, 100, 4080, 20), layout);
#else
  // Zero sized allocations should work fine.
  EXPECT_TRUE(BlockPlanLayout(8, 8, 0, 0, 0, &layout));
  EXPECT_EQ(BuildBlockLayout(8, 56, 24, 0, 0, 4, 28), layout);

  EXPECT_TRUE(BlockPlanLayout(8, 8, 60, 32, 32, &layout));
  EXPECT_EQ(BuildBlockLayout(8, 128, 24, 8, 60, 8, 28), layout);

  EXPECT_TRUE(BlockPlanLayout(8, 8, 60, 0, 0, &layout));
  EXPECT_EQ(BuildBlockLayout(8, 112, 24, 0, 60, 0, 28), layout);

  EXPECT_TRUE(BlockPlanLayout(8, 8, 64, 0, 0, &layout));
  EXPECT_EQ(BuildBlockLayout(8, 120, 24, 0, 64, 4, 28), layout);

  EXPECT_TRUE(BlockPlanLayout(8, 8, 61, 0, 0, &layout));
  EXPECT_EQ(BuildBlockLayout(8, 120, 24, 0, 61, 7, 28), layout);

  // Plan a layout that would use guard pages.
  EXPECT_TRUE(BlockPlanLayout(4096, 8, 100, 4096, 4096, &layout));
  EXPECT_EQ(BuildBlockLayout(4096, 3 * 4096, 24, 8064, 100, 4072, 28), layout);
#endif

  EXPECT_TRUE(BlockPlanLayout(
      8, 8, static_cast<uint32_t>(1 << kBlockBodySizeBits) - 1, 0, 0, &layout));

  // Plan some layouts with an invalid size, this should fail.
  EXPECT_FALSE(BlockPlanLayout(
      8, 8, static_cast<uint32_t>(1 << kBlockBodySizeBits), 0, 0, &layout));
  EXPECT_FALSE(BlockPlanLayout(8, 8, 0xffffffff, 0, 0, &layout));
}

TEST_F(BlockTest, EndToEnd) {
  BlockLayout layout = {};
  BlockInfo block_info = {};

  EXPECT_TRUE(BlockPlanLayout(8, 8, 4, 0, 0, &layout));
  std::vector<uint8_t> block_data(layout.block_size);
  BlockInitialize(layout, block_data.data(), &block_info);
  EXPECT_NO_FATAL_FAILURE(IsValidInitializedBlock(block_info));
  block_data.clear();

  EXPECT_TRUE(BlockPlanLayout(8, 8, 61, 0, 0, &layout));
  block_data.resize(layout.block_size);
  BlockInitialize(layout, block_data.data(), &block_info);
  EXPECT_NO_FATAL_FAILURE(IsValidInitializedBlock(block_info));
  block_data.clear();

  EXPECT_TRUE(BlockPlanLayout(8, 8, 60, 32, 32, &layout));
  block_data.resize(layout.block_size);
  BlockInitialize(layout, block_data.data(), &block_info);
  EXPECT_NO_FATAL_FAILURE(IsValidInitializedBlock(block_info));
  block_data.clear();

  // Do an allocation that uses entire pages.
  EXPECT_TRUE(BlockPlanLayout(4096, 8, 100, 4096, 4096, &layout));
  void* data = ::VirtualAlloc(NULL, layout.block_size, MEM_COMMIT,
                              PAGE_READWRITE);
  ::memset(data, 0, layout.block_size);
  BlockInitialize(layout, data, &block_info);
  EXPECT_NO_FATAL_FAILURE(IsValidInitializedBlock(block_info));
  ASSERT_EQ(TRUE, ::VirtualFree(data, 0, MEM_RELEASE));
}

TEST_F(BlockTest, GetHeaderFromBody) {
  // Plan two layouts, one with header padding and another without.
  BlockLayout layout1 = {};
  BlockLayout layout2 = {};
  EXPECT_TRUE(BlockPlanLayout(kShadowRatio, kShadowRatio, 10, 0, 0, &layout1));
  EXPECT_TRUE(BlockPlanLayout(kShadowRatio, kShadowRatio, 10, 32, 0, &layout2));

  std::unique_ptr<uint8_t[]> data(new uint8_t[layout2.block_size]);
  ::memset(data.get(), 0, layout2.block_size);

  // First try navigating a block without header padding.
  BlockInfo info = {};
  BlockInitialize(layout1, data.get(), &info);
  // This should succeed as expected.
  EXPECT_EQ(info.header, BlockGetHeaderFromBody(info.body));
  // This fails because of invalid alignment.
  EXPECT_TRUE(BlockGetHeaderFromBody(
      reinterpret_cast<BlockBody*>(info.RawBody() + 1)) == nullptr);
  // This fails because the pointer is not at the beginning of the
  // body.
  EXPECT_TRUE(BlockGetHeaderFromBody(
      reinterpret_cast<BlockBody*>(info.RawBody() + kShadowRatio)) == nullptr);
  // This fails because of invalid header magic.
  ++info.header->magic;
  EXPECT_TRUE(BlockGetHeaderFromBody(info.body) == nullptr);
  // This fails because the header indicates there's padding.
  --info.header->magic;
  info.header->has_header_padding = 1;
  EXPECT_TRUE(BlockGetHeaderFromBody(info.body) == nullptr);

  // Now navigate a block with header padding.
  BlockInitialize(layout2, data.get(), &info);
  // This should succeed as expected.
  EXPECT_EQ(info.header, BlockGetHeaderFromBody(info.body));
  // This fails because of invalid alignment.
  EXPECT_TRUE(BlockGetHeaderFromBody(
      reinterpret_cast<BlockBody*>(info.RawBody() + 1)) == nullptr);
  // This fails because the pointer is not at the beginning of the
  // body.
  EXPECT_TRUE(BlockGetHeaderFromBody(
      reinterpret_cast<BlockBody*>(info.RawBody() + kShadowRatio)) == nullptr);
  // This fails because of invalid header magic.
  ++info.header->magic;
  EXPECT_TRUE(BlockGetHeaderFromBody(info.body) == nullptr);
  // This fails because the header indicates there's no padding.
  --info.header->magic;
  info.header->has_header_padding = 0;
  EXPECT_TRUE(BlockGetHeaderFromBody(info.body) == nullptr);
  // This fails because the padding length is invalid.
  info.header->has_header_padding = 1;
  uint32_t* head = reinterpret_cast<uint32_t*>(info.header_padding);
  uint32_t* tail = head + (info.header_padding_size / sizeof(uint32_t)) - 1;
  ++(*tail);
  EXPECT_TRUE(BlockGetHeaderFromBody(info.body) == nullptr);
  // This fails because the padding lengths don't agree.
  --(*tail);
  ++(*head);
  EXPECT_TRUE(BlockGetHeaderFromBody(info.body) == nullptr);
}

TEST_F(BlockTest, GetHeaderFromBodyProtectedMemory) {
  BlockLayout layout = {};
  EXPECT_TRUE(BlockPlanLayout(4096, 4096, 4096, 4096, 4096, &layout));
  void* alloc = ::VirtualAlloc(NULL, layout.block_size, MEM_COMMIT,
                               PAGE_READWRITE);
  ASSERT_TRUE(alloc != NULL);
  BlockInfo block_info = {};
  BlockInitialize(layout, alloc, &block_info);

  BlockProtectRedzones(block_info, &shadow_);
  EXPECT_CALL(*this, OnExceptionCallback(_));
  EXPECT_TRUE(BlockGetHeaderFromBody(block_info.body) == NULL);
  testing::Mock::VerifyAndClearExpectations(this);
  BlockProtectNone(block_info, &shadow_);

  ASSERT_EQ(TRUE, ::VirtualFree(alloc, 0, MEM_RELEASE));
}

TEST_F(BlockTest, ConvertBlockInfo) {
  BlockLayout layout = {};
  EXPECT_TRUE(BlockPlanLayout(kShadowRatio, kShadowRatio, 10, 0, 0, &layout));

  std::unique_ptr<uint8_t[]> data(new uint8_t[layout.block_size]);
  ::memset(data.get(), 0, layout.block_size);

  BlockInfo expanded = {};
  BlockInitialize(layout, data.get(), &expanded);

  CompactBlockInfo compact = {};
  ConvertBlockInfo(expanded, &compact);
  EXPECT_EQ(layout.block_size, compact.block_size);
  EXPECT_EQ(layout.header_size + layout.header_padding_size,
            compact.header_size);
  EXPECT_EQ(layout.trailer_size + layout.trailer_padding_size,
            compact.trailer_size);
  EXPECT_FALSE(compact.is_nested);

  BlockInfo expanded2 = {};
  ConvertBlockInfo(compact, &expanded2);
  EXPECT_EQ(0, ::memcmp(&expanded, &expanded2, sizeof(expanded)));
}

TEST_F(BlockTest, BlockInfoFromMemory) {
  // Plan two layouts, one with header padding and another without.
  BlockLayout layout1 = {};
  BlockLayout layout2 = {};
  EXPECT_TRUE(BlockPlanLayout(kShadowRatio, kShadowRatio, 10, 0, 0, &layout1));
  EXPECT_TRUE(BlockPlanLayout(kShadowRatio, kShadowRatio, 10, 32, 0, &layout2));

  std::unique_ptr<uint8_t[]> data(new uint8_t[layout2.block_size]);
  ::memset(data.get(), 0, layout2.block_size);

  // First recover a block without header padding.
  BlockInfo info = {};
  BlockInitialize(layout1, data.get(), &info);
  BlockInfo info_recovered = {};
  EXPECT_TRUE(BlockInfoFromMemory(info.header, &info_recovered));
  EXPECT_EQ(info, info_recovered);
  // Failed because its not aligned.
  EXPECT_FALSE(BlockInfoFromMemory(
      reinterpret_cast<BlockHeader*>(info.RawHeader() + 1),
      &info_recovered));
  // Failed because the magic is invalid.
  ++info.header->magic;
  EXPECT_FALSE(BlockInfoFromMemory(info.header, &info_recovered));
  --info.header->magic;
  // This fails because the header indicates there's padding yet there is
  // none.
  info.header->has_header_padding = 1;
  EXPECT_FALSE(BlockInfoFromMemory(info.header, &info_recovered));

  // Now recover a block with header padding.
  BlockInitialize(layout2, data.get(), &info);
  EXPECT_TRUE(BlockInfoFromMemory(info.header, &info_recovered));
  EXPECT_EQ(info, info_recovered);
  // Failed because the magic is invalid.
  ++info.header->magic;
  EXPECT_FALSE(BlockInfoFromMemory(info.header, &info_recovered));
  --info.header->magic;
  // Failed because the header padding lengths don't match.
  uint32_t* head = reinterpret_cast<uint32_t*>(info.header_padding);
  uint32_t* tail = head + (info.header_padding_size / sizeof(uint32_t)) - 1;
  ++(*tail);
  EXPECT_FALSE(BlockInfoFromMemory(info.header, &info_recovered));
  --(*tail);

  // Finally ensure that we can recover information about blocks of various
  // sizes.
  const size_t kAllocSize = 3 * GetPageSize();
  void* alloc = ::VirtualAlloc(NULL, kAllocSize, MEM_COMMIT, PAGE_READWRITE);
  for (uint32_t block_size = 0; block_size < kShadowRatio * 2; ++block_size) {
    BlockLayout layout = {};
    EXPECT_TRUE(BlockPlanLayout(kShadowRatio, kShadowRatio, block_size, 0, 0,
                                &layout));
    ASSERT_LE(layout.block_size, kAllocSize);
    BlockInitialize(layout, alloc, &info);
    EXPECT_TRUE(BlockInfoFromMemory(info.header, &info_recovered));
    EXPECT_EQ(info.body_size, info_recovered.body_size);
    EXPECT_EQ(info, info_recovered) << block_size;

    EXPECT_TRUE(BlockPlanLayout(4096, 4096, block_size, 4096, 4096,
                                &layout));
    ASSERT_LE(layout.block_size, kAllocSize);
    BlockInitialize(layout, alloc, &info);
    EXPECT_TRUE(BlockInfoFromMemory(info.header, &info_recovered));
    EXPECT_EQ(info.body_size, info_recovered.body_size);
    EXPECT_EQ(info, info_recovered);
  }
  ::VirtualFree(alloc, 0, MEM_RELEASE);
}

TEST_F(BlockTest, BlockInfoFromMemoryInvalidPadding) {
  BlockLayout layout = {};
  EXPECT_TRUE(BlockPlanLayout(kShadowRatio, kShadowRatio, 10,
      4 * sizeof(BlockHeader), 0, &layout));

  std::unique_ptr<uint8_t[]> data(new uint8_t[layout.block_size]);
  ::memset(data.get(), 0, layout.block_size);

  BlockInfo info = {};
  BlockInitialize(layout, data.get(), &info);
  EXPECT_EQ(1, info.header->has_header_padding);
  BlockInfo info_recovered = {};
  EXPECT_TRUE(BlockInfoFromMemory(info.header, &info_recovered));
  EXPECT_EQ(info, info_recovered);

  // Invalidates the padding size and make sure that we can't retrieve the block
  // information.
  size_t* padding_size = reinterpret_cast<size_t*>(info.header + 1);
  EXPECT_GE(*padding_size, 2 * sizeof(uint32_t));
  for (*padding_size = 0; *padding_size < 2 * sizeof(uint32_t);
       ++(*padding_size)) {
    EXPECT_FALSE(BlockInfoFromMemory(info.header, &info_recovered));
  }
}

TEST_F(BlockTest, BlockInfoFromMemoryProtectedMemory) {
  BlockLayout layout = {};
  EXPECT_TRUE(BlockPlanLayout(4096, 4096, 4096, 4096, 4096, &layout));
  void* alloc = ::VirtualAlloc(NULL, layout.block_size, MEM_COMMIT,
                               PAGE_READWRITE);
  ASSERT_TRUE(alloc != NULL);
  BlockInfo block_info = {};
  BlockInitialize(layout, alloc, &block_info);

  BlockProtectRedzones(block_info, &shadow_);
  BlockInfo recovered_info = {};
  EXPECT_CALL(*this, OnExceptionCallback(_));
  EXPECT_FALSE(BlockInfoFromMemory(block_info.header, &recovered_info));
  testing::Mock::VerifyAndClearExpectations(this);
  BlockProtectNone(block_info, &shadow_);

  ASSERT_EQ(TRUE, ::VirtualFree(alloc, 0, MEM_RELEASE));
}

TEST_F(BlockTest, ChecksumWorksForAllStates) {
  BlockLayout layout = {};
  EXPECT_TRUE(BlockPlanLayout(kShadowRatio, kShadowRatio, 10, 0, 0, &layout));
  std::unique_ptr<uint8_t[]> data(new uint8_t[layout.block_size]);
  ::memset(data.get(), 0, layout.block_size);
  BlockInfo info = {};
  BlockInitialize(layout, data.get(), &info);
  while (true) {
    BlockCalculateChecksum(info);
    ++info.header->state;
    if (info.header->state == 0)
      break;
  }
}

namespace {

// Given two arrays of data, compares them byte-by-byte to find the first
// byte with altered data. Within that byte determines the mask of bits that
// have been altered. Returns the results via |offset| and |mask|.
void FindModifiedBits(size_t length,
                      const uint8_t* buffer1,
                      const uint8_t* buffer2,
                      size_t* offset,
                      uint8_t* mask) {
  ASSERT_TRUE(buffer1 != NULL);
  ASSERT_TRUE(buffer2 != NULL);
  ASSERT_TRUE(offset != NULL);
  ASSERT_TRUE(mask != NULL);

  for (size_t i = 0; i < length; ++i) {
    if (buffer1[i] != buffer2[i]) {
      *offset = i;
      *mask = buffer1[i] ^ buffer2[i];
      return;
    }
  }

  *offset = 0;
  *mask = 0;
}

// This is initialized by TestChecksumDetectsTampering, but referred to by
// ChecksumDetectsTamperingWithMask as well, hence not in a function.
size_t state_offset = SIZE_MAX;
uint8_t state_mask = 0;

bool ChecksumDetectsTamperingWithMask(const BlockInfo& block_info,
                                      void* address_to_modify,
                                      uint8_t mask_to_modify) {
  uint8_t* byte_to_modify = reinterpret_cast<uint8_t*>(address_to_modify);

  // Remember the original contents.
  uint8_t original_value = *byte_to_modify;
  uint8_t original_bits = original_value & ~mask_to_modify;

  // Since the checksum can collide we check a handful of times to build up
  // some confidence. Since we sometimes expect this to return false the number
  // of iterations needs to be kept reasonably low to keep the unittest fast.
  bool detected = false;
  BlockSetChecksum(block_info);
  uint32_t checksum = block_info.header->checksum;
  for (size_t i = 0; i < 4; ++i) {
    // Modify the value, altering only bits in |mask_to_modify|.
    while (true) {
      ++(*byte_to_modify);
      if (((*byte_to_modify) & ~mask_to_modify) == original_bits)
        break;
    }
    BlockSetChecksum(block_info);
    if (block_info.header->checksum != checksum) {
      // Success, the checksum detected the change!
      // Restore the original checksum so the block analysis can continue.
      block_info.header->checksum = checksum;
      detected = true;
      break;
    }
  }

  // Run a detailed analysis on the block. We expect the results of this to
  // agree with where the block was modified.
  BlockAnalysisResult result = {};
  BlockAnalyze(static_cast<BlockState>(block_info.header->state), block_info,
               &result);
  if (address_to_modify < block_info.body) {
    EXPECT_EQ(kDataIsCorrupt, result.block_state);
    // If the thing being modified is the block state, then this is so
    // localized that the analysis will sometimes mess up. Seeing this in
    // the wild is quite unlikely.
    // TODO(chrisha): If we ever have individual checksums for the header,
    //     the body and the trailer, then revisit this.
    if (address_to_modify != block_info.RawHeader() + state_offset ||
        mask_to_modify != state_mask) {
      EXPECT_EQ(kDataIsCorrupt, result.header_state);
      EXPECT_EQ(kDataStateUnknown, result.body_state);
      EXPECT_EQ(kDataIsClean, result.trailer_state);
    }
  } else if (address_to_modify >= block_info.trailer_padding) {
    EXPECT_EQ(kDataIsCorrupt, result.block_state);
    EXPECT_EQ(kDataIsClean, result.header_state);
    EXPECT_EQ(kDataStateUnknown, result.body_state);
    EXPECT_EQ(kDataIsCorrupt, result.trailer_state);
  } else {
    // The byte being modified is in the body. Only expect to find
    // tampering if the block is quarantined or freed.
    if (block_info.header->state != ALLOCATED_BLOCK) {
      EXPECT_EQ(kDataIsCorrupt, result.block_state);
      EXPECT_EQ(kDataIsClean, result.header_state);
      EXPECT_EQ(kDataIsCorrupt, result.body_state);
      EXPECT_EQ(kDataIsClean, result.trailer_state);
    } else {
      EXPECT_EQ(kDataIsClean, result.block_state);
      EXPECT_EQ(kDataIsClean, result.header_state);
      EXPECT_EQ(kDataIsClean, result.body_state);
      EXPECT_EQ(kDataIsClean, result.trailer_state);
    }
  }

  // Restore the original value before returning.
  *byte_to_modify = original_value;
  return detected;
}

bool ChecksumDetectsTampering(const BlockInfo& block_info,
                              void* address_to_modify) {
  if (!ChecksumDetectsTamperingWithMask(block_info, address_to_modify, 0xFF))
    return false;
  return true;
}

void TestChecksumDetectsTampering(const BlockInfo& block_info) {
  uint32_t checksum = BlockCalculateChecksum(block_info);
  block_info.header->checksum = checksum;
  EXPECT_TRUE(BlockChecksumIsValid(block_info));
  ++block_info.header->checksum;
  EXPECT_FALSE(BlockChecksumIsValid(block_info));
  BlockSetChecksum(block_info);
  EXPECT_EQ(checksum, block_info.header->checksum);

  // A detailed block analysis should find nothing awry.
  BlockAnalysisResult result = {};
  BlockAnalyze(static_cast<BlockState>(block_info.header->state), block_info,
               &result);
  EXPECT_EQ(kDataIsClean, result.block_state);
  EXPECT_EQ(kDataIsClean, result.header_state);
  EXPECT_EQ(kDataIsClean, result.body_state);
  EXPECT_EQ(kDataIsClean, result.trailer_state);

  // Get the offset of the byte and the mask of the bits containing the
  // block state. This is resilient to changes in the BlockHeader layout.
  if (state_offset == -1) {
    BlockHeader header1 = {};
    BlockHeader header2 = {};
    header2.state = ~header2.state;
    FindModifiedBits(
        sizeof(BlockHeader), reinterpret_cast<const uint8_t*>(&header1),
        reinterpret_cast<const uint8_t*>(&header2), &state_offset, &state_mask);
  }

  // Header bytes should be tamper proof.
  EXPECT_TRUE(ChecksumDetectsTampering(block_info, block_info.header));
  EXPECT_TRUE(ChecksumDetectsTampering(block_info,
                                       &block_info.header->alloc_stack));
  EXPECT_TRUE(ChecksumDetectsTamperingWithMask(
      block_info,
      block_info.RawHeader() + state_offset,
      state_mask));

  // Header padding should be tamper proof.
  if (block_info.header_padding_size > 0) {
    EXPECT_TRUE(ChecksumDetectsTampering(block_info,
        block_info.RawHeaderPadding() + block_info.header_padding_size / 2));
  }

  // Trailer padding should be tamper proof.
  if (block_info.trailer_padding_size > 0) {
    EXPECT_TRUE(ChecksumDetectsTampering(block_info,
        block_info.RawTrailerPadding() + block_info.trailer_padding_size / 2));
  }

  // Trailer bytes should be tamper proof.
  EXPECT_TRUE(ChecksumDetectsTampering(block_info, block_info.trailer));
  EXPECT_TRUE(ChecksumDetectsTampering(block_info,
                                       &block_info.trailer->heap_id));

  // Expect the checksum to detect body tampering in quarantined and freed
  // states, but not in the allocated state or flooded states.
  bool expected = block_info.header->state == QUARANTINED_BLOCK ||
      block_info.header->state == FREED_BLOCK;
  EXPECT_EQ(expected, ChecksumDetectsTampering(block_info, block_info.body));
  EXPECT_EQ(expected, ChecksumDetectsTampering(block_info,
      block_info.RawBody() + block_info.body_size / 2));
  EXPECT_EQ(expected, ChecksumDetectsTampering(block_info,
      block_info.RawBody() + block_info.body_size - 1));
}

}  // namespace

TEST_F(BlockTest, ChecksumDetectsTampering) {
  // This test requires a runtime because it makes use of BlockAnalyze.
  // Initialize it with valid values.
  AsanRuntime runtime;
  ASSERT_NO_FATAL_FAILURE(runtime.SetUp(L""));
  HeapManagerInterface::HeapId valid_heap_id = runtime.GetProcessHeap();
  runtime.AddThreadId(::GetCurrentThreadId());
  common::StackCapture capture;
  capture.InitFromStack();
  const common::StackCapture* valid_stack =
      runtime.stack_cache()->SaveStackTrace(capture);

  uint32_t kSizes[] = { 1, 4, 7, 16, 23, 32, 117, 1000, 4096 };

  // Doing a single allocation makes this test a bit faster.
  size_t kAllocSize = 4 * 4096;
  void* alloc = ::VirtualAlloc(NULL, kAllocSize, MEM_COMMIT, PAGE_READWRITE);
  ASSERT_TRUE(alloc != NULL);

  // We test 9 different sizes, 9 different chunk sizes, 1 to 9 different
  // alignments, and 2 different redzone sizes. This is 810 different
  // combinations. We test each of these block allocations in all 4 possible
  // states. The probe itself tests the block at 7 to 9 different points, and
  // the tests require multiple iterations. Be careful playing with these
  // constants or the unittest time can easily spiral out of control! This
  // currently requires less than half a second, and is strictly CPU bound.
  for (uint32_t chunk_size = kShadowRatio; chunk_size <= GetPageSize();
       chunk_size *= 2) {
    for (uint32_t align = kShadowRatio; align <= chunk_size; align *= 2) {
      for (uint32_t redzone = 0; redzone <= chunk_size; redzone += chunk_size) {
        for (size_t i = 0; i < arraysize(kSizes); ++i) {
          BlockLayout layout = {};
          EXPECT_TRUE(BlockPlanLayout(chunk_size, align, kSizes[i], redzone,
                                      redzone, &layout));
          ASSERT_GT(kAllocSize, layout.block_size);

          BlockInfo block_info = {};
          BlockInitialize(layout, alloc, &block_info);
          block_info.header->alloc_stack = valid_stack;
          block_info.trailer->heap_id = valid_heap_id;

          // Test that the checksum detects tampering as expected in each block
          // state.
          block_info.header->state = ALLOCATED_BLOCK;
          ASSERT_NO_FATAL_FAILURE(TestChecksumDetectsTampering(block_info));

          block_info.header->state = QUARANTINED_BLOCK;
          block_info.header->free_stack = valid_stack;
          block_info.trailer->free_tid = ::GetCurrentThreadId();
          block_info.trailer->free_ticks = ::GetTickCount();
          ASSERT_NO_FATAL_FAILURE(TestChecksumDetectsTampering(block_info));

          block_info.header->state = QUARANTINED_FLOODED_BLOCK;
          ::memset(block_info.body, kBlockFloodFillByte, block_info.body_size);
          ASSERT_NO_FATAL_FAILURE(TestChecksumDetectsTampering(block_info));

          block_info.header->state = FREED_BLOCK;
          ASSERT_NO_FATAL_FAILURE(TestChecksumDetectsTampering(block_info));
        }  // kSizes[i]
      }  // redzone
    }  // align
  }  // chunk_size

  ASSERT_EQ(TRUE, ::VirtualFree(alloc, 0, MEM_RELEASE));
  ASSERT_NO_FATAL_FAILURE(runtime.TearDown());
}

TEST_F(BlockTest, BlockBodyIsFloodFilled) {
  static char dummy_body[3] = { 0x00, 0x00, 0x00 };
  BlockInfo dummy_info = {};
  dummy_info.body = reinterpret_cast<BlockBody*>(dummy_body);
  dummy_info.body_size = sizeof(dummy_body);
  for (size_t i = 0; i < arraysize(dummy_body); ++i) {
    EXPECT_FALSE(BlockBodyIsFloodFilled(dummy_info));
    dummy_body[i] = kBlockFloodFillByte;
  }
  EXPECT_TRUE(BlockBodyIsFloodFilled(dummy_info));
}

TEST_F(BlockTest, BlockDetermineMostLikelyState) {
  AsanLogger logger;
  Shadow shadow;
  memory_notifiers::ShadowMemoryNotifier notifier(&shadow);
  StackCaptureCache cache(&logger, &notifier);

  {
    testing::FakeAsanBlock block1(&shadow, kShadowRatio, &cache);
    block1.InitializeBlock(1024);
    EXPECT_EQ(ALLOCATED_BLOCK,
              BlockDetermineMostLikelyState(&shadow, block1.block_info));
    block1.block_info.header->state = ~block1.block_info.header->state;
    EXPECT_EQ(ALLOCATED_BLOCK,
              BlockDetermineMostLikelyState(&shadow, block1.block_info));
    block1.MarkBlockAsQuarantined();
    EXPECT_EQ(QUARANTINED_BLOCK,
              BlockDetermineMostLikelyState(&shadow, block1.block_info));
    block1.block_info.header->state = ~block1.block_info.header->state;
    EXPECT_EQ(QUARANTINED_BLOCK,
              BlockDetermineMostLikelyState(&shadow, block1.block_info));
  }

  {
    testing::FakeAsanBlock block2(&shadow, kShadowRatio, &cache);
    block2.InitializeBlock(1024);
    EXPECT_EQ(ALLOCATED_BLOCK,
              BlockDetermineMostLikelyState(&shadow, block2.block_info));
    block2.block_info.header->state = ~block2.block_info.header->state;
    EXPECT_EQ(ALLOCATED_BLOCK,
              BlockDetermineMostLikelyState(&shadow, block2.block_info));
    block2.MarkBlockAsQuarantinedFlooded();
    EXPECT_EQ(QUARANTINED_FLOODED_BLOCK,
              BlockDetermineMostLikelyState(&shadow, block2.block_info));
    block2.block_info.header->state = ~block2.block_info.header->state;
    EXPECT_EQ(QUARANTINED_FLOODED_BLOCK,
              BlockDetermineMostLikelyState(&shadow, block2.block_info));
    block2.block_info.RawBody(10) = 0;
    EXPECT_EQ(QUARANTINED_FLOODED_BLOCK,
              BlockDetermineMostLikelyState(&shadow, block2.block_info));
    ::memset(block2.block_info.body, 0, block2.block_info.body_size);
    EXPECT_EQ(QUARANTINED_BLOCK,
              BlockDetermineMostLikelyState(&shadow, block2.block_info));
  }
}

TEST_F(BlockTest, BitFlips) {
  AsanLogger logger;
  Shadow shadow;
  memory_notifiers::ShadowMemoryNotifier notifier(&shadow);
  StackCaptureCache cache(&logger, &notifier);

  testing::FakeAsanBlock block1(&shadow, kShadowRatio, &cache);
  block1.InitializeBlock(100);
  block1.MarkBlockAsQuarantined();
  size_t flips = 0;

  EXPECT_TRUE(
      BlockBitFlipsFixChecksum(QUARANTINED_BLOCK, block1.block_info, 0));
  flips = BlockBitFlipsRequired(QUARANTINED_BLOCK, block1.block_info, 3);
  EXPECT_EQ(0u, flips);

  block1.block_info.RawHeader(2) ^= 4;
  EXPECT_FALSE(
      BlockBitFlipsFixChecksum(QUARANTINED_BLOCK, block1.block_info, 0));
  EXPECT_TRUE(
      BlockBitFlipsFixChecksum(QUARANTINED_BLOCK, block1.block_info, 1));
  flips = BlockBitFlipsRequired(QUARANTINED_BLOCK, block1.block_info, 3);
  EXPECT_EQ(1u, flips);

  block1.block_info.RawBody(5) ^= 2;
  EXPECT_FALSE(
      BlockBitFlipsFixChecksum(QUARANTINED_BLOCK, block1.block_info, 0));
  EXPECT_TRUE(
      BlockBitFlipsFixChecksum(QUARANTINED_BLOCK, block1.block_info, 2));
  flips = BlockBitFlipsRequired(QUARANTINED_BLOCK, block1.block_info, 3);
  EXPECT_LT(0u, flips);
  EXPECT_GE(2u, flips);

  block1.block_info.RawTrailer(3) ^= 1;
  EXPECT_FALSE(
      BlockBitFlipsFixChecksum(QUARANTINED_BLOCK, block1.block_info, 0));
  EXPECT_TRUE(
      BlockBitFlipsFixChecksum(QUARANTINED_BLOCK, block1.block_info, 3));
  flips = BlockBitFlipsRequired(QUARANTINED_BLOCK, block1.block_info, 3);
  EXPECT_LT(0u, flips);
  EXPECT_GE(3u, flips);
}

}  // namespace asan
}  // namespace agent
