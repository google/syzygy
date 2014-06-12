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

#include "windows.h"

#include "base/debug/alias.h"
#include "gtest/gtest.h"

namespace agent {
namespace asan {

namespace {

BlockLayout BuildBlockLayout(size_t block_alignment,
                             size_t block_size,
                             size_t header_size,
                             size_t header_padding_size,
                             size_t body_size,
                             size_t trailer_padding_size,
                             size_t trailer_size) {
  BlockLayout layout = { block_alignment, block_size, header_size,
      header_padding_size, body_size, trailer_padding_size, trailer_size };
  return layout;
}

// Checks that the given block is valid, and initialized as expected.
void IsValidBlockImpl(const BlockInfo& block, bool just_initialized) {
  EXPECT_EQ(0u, block.block_size % kShadowRatio);

  // Validate the layout of the block.
  EXPECT_TRUE(block.block != NULL);
  EXPECT_EQ(0u, block.block_size % kShadowRatio);
  EXPECT_EQ(block.block, reinterpret_cast<void*>(block.header));
  EXPECT_EQ(0u, block.header_padding_size % kShadowRatio);
  EXPECT_EQ(reinterpret_cast<uint8*>(block.header + 1),
            block.header_padding);
  EXPECT_EQ(block.header_padding + block.header_padding_size,
            block.body);
  EXPECT_EQ(reinterpret_cast<uint8*>(block.body + block.body_size),
            block.trailer_padding);
  EXPECT_EQ(block.trailer_padding + block.trailer_padding_size,
            reinterpret_cast<uint8*>(block.trailer));
  EXPECT_EQ(block.block + block.block_size,
            reinterpret_cast<uint8*>(block.trailer + 1));

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
              *reinterpret_cast<const uint32*>(block.header_padding));
    EXPECT_EQ(block.header_padding_size,
              *reinterpret_cast<const uint32*>(block.header_padding +
                  block.header_padding_size - sizeof(uint32)));
    for (size_t i = sizeof(uint32);
         i < block.header_padding_size - sizeof(uint32);
         ++i) {
      EXPECT_EQ(kBlockHeaderPaddingByte, block.header_padding[i]);
    }
  }

  // Check the trailer padding.
  size_t start_of_trailer_iteration = 0;
  if (block.header->has_excess_trailer_padding) {
    start_of_trailer_iteration = 4;
    EXPECT_EQ(block.trailer_padding_size,
              *reinterpret_cast<const uint32*>(block.trailer_padding));
  }
  for (size_t i = start_of_trailer_iteration; i < block.trailer_padding_size;
       ++i) {
    EXPECT_EQ(kBlockTrailerPaddingByte, block.trailer_padding[i]);
  }

  // Check the trailer.
  EXPECT_NE(0u, block.trailer->alloc_tid);
  EXPECT_GE(::GetTickCount(), block.trailer->alloc_ticks);
  EXPECT_TRUE(block.trailer->next == NULL);
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

}  // namespace

bool operator==(const BlockLayout& bl1, const BlockLayout& bl2) {
  return ::memcmp(&bl1, &bl2, sizeof(BlockLayout)) == 0;
}

TEST(BlockTest, BlockPlanLayout) {
  BlockLayout layout = {};

  // Zero sized allocations should work fine.
  BlockPlanLayout(8, 8, 0, 0, 0, &layout);
  EXPECT_EQ(BuildBlockLayout(8, 40, 16, 0, 0, 4, 20), layout);

  BlockPlanLayout(8, 8, 60, 32, 32, &layout);
  EXPECT_EQ(BuildBlockLayout(8, 128, 16, 16, 60, 16, 20), layout);

  BlockPlanLayout(8, 8, 60, 0, 0, &layout);
  EXPECT_EQ(BuildBlockLayout(8, 96, 16, 0, 60, 0, 20), layout);

  BlockPlanLayout(8, 8, 64, 0, 0, &layout);
  EXPECT_EQ(BuildBlockLayout(8, 104, 16, 0, 64, 4, 20), layout);

  BlockPlanLayout(8, 8, 61, 0, 0, &layout);
  EXPECT_EQ(BuildBlockLayout(8, 104, 16, 0, 61, 7, 20), layout);

  // Plan a layout that would use guard pages.
  BlockPlanLayout(4096, 8, 100, 4096, 4096, &layout);
  EXPECT_EQ(BuildBlockLayout(4096, 3 * 4096, 16, 8072, 100, 4080, 20), layout);
}

TEST(BlockTest, EndToEnd) {
  BlockLayout layout = {};
  BlockInfo block_info = {};

  BlockPlanLayout(8, 8, 61, 0, 0, &layout);
  void* block_data = ::malloc(layout.block_size);
  ASSERT_TRUE(block_data != NULL);
  BlockInitialize(layout, block_data, &block_info);
  EXPECT_NO_FATAL_FAILURE(IsValidInitializedBlock(block_info));
  ::free(block_data);
  block_data = NULL;

  BlockPlanLayout(8, 8, 60, 32, 32, &layout);
  block_data = ::malloc(layout.block_size);
  ASSERT_TRUE(block_data != NULL);
  BlockInitialize(layout, block_data, &block_info);
  EXPECT_NO_FATAL_FAILURE(IsValidInitializedBlock(block_info));
  ::free(block_data);
  block_data = NULL;

  // Do an allocation that uses entire pages.
  BlockPlanLayout(4096, 8, 100, 4096, 4096, &layout);
  block_data = ::VirtualAlloc(NULL, layout.block_size, MEM_COMMIT,
                              PAGE_READWRITE);
  ASSERT_TRUE(block_data != NULL);
  BlockInitialize(layout, block_data, &block_info);
  EXPECT_NO_FATAL_FAILURE(IsValidInitializedBlock(block_info));
  ASSERT_EQ(TRUE, ::VirtualFree(block_data, 0, MEM_RELEASE));
  block_data = NULL;
}

TEST(BlockTest, GetHeaderFromBody) {
  // Plan two layouts, one with header padding and another without.
  BlockLayout layout1 = {};
  BlockLayout layout2 = {};
  BlockPlanLayout(kShadowRatio, kShadowRatio, 10, 0, 0, &layout1);
  BlockPlanLayout(kShadowRatio, kShadowRatio, 10, 32, 0, &layout2);

  uint8* data = new uint8[layout2.block_size];

  // First try navigating a block without header padding.
  BlockInfo info = {};
  BlockInitialize(layout1, data, &info);
  // This should succeed as expected.
  EXPECT_EQ(info.header, BlockGetHeaderFromBody(info.body));
  // This fails because of invalid alignment.
  EXPECT_TRUE(BlockGetHeaderFromBody(info.body + 1) == NULL);
  // This fails because the pointer is not at the beginning of the
  // body.
  EXPECT_TRUE(BlockGetHeaderFromBody(info.body + 8) == NULL);
  // This fails because of invalid header magic.
  ++info.header->magic;
  EXPECT_TRUE(BlockGetHeaderFromBody(info.body) == NULL);
  // This fails because the header indicates there's padding.
  --info.header->magic;
  info.header->has_header_padding = 1;
  EXPECT_TRUE(BlockGetHeaderFromBody(info.body) == NULL);

  // First try navigating a block without header padding.
  BlockInitialize(layout2, data, &info);
  // This should succeed as expected.
  EXPECT_EQ(info.header, BlockGetHeaderFromBody(info.body));
  // This fails because of invalid alignment.
  EXPECT_TRUE(BlockGetHeaderFromBody(info.body + 1) == NULL);
  // This fails because the pointer is not at the beginning of the
  // body.
  EXPECT_TRUE(BlockGetHeaderFromBody(info.body + 8) == NULL);
  // This fails because of invalid header magic.
  ++info.header->magic;
  EXPECT_TRUE(BlockGetHeaderFromBody(info.body) == NULL);
  // This fails because the header indicates there's no padding.
  --info.header->magic;
  info.header->has_header_padding = 0;
  EXPECT_TRUE(BlockGetHeaderFromBody(info.body) == NULL);
  // This fails because the padding length is invalid.
  info.header->has_header_padding = 1;
  uint32* head = reinterpret_cast<uint32*>(info.header_padding);
  uint32* tail = head + (info.header_padding_size / sizeof(uint32)) - 1;
  ++(*tail);
  EXPECT_TRUE(BlockGetHeaderFromBody(info.body) == NULL);
  // This fails because the padding lengths don't agree.
  --(*tail);
  ++(*head);
  EXPECT_TRUE(BlockGetHeaderFromBody(info.body) == NULL);

  delete[] data;
}

TEST(BlockTest, GetHeaderFromBodyProtectedMemory) {
  BlockLayout layout = {};
  BlockPlanLayout(4096, 4096, 4096, 4096, 4096, &layout);
  void* alloc = ::VirtualAlloc(NULL, layout.block_size, MEM_COMMIT,
                               PAGE_READWRITE);
  ASSERT_TRUE(alloc != NULL);
  BlockInfo block_info = {};
  BlockInitialize(layout, alloc, &block_info);

  BlockProtectRedzones(block_info);
  EXPECT_TRUE(BlockGetHeaderFromBody(block_info.body) == NULL);

  ASSERT_EQ(TRUE, ::VirtualFree(alloc, 0, MEM_RELEASE));
}

TEST(BlockTest, ChecksumWorksForAllStates) {
  BlockLayout layout = {};
  BlockPlanLayout(kShadowRatio, kShadowRatio, 10, 0, 0, &layout);
  uint8* data = new uint8[layout.block_size];
  BlockInfo info = {};
  BlockInitialize(layout, data, &info);
  while (true) {
    BlockCalculateChecksum(info);
    ++info.header->state;
    if (info.header->state == 0)
      break;
  }
  delete[] data;
}

namespace {

// Given two arrays of data, compares them byte-by-byte to find the first
// byte with altered data. Within that byte determines the mask of bits that
// have been altered. Returns the results via |offset| and |mask|.
void FindModifiedBits(size_t length,
                      const uint8* buffer1,
                      const uint8* buffer2,
                      size_t* offset,
                      uint8* mask) {
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

bool ChecksumDetectsTamperingWithMask(const BlockInfo& block_info,
                                      void* address_to_modify,
                                      uint8 mask_to_modify) {
  uint8* byte_to_modify = reinterpret_cast<uint8*>(address_to_modify);

  // Remember the original contents.
  uint8 original_value = *byte_to_modify;
  uint8 original_bits = original_value & ~mask_to_modify;

  // Since the checksum can collide we check a handful of times to build up
  // some confidence. Since we sometimes expect this to return false the number
  // of iterations needs to be kept reasonably low to keep the unittest fast.
  bool detected = false;
  BlockSetChecksum(block_info);
  uint32 checksum = block_info.header->checksum;
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
      detected = true;
      break;
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
  uint32 checksum = BlockCalculateChecksum(block_info);
  block_info.header->checksum = checksum;
  EXPECT_TRUE(BlockChecksumIsValid(block_info));
  ++block_info.header->checksum;
  EXPECT_FALSE(BlockChecksumIsValid(block_info));
  BlockSetChecksum(block_info);
  EXPECT_EQ(checksum, block_info.header->checksum);

  // Get the offset of the byte and the mask of the bits containing the
  // block state. This is resilient to changes in the BlockHeader layout.
  static size_t state_offset = -1;
  static uint8 state_mask = 0;
  if (state_offset == -1) {
    BlockHeader header1 = {};
    BlockHeader header2 = {};
    header2.state = -1;
    FindModifiedBits(sizeof(BlockHeader),
                     reinterpret_cast<const uint8*>(&header1),
                     reinterpret_cast<const uint8*>(&header2),
                     &state_offset,
                     &state_mask);
  }

  // Header bytes should be tamper proof.
  EXPECT_TRUE(ChecksumDetectsTampering(block_info, block_info.header));
  EXPECT_TRUE(ChecksumDetectsTampering(block_info,
                                       &block_info.header->alloc_stack));
  EXPECT_TRUE(ChecksumDetectsTamperingWithMask(
      block_info,
      block_info.block + state_offset,
      state_mask));

  // Header padding should be tamper proof.
  if (block_info.header_padding_size > 0) {
    EXPECT_TRUE(ChecksumDetectsTampering(block_info,
        block_info.header_padding + block_info.header_padding_size / 2));
  }

  // Trailer padding should be tamper proof.
  if (block_info.trailer_padding_size > 0) {
    EXPECT_TRUE(ChecksumDetectsTampering(block_info,
        block_info.trailer_padding + block_info.trailer_padding_size / 2));
  }

  // Trailer bytes should be tamper proof.
  EXPECT_TRUE(ChecksumDetectsTampering(block_info, block_info.trailer));
  EXPECT_TRUE(ChecksumDetectsTampering(block_info,
                                       &block_info.trailer->alloc_ticks));

  // Expect the checksum to detect body tampering in quarantined and freed
  // states, but not in the allocated state.
  bool expected = (block_info.header->state != ALLOCATED_BLOCK);
  EXPECT_EQ(expected, ChecksumDetectsTampering(block_info, block_info.body));
  EXPECT_EQ(expected, ChecksumDetectsTampering(block_info,
      block_info.body + block_info.body_size / 2));
  EXPECT_EQ(expected, ChecksumDetectsTampering(block_info,
      block_info.body + block_info.body_size - 1));
}

}  // namespace

TEST(BlockTest, ChecksumDetectsTampering) {
  size_t kSizes[] = { 1, 4, 7, 16, 23, 32, 117, 1000, 4096 };

  // Doing a single allocation makes this test a bit faster.
  size_t kAllocSize = 4 * 4096;
  void* alloc = ::VirtualAlloc(NULL, kAllocSize, MEM_COMMIT, PAGE_READWRITE);
  ASSERT_TRUE(alloc != NULL);

  // We test 9 different sizes, 9 different chunk sizes, 1 to 9 different
  // alignments, and 2 different redzone sizes. This is 810 different
  // combinations. We test each of these block allocations in all 3 possible
  // states. The probe itself tests the block at 7 to 9 different points, and
  // the tests require multiple iterations. Be careful playing with these
  // constants or the unittest time can easily spiral out of control! This
  // currently requires less than half a second, and is strictly CPU bound.
  for (size_t chunk_size = kShadowRatio; chunk_size <= kPageSize;
       chunk_size *= 2) {
    for (size_t align = kShadowRatio; align <= chunk_size; align *= 2) {
      for (size_t redzone = 0; redzone <= chunk_size; redzone += chunk_size) {
        for (size_t i = 0; i < arraysize(kSizes); ++i) {
          BlockLayout layout = {};
          BlockPlanLayout(chunk_size, align, kSizes[i], redzone, redzone,
                          &layout);
          ASSERT_GT(kAllocSize, layout.block_size);

          BlockInfo block_info = {};
          BlockInitialize(layout, alloc, &block_info);

          // Test that the checksum detects tampering as expected in each block
          // state.
          block_info.header->state = ALLOCATED_BLOCK;
          ASSERT_NO_FATAL_FAILURE(TestChecksumDetectsTampering(block_info));
          block_info.header->state = QUARANTINED_BLOCK;
          ASSERT_NO_FATAL_FAILURE(TestChecksumDetectsTampering(block_info));
          block_info.header->state = FREED_BLOCK;
          ASSERT_NO_FATAL_FAILURE(TestChecksumDetectsTampering(block_info));
        }  // kSizes[i]
      }  // redzone
    }  // align
  }  // chunk_size

  ASSERT_EQ(TRUE, ::VirtualFree(alloc, 0, MEM_RELEASE));
}

namespace {

// An exception filter that grabs and sets an exception pointer, and
// triggers only for access violations.
DWORD AccessViolationFilter(EXCEPTION_POINTERS* e,
                            EXCEPTION_POINTERS** pe) {
  *pe = e;
  if (e->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
    return EXCEPTION_EXECUTE_HANDLER;
  return EXCEPTION_CONTINUE_SEARCH;
}

// Tries to access the given address, validating whether or not an
// access violation occurs.
bool TestAccess(void* address, bool expect_access_violation) {
  uint8* m = reinterpret_cast<uint8*>(address);
  ULONG_PTR p = reinterpret_cast<ULONG_PTR>(address);

  // Try a read.
  uint8 value = 0;
  EXCEPTION_POINTERS* e = NULL;
  __try {
    value = m[0];
    if (expect_access_violation)
      return false;
  } __except (AccessViolationFilter(GetExceptionInformation(), &e)) {
    if (!expect_access_violation)
      return false;
    if (e->ExceptionRecord == NULL ||
        e->ExceptionRecord->NumberParameters < 2 ||
        e->ExceptionRecord->ExceptionInformation[1] != p) {
      return false;
    }
    return true;
  }

  // Try a write.
  __try {
    m[0] = 0;
    if (expect_access_violation)
      return false;
  } __except (AccessViolationFilter(GetExceptionInformation(), &e)) {
    if (!expect_access_violation)
      return false;
    if (e->ExceptionRecord == NULL ||
        e->ExceptionRecord->NumberParameters < 2 ||
        e->ExceptionRecord->ExceptionInformation[1] != p) {
      return false;
    }
  }

  // Ensure that |value| doesn't get optimized away. If so, the attempted
  // read never occurs.
  base::debug::Alias(&value);

  return true;
}

// Readable wrappers to TestAccess.
bool IsAccessible(void* address) {
  return TestAccess(address, false);
}
bool IsNotAccessible(void* address) {
  return TestAccess(address, true);
}

enum Protection {
  kProtectNone,
  kProtectRedzones,
  kProtectAll,
};

void TestAccessUnderProtection(const BlockInfo& block_info,
                               Protection protection) {
  // Grab a set of points to sample for access, scattered across the various
  // components of the block.
  std::set<void*> samples;
  samples.insert(block_info.header);
  samples.insert(block_info.header_padding - 1);
  samples.insert(block_info.header_padding);
  samples.insert(block_info.header_padding +
      block_info.header_padding_size / 2);
  samples.insert(block_info.header_padding +
      block_info.header_padding_size - 1);
  samples.insert(block_info.body);
  samples.insert(block_info.body + block_info.body_size / 2);
  samples.insert(block_info.body + block_info.body_size - 1);
  samples.insert(block_info.trailer_padding);
  samples.insert(block_info.trailer_padding +
      block_info.trailer_padding_size / 2);
  samples.insert(block_info.trailer_padding +
      block_info.trailer_padding_size - 1);
  samples.insert(block_info.trailer);
  samples.insert(block_info.trailer);
  samples.insert(block_info.block + block_info.block_size - 1);

  // Also sample at points at the edges of the pages in the redzones.
  if (block_info.left_redzone_pages_size > 0) {
    if (block_info.block < block_info.left_redzone_pages)
      samples.insert(block_info.left_redzone_pages - 1);
    samples.insert(block_info.left_redzone_pages);
    samples.insert(block_info.left_redzone_pages +
        block_info.left_redzone_pages_size - 1);
    samples.insert(block_info.left_redzone_pages +
        block_info.left_redzone_pages_size);
  }
  if (block_info.right_redzone_pages_size > 0) {
    samples.insert(block_info.right_redzone_pages - 1);
    samples.insert(block_info.right_redzone_pages);
    samples.insert(block_info.right_redzone_pages +
        block_info.right_redzone_pages_size - 1);
    uint8* past_end = block_info.right_redzone_pages +
        block_info.right_redzone_pages_size;
    if (past_end < block_info.block + block_info.block_size)
      samples.insert(past_end);
  }

  uint8* left_end = block_info.left_redzone_pages +
      block_info.left_redzone_pages_size;
  uint8* right_end = block_info.right_redzone_pages +
      block_info.right_redzone_pages_size;
  uint8* block_end = block_info.block_pages + block_info.block_pages_size;

  std::set<void*>::const_iterator it = samples.begin();
  for (; it != samples.end(); ++it) {
    if ((*it >= block_info.left_redzone_pages && *it < left_end) ||
        (*it >= block_info.right_redzone_pages && *it < right_end)) {
      // In the left or right guard pages.
      if (protection == kProtectNone) {
        EXPECT_TRUE(IsAccessible(*it));
      } else {
        EXPECT_TRUE(IsNotAccessible(*it));
      }
    } else if (*it >= block_info.block_pages && *it < block_end) {
      // In the block pages, but not a left or right guard page.
      if (protection == kProtectAll) {
        EXPECT_TRUE(IsNotAccessible(*it));
      } else {
        EXPECT_TRUE(IsAccessible(*it));
      }
    } else {
      // In the block, but in a page that is only partially covered.
      EXPECT_TRUE(IsAccessible(*it));
    }
  }
}

// Tests that the page protections are as expected after calling
// BlockProtectNone.
void TestProtectNone(const BlockInfo& block_info) {
  BlockProtectNone(block_info);
  EXPECT_NO_FATAL_FAILURE(TestAccessUnderProtection(block_info,
                                                    kProtectNone));
}

// Tests that the page protections are as expected after calling
// BlockProtectRedzones.
void TestProtectRedzones(const BlockInfo& block_info) {
  BlockProtectRedzones(block_info);
  EXPECT_NO_FATAL_FAILURE(TestAccessUnderProtection(block_info,
                                                    kProtectRedzones));
}

// Tests that the page protections are as expected after calling
// BlockProtectAll.
void TestProtectAll(const BlockInfo& block_info) {
  BlockProtectAll(block_info);
  EXPECT_NO_FATAL_FAILURE(TestAccessUnderProtection(block_info,
                                                    kProtectAll));
}

// Tests that all page protection transitions work.
void TestAllProtectionTransitions(size_t chunk_size,
                                  size_t alignment,
                                  size_t size,
                                  size_t min_left_redzone_size,
                                  size_t min_right_redzone_size) {
  // Create and initialize the given block.
  BlockLayout layout = {};
  BlockPlanLayout(chunk_size, alignment, size, min_left_redzone_size,
                  min_right_redzone_size, &layout);
  void* alloc = ::VirtualAlloc(NULL, layout.block_size, MEM_COMMIT,
                               PAGE_READWRITE);
  ASSERT_TRUE(alloc != NULL);
  BlockInfo block_info = {};
  BlockInitialize(layout, alloc, &block_info);

  // By default the protections should be disabled for a fresh allocation.
  EXPECT_NO_FATAL_FAILURE(TestAccessUnderProtection(block_info,
                                                    kProtectNone));

  // Try a full cycle of page protections. This tests all possible
  // transitions, including self transitions.
  EXPECT_NO_FATAL_FAILURE(TestProtectNone(block_info));
  EXPECT_NO_FATAL_FAILURE(TestProtectNone(block_info));
  EXPECT_NO_FATAL_FAILURE(TestProtectRedzones(block_info));
  EXPECT_NO_FATAL_FAILURE(TestProtectRedzones(block_info));
  EXPECT_NO_FATAL_FAILURE(TestProtectAll(block_info));
  EXPECT_NO_FATAL_FAILURE(TestProtectAll(block_info));
  EXPECT_NO_FATAL_FAILURE(TestProtectNone(block_info));
  EXPECT_NO_FATAL_FAILURE(TestProtectAll(block_info));
  EXPECT_NO_FATAL_FAILURE(TestProtectRedzones(block_info));
  EXPECT_NO_FATAL_FAILURE(TestProtectNone(block_info));

  ASSERT_EQ(TRUE, ::VirtualFree(alloc, 0, MEM_RELEASE));
}

}  // namespace

TEST(BlockTest, ProtectionTransitions) {
  // Left and right guard pages, everything page aligned.
  EXPECT_NO_FATAL_FAILURE(TestAllProtectionTransitions(
      4096, 4096, 4096, 4096, 4096));

  // Left and right guard pages will contain entire pages, but
  // not be entirely covered by pages.
  EXPECT_NO_FATAL_FAILURE(TestAllProtectionTransitions(
      8, 8, 128, 4100, 8200));

  // An allocation that will contain no pages whatsoever.
  EXPECT_NO_FATAL_FAILURE(TestAllProtectionTransitions(
      8, 8, 67, 0, 0));

  // An allocation with redzones containing no pages, but that covers an
  // entire page.
  EXPECT_NO_FATAL_FAILURE(TestAllProtectionTransitions(
      4096, 8, 67, 0, 0));
}

}  // namespace asan
}  // namespace agent
