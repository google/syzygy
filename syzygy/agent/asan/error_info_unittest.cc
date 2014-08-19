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

#include "syzygy/agent/asan/error_info.h"

#include <windows.h>

#include "gtest/gtest.h"
#include "syzygy/agent/asan/unittest_util.h"

namespace agent {
namespace asan {

namespace {

typedef testing::TestWithAsanRuntime AsanErrorInfoTest;

}  // namespace

TEST_F(AsanErrorInfoTest, ErrorInfoAccessTypeToStr) {
  EXPECT_EQ(kHeapUseAfterFree, ErrorInfoAccessTypeToStr(USE_AFTER_FREE));
  EXPECT_EQ(kHeapBufferUnderFlow,
            ErrorInfoAccessTypeToStr(HEAP_BUFFER_UNDERFLOW));
  EXPECT_EQ(kHeapBufferOverFlow,
            ErrorInfoAccessTypeToStr(HEAP_BUFFER_OVERFLOW));
  EXPECT_EQ(kAttemptingDoubleFree, ErrorInfoAccessTypeToStr(DOUBLE_FREE));
  EXPECT_EQ(kInvalidAddress, ErrorInfoAccessTypeToStr(INVALID_ADDRESS));
  EXPECT_EQ(kWildAccess, ErrorInfoAccessTypeToStr(WILD_ACCESS));
  EXPECT_EQ(kHeapUnknownError, ErrorInfoAccessTypeToStr(UNKNOWN_BAD_ACCESS));
  EXPECT_EQ(kHeapCorruptBlock, ErrorInfoAccessTypeToStr(CORRUPT_BLOCK));
  EXPECT_EQ(kCorruptHeap, ErrorInfoAccessTypeToStr(CORRUPT_HEAP));
}

TEST_F(AsanErrorInfoTest, ErrorInfoGetBadAccessInformation) {
  testing::FakeAsanBlock fake_block(kShadowRatioLog, runtime_.stack_cache());
  const size_t kAllocSize = 100;
  EXPECT_TRUE(fake_block.InitializeBlock(kAllocSize));

  AsanErrorInfo error_info = {};
  error_info.location = fake_block.block_info.body +
      kAllocSize + 1;
  EXPECT_TRUE(ErrorInfoGetBadAccessInformation(runtime_.stack_cache(),
                                               &error_info));
  EXPECT_EQ(HEAP_BUFFER_OVERFLOW, error_info.error_type);

  EXPECT_TRUE(fake_block.MarkBlockAsQuarantined());
  error_info.location = fake_block.block_info.body;
  EXPECT_TRUE(ErrorInfoGetBadAccessInformation(runtime_.stack_cache(),
                                               &error_info));
  EXPECT_EQ(USE_AFTER_FREE, error_info.error_type);

  error_info.location = fake_block.buffer_align_begin - 1;
  EXPECT_FALSE(ErrorInfoGetBadAccessInformation(runtime_.stack_cache(),
                                                &error_info));
}

TEST_F(AsanErrorInfoTest, GetBadAccessInformationNestedBlock) {
  // Test a nested use after free. We allocate an outer block and an inner block
  // inside it, then we mark the outer block as quarantined and we test a bad
  // access inside the inner block.

  testing::FakeAsanBlock fake_block(kShadowRatioLog, runtime_.stack_cache());
  const size_t kInnerBlockAllocSize = 100;

  // Allocates the outer block.
  BlockLayout outer_block_layout = {};
  BlockPlanLayout(kShadowRatio, kShadowRatio, kInnerBlockAllocSize, 0, 0,
      &outer_block_layout);
  EXPECT_TRUE(fake_block.InitializeBlock(outer_block_layout.block_size));

  StackCapture stack;
  stack.InitFromStack();

  // Initializes the inner block.
  BlockLayout inner_block_layout = {};
  BlockPlanLayout(kShadowRatio,
                  kShadowRatio,
                  kInnerBlockAllocSize,
                  0,
                  0,
                  &inner_block_layout);
  BlockInfo inner_block_info = {};
  BlockInitialize(inner_block_layout, fake_block.block_info.body, true,
      &inner_block_info);
  ASSERT_NE(reinterpret_cast<void*>(NULL), inner_block_info.body);
  Shadow::PoisonAllocatedBlock(inner_block_info);
  inner_block_info.header->alloc_stack =
      runtime_.stack_cache()->SaveStackTrace(stack);
  BlockHeader* inner_header = inner_block_info.header;
  BlockHeader* outer_header = reinterpret_cast<BlockHeader*>(
      fake_block.buffer_align_begin);

  AsanErrorInfo error_info = {};

  // Mark the inner block as quarantined and check that we detect a use after
  // free when trying to access its data.
  inner_block_info.header->free_stack =
      runtime_.stack_cache()->SaveStackTrace(stack);
  EXPECT_NE(reinterpret_cast<void*>(NULL), inner_header->free_stack);
  inner_header->state = QUARANTINED_BLOCK;

  error_info.location = fake_block.block_info.body;
  EXPECT_TRUE(ErrorInfoGetBadAccessInformation(runtime_.stack_cache(),
                                               &error_info));
  EXPECT_EQ(USE_AFTER_FREE, error_info.error_type);
  EXPECT_NE(reinterpret_cast<void*>(NULL), error_info.free_stack);

  EXPECT_EQ(inner_header->free_stack->num_frames(), error_info.free_stack_size);
  for (size_t i = 0; i < inner_header->free_stack->num_frames(); ++i)
    EXPECT_EQ(inner_header->free_stack->frames()[i], error_info.free_stack[i]);

  // Mark the outer block as quarantined, we should detect a use after free
  // when trying to access the data of the inner block, and the free stack
  // should be the one of the inner block.
  EXPECT_TRUE(fake_block.MarkBlockAsQuarantined());
  EXPECT_NE(ALLOCATED_BLOCK, static_cast<BlockState>(outer_header->state));
  EXPECT_NE(reinterpret_cast<void*>(NULL), outer_header->free_stack);

  // Tests an access in the inner block.
  error_info.location = inner_block_info.body;
  EXPECT_TRUE(ErrorInfoGetBadAccessInformation(runtime_.stack_cache(),
                                               &error_info));
  EXPECT_EQ(USE_AFTER_FREE, error_info.error_type);
  EXPECT_NE(reinterpret_cast<void*>(NULL), error_info.free_stack);

  EXPECT_EQ(inner_header->free_stack->num_frames(), error_info.free_stack_size);
  for (size_t i = 0; i < inner_header->free_stack->num_frames(); ++i)
    EXPECT_EQ(inner_header->free_stack->frames()[i], error_info.free_stack[i]);
}

TEST_F(AsanErrorInfoTest, ErrorInfoGetBadAccessKind) {
  const size_t kAllocSize = 100;
  testing::FakeAsanBlock fake_block(kShadowRatioLog, runtime_.stack_cache());
  EXPECT_TRUE(fake_block.InitializeBlock(kAllocSize));
  uint8* heap_underflow_address = fake_block.block_info.body - 1;
  uint8* heap_overflow_address = fake_block.block_info.body +
      kAllocSize * sizeof(uint8);
  EXPECT_EQ(HEAP_BUFFER_UNDERFLOW,
            ErrorInfoGetBadAccessKind(heap_underflow_address,
                                      fake_block.block_info.header));
  EXPECT_EQ(HEAP_BUFFER_OVERFLOW,
            ErrorInfoGetBadAccessKind(heap_overflow_address,
                                      fake_block.block_info.header));
  EXPECT_TRUE(fake_block.MarkBlockAsQuarantined());
  EXPECT_EQ(USE_AFTER_FREE, ErrorInfoGetBadAccessKind(
      fake_block.block_info.body, fake_block.block_info.header));
}

TEST_F(AsanErrorInfoTest, ErrorInfoGetAsanBlockInfo) {
  const size_t kAllocSize = 100;
  testing::FakeAsanBlock fake_block(kShadowRatioLog, runtime_.stack_cache());
  EXPECT_TRUE(fake_block.InitializeBlock(kAllocSize));

  AsanBlockInfo asan_block_info = {};
  asan_block_info.header = fake_block.block_info.header;
  asan_block_info.corrupt = !BlockChecksumIsValid(fake_block.block_info);
  ErrorInfoGetAsanBlockInfo(runtime_.stack_cache(), &asan_block_info);

  // Test ErrorInfoGetAsanBlockInfo with an allocated block.
  EXPECT_EQ(fake_block.block_info.body_size, asan_block_info.user_size);
  EXPECT_EQ(ALLOCATED_BLOCK, static_cast<BlockState>(asan_block_info.state));
  EXPECT_EQ(fake_block.block_info.header->state,
            static_cast<BlockState>(asan_block_info.state));
  EXPECT_EQ(::GetCurrentThreadId(), asan_block_info.alloc_tid);
  EXPECT_EQ(0, asan_block_info.free_tid);
  EXPECT_FALSE(asan_block_info.corrupt);
  EXPECT_EQ(fake_block.block_info.header->alloc_stack->num_frames(),
            asan_block_info.alloc_stack_size);
  EXPECT_EQ(0, asan_block_info.free_stack_size);

  // Now test it with a quarantined block.
  EXPECT_TRUE(fake_block.MarkBlockAsQuarantined());
  ErrorInfoGetAsanBlockInfo(runtime_.stack_cache(), &asan_block_info);
  EXPECT_EQ(QUARANTINED_BLOCK, static_cast<BlockState>(asan_block_info.state));
  EXPECT_EQ(fake_block.block_info.header->state,
            static_cast<BlockState>(asan_block_info.state));
  EXPECT_EQ(::GetCurrentThreadId(), asan_block_info.free_tid);
  EXPECT_EQ(fake_block.block_info.header->free_stack->num_frames(),
            asan_block_info.free_stack_size);

  // Ensure that the block is correctly tagged as corrupt if the header is
  // invalid.
  fake_block.block_info.header->magic = ~kBlockHeaderMagic;
  ErrorInfoGetAsanBlockInfo(runtime_.stack_cache(), &asan_block_info);
  EXPECT_TRUE(asan_block_info.corrupt);
  fake_block.block_info.header->magic = kBlockHeaderMagic;
}

TEST_F(AsanErrorInfoTest, GetTimeSinceFree) {
  const size_t kAllocSize = 100;
  const size_t kSleepTime = 25;
  testing::FakeAsanBlock fake_block(kShadowRatioLog, runtime_.stack_cache());
  EXPECT_TRUE(fake_block.InitializeBlock(kAllocSize));

  uint32 ticks_before_free = ::GetTickCount();
  EXPECT_TRUE(fake_block.MarkBlockAsQuarantined());
  ::Sleep(kSleepTime);
  AsanErrorInfo error_info = {};
  error_info.error_type = USE_AFTER_FREE;
  error_info.location = fake_block.block_info.body;
  EXPECT_TRUE(ErrorInfoGetBadAccessInformation(runtime_.stack_cache(),
                                               &error_info));
  EXPECT_NE(0U, error_info.milliseconds_since_free);

  uint32 ticks_delta = ::GetTickCount() - ticks_before_free;
  EXPECT_GT(ticks_delta, 0U);

  EXPECT_GE(ticks_delta, error_info.milliseconds_since_free);
}

}  // namespace asan
}  // namespace agent
