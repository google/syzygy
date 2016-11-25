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

#include <string>

#include "base/strings/stringprintf.h"
#include "gtest/gtest.h"
#include "syzygy/agent/asan/unittest_util.h"
#include "syzygy/crashdata/json.h"

namespace agent {
namespace asan {

namespace {

class AsanErrorInfoTest : public testing::TestWithAsanRuntime {
 public:
  typedef testing::TestWithAsanRuntime Super;
  void SetUp() override {
    Super::SetUp();
  }

  void TearDown() override {
    // Clean up the fake asan block if there is one.
    // TODO(chrisha): Migrate this to using a dynamic shadow.
    if (!dummy_block_data_.empty()) {
      runtime_->shadow()->Unpoison(dummy_block_data_.data(),
                                   dummy_block_data_.size());
    }

    Super::TearDown();
  }

  void InitAsanBlockInfo(AsanBlockInfo* block_info) {
    if (dummy_block_data_.empty()) {
      // Create a dummy block to physically back the report.
      BlockLayout layout = {};
      BlockPlanLayout(kShadowRatio, kShadowRatio, 8, 0, 0, &layout);
      dummy_block_data_.resize(layout.block_size);
      BlockInfo info = {};
      BlockInitialize(layout, &dummy_block_data_.at(0), &info);
      runtime_->shadow()->PoisonAllocatedBlock(info);

      // Normalize a handful of fields to make the comparison simpler.
      info.trailer->alloc_ticks = 0;
      info.trailer->alloc_tid = 0;
    }

    block_info->header = &dummy_block_data_.at(0);
    block_info->user_size = 8;
    block_info->state = ALLOCATED_BLOCK;
    block_info->alloc_tid = 47;
    block_info->analysis.block_state = kDataIsCorrupt;
    block_info->analysis.header_state = kDataIsCorrupt;
    block_info->analysis.body_state = kDataStateUnknown;
    block_info->analysis.trailer_state = kDataIsClean;
    block_info->alloc_stack[0] = reinterpret_cast<void*>(1);
    block_info->alloc_stack[1] = reinterpret_cast<void*>(2);
    block_info->alloc_stack_size = 2;
    block_info->heap_type = kWinHeap;
  }

  const void* BlockShadowAddress() {
    return runtime_->shadow()->shadow() +
        reinterpret_cast<uintptr_t>(dummy_block_data_.data()) / kShadowRatio;
  }

 private:
  std::vector<unsigned char> dummy_block_data_;
};


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
  testing::FakeAsanBlock fake_block(
      runtime_->shadow(), kShadowRatioLog, runtime_->stack_cache());
  const size_t kAllocSize = 100;
  EXPECT_TRUE(fake_block.InitializeBlock(kAllocSize));

  AsanErrorInfo error_info = {};
  error_info.location = fake_block.block_info.RawBody() + kAllocSize + 1;
  EXPECT_TRUE(ErrorInfoGetBadAccessInformation(runtime_->shadow(),
                                               runtime_->stack_cache(),
                                               &error_info));
  EXPECT_EQ(HEAP_BUFFER_OVERFLOW, error_info.error_type);
  EXPECT_EQ(kUnknownHeapType, error_info.block_info.heap_type);

  EXPECT_TRUE(fake_block.MarkBlockAsQuarantined());
  error_info.location = fake_block.block_info.body;
  EXPECT_TRUE(ErrorInfoGetBadAccessInformation(runtime_->shadow(),
                                               runtime_->stack_cache(),
                                               &error_info));
  EXPECT_EQ(USE_AFTER_FREE, error_info.error_type);
  EXPECT_EQ(kUnknownHeapType, error_info.block_info.heap_type);

  error_info.location = fake_block.buffer_align_begin - 1;
  EXPECT_FALSE(ErrorInfoGetBadAccessInformation(runtime_->shadow(),
                                                runtime_->stack_cache(),
                                                &error_info));
}

TEST_F(AsanErrorInfoTest, GetBadAccessInformationNestedBlock) {
  // Test a nested use after free. We allocate an outer block and an inner block
  // inside it, then we mark the outer block as quarantined and we test a bad
  // access inside the inner block.

  testing::FakeAsanBlock fake_block(
      runtime_->shadow(), kShadowRatioLog, runtime_->stack_cache());
  const size_t kInnerBlockAllocSize = 100;

  // Allocates the outer block.
  BlockLayout outer_block_layout = {};
  EXPECT_TRUE(BlockPlanLayout(kShadowRatio, kShadowRatio, kInnerBlockAllocSize,
                              0, 0, &outer_block_layout));
  EXPECT_TRUE(fake_block.InitializeBlock(outer_block_layout.block_size));

  common::StackCapture stack;
  stack.InitFromStack();

  // Initializes the inner block.
  BlockLayout inner_block_layout = {};
  EXPECT_TRUE(BlockPlanLayout(kShadowRatio,
                              kShadowRatio,
                              kInnerBlockAllocSize,
                              0,
                              0,
                              &inner_block_layout));
  BlockInfo inner_block_info = {};
  BlockInitialize(inner_block_layout, fake_block.block_info.body,
                  &inner_block_info);
  ASSERT_NE(reinterpret_cast<void*>(NULL), inner_block_info.body);
  runtime_->shadow()->PoisonAllocatedBlock(inner_block_info);
  inner_block_info.header->alloc_stack =
      runtime_->stack_cache()->SaveStackTrace(stack);
  BlockHeader* inner_header = inner_block_info.header;
  BlockHeader* outer_header = reinterpret_cast<BlockHeader*>(
      fake_block.buffer_align_begin);

  AsanErrorInfo error_info = {};

  // Mark the inner block as quarantined and check that we detect a use after
  // free when trying to access its data.
  inner_block_info.header->free_stack =
      runtime_->stack_cache()->SaveStackTrace(stack);
  EXPECT_NE(reinterpret_cast<void*>(NULL), inner_header->free_stack);
  inner_header->state = QUARANTINED_BLOCK;

  error_info.location = fake_block.block_info.body;
  EXPECT_TRUE(ErrorInfoGetBadAccessInformation(runtime_->shadow(),
                                               runtime_->stack_cache(),
                                               &error_info));
  EXPECT_EQ(USE_AFTER_FREE, error_info.error_type);
  EXPECT_NE(reinterpret_cast<void*>(NULL), error_info.block_info.free_stack);
  EXPECT_EQ(kUnknownHeapType, error_info.block_info.heap_type);

  EXPECT_EQ(inner_header->free_stack->num_frames(),
            error_info.block_info.free_stack_size);
  for (size_t i = 0; i < inner_header->free_stack->num_frames(); ++i) {
    EXPECT_EQ(inner_header->free_stack->frames()[i],
              error_info.block_info.free_stack[i]);
  }

  // Mark the outer block as quarantined, we should detect a use after free
  // when trying to access the data of the inner block, and the free stack
  // should be the one of the inner block.
  EXPECT_TRUE(fake_block.MarkBlockAsQuarantined());
  EXPECT_NE(ALLOCATED_BLOCK, static_cast<BlockState>(outer_header->state));
  EXPECT_NE(reinterpret_cast<void*>(NULL), outer_header->free_stack);

  // Tests an access in the inner block.
  error_info.location = inner_block_info.body;
  EXPECT_TRUE(ErrorInfoGetBadAccessInformation(runtime_->shadow(),
                                               runtime_->stack_cache(),
                                               &error_info));
  EXPECT_EQ(USE_AFTER_FREE, error_info.error_type);
  EXPECT_NE(reinterpret_cast<void*>(NULL), error_info.block_info.free_stack);
  EXPECT_EQ(kUnknownHeapType, error_info.block_info.heap_type);

  EXPECT_EQ(inner_header->free_stack->num_frames(),
            error_info.block_info.free_stack_size);
  for (size_t i = 0; i < inner_header->free_stack->num_frames(); ++i) {
    EXPECT_EQ(inner_header->free_stack->frames()[i],
              error_info.block_info.free_stack[i]);
  }
}

TEST_F(AsanErrorInfoTest, ErrorInfoGetBadAccessKind) {
  const size_t kAllocSize = 100;
  testing::FakeAsanBlock fake_block(
      runtime_->shadow(), kShadowRatioLog, runtime_->stack_cache());
  EXPECT_TRUE(fake_block.InitializeBlock(kAllocSize));
  uint8_t* heap_underflow_address = fake_block.block_info.RawBody() - 1;
  uint8_t* heap_overflow_address =
      fake_block.block_info.RawBody() + kAllocSize * sizeof(uint8_t);
  EXPECT_EQ(HEAP_BUFFER_UNDERFLOW,
            ErrorInfoGetBadAccessKind(runtime_->shadow(),
                                      heap_underflow_address,
                                      fake_block.block_info.header));
  EXPECT_EQ(HEAP_BUFFER_OVERFLOW,
            ErrorInfoGetBadAccessKind(runtime_->shadow(),
                                      heap_overflow_address,
                                      fake_block.block_info.header));
  EXPECT_TRUE(fake_block.MarkBlockAsQuarantined());
  EXPECT_EQ(USE_AFTER_FREE, ErrorInfoGetBadAccessKind(runtime_->shadow(),
      fake_block.block_info.body, fake_block.block_info.header));
}

TEST_F(AsanErrorInfoTest, ErrorInfoGetAsanBlockInfo) {
  const size_t kAllocSize = 100;
  testing::FakeAsanBlock fake_block(
      runtime_->shadow(), kShadowRatioLog, runtime_->stack_cache());
  EXPECT_TRUE(fake_block.InitializeBlock(kAllocSize));

  AsanBlockInfo asan_block_info = {};
  ErrorInfoGetAsanBlockInfo(runtime_->shadow(), fake_block.block_info,
                            runtime_->stack_cache(), &asan_block_info);

  // Test ErrorInfoGetAsanBlockInfo with an allocated block.
  EXPECT_EQ(fake_block.block_info.body_size, asan_block_info.user_size);
  EXPECT_EQ(ALLOCATED_BLOCK, static_cast<BlockState>(asan_block_info.state));
  EXPECT_EQ(fake_block.block_info.header->state,
            static_cast<BlockState>(asan_block_info.state));
  EXPECT_EQ(::GetCurrentThreadId(), asan_block_info.alloc_tid);
  EXPECT_EQ(0, asan_block_info.free_tid);
  EXPECT_EQ(kDataIsClean, asan_block_info.analysis.block_state);
  EXPECT_EQ(fake_block.block_info.header->alloc_stack->num_frames(),
            asan_block_info.alloc_stack_size);
  EXPECT_EQ(0, asan_block_info.free_stack_size);
  EXPECT_EQ(kUnknownHeapType, asan_block_info.heap_type);

  // Now test it with a quarantined block.
  EXPECT_TRUE(fake_block.MarkBlockAsQuarantined());
  ErrorInfoGetAsanBlockInfo(runtime_->shadow(), fake_block.block_info,
                            runtime_->stack_cache(), &asan_block_info);
  EXPECT_EQ(QUARANTINED_BLOCK, static_cast<BlockState>(asan_block_info.state));
  EXPECT_EQ(fake_block.block_info.header->state,
            static_cast<BlockState>(asan_block_info.state));
  EXPECT_EQ(::GetCurrentThreadId(), asan_block_info.free_tid);
  EXPECT_EQ(fake_block.block_info.header->free_stack->num_frames(),
            asan_block_info.free_stack_size);
  EXPECT_EQ(kUnknownHeapType, asan_block_info.heap_type);

  // Ensure that the block is correctly tagged as corrupt if the header is
  // invalid.
  fake_block.block_info.header->magic =
      static_cast<uint16_t>(~kBlockHeaderMagic);
  ErrorInfoGetAsanBlockInfo(runtime_->shadow(), fake_block.block_info,
                            runtime_->stack_cache(), &asan_block_info);
  EXPECT_EQ(kDataIsCorrupt, asan_block_info.analysis.block_state);
  fake_block.block_info.header->magic =
      static_cast<uint16_t>(~kBlockHeaderMagic);
}

TEST_F(AsanErrorInfoTest, GetTimeSinceFree) {
  const size_t kAllocSize = 100;
  const size_t kSleepTime = 25;
  testing::FakeAsanBlock fake_block(
      runtime_->shadow(), kShadowRatioLog, runtime_->stack_cache());
  EXPECT_TRUE(fake_block.InitializeBlock(kAllocSize));

  uint32_t ticks_before_free = ::GetTickCount();
  EXPECT_TRUE(fake_block.MarkBlockAsQuarantined());
  ::Sleep(kSleepTime);
  AsanErrorInfo error_info = {};
  error_info.error_type = USE_AFTER_FREE;
  error_info.location = fake_block.block_info.body;
  EXPECT_TRUE(ErrorInfoGetBadAccessInformation(runtime_->shadow(),
                                               runtime_->stack_cache(),
                                               &error_info));
  EXPECT_NE(0U, error_info.block_info.milliseconds_since_free);

  uint32_t ticks_delta = ::GetTickCount() - ticks_before_free;
  EXPECT_GT(ticks_delta, 0U);

  EXPECT_GE(ticks_delta, error_info.block_info.milliseconds_since_free);
}

TEST_F(AsanErrorInfoTest, PopulateBlockInfo) {
  AsanBlockInfo block_info = {};
  InitAsanBlockInfo(&block_info);

  {
    crashdata::Value info;
    PopulateBlockInfo(runtime_->shadow(), block_info, false, &info, nullptr);
    std::string json;
    EXPECT_TRUE(crashdata::ToJson(true, &info, &json));
    const char kExpected[] =
        "{\n"
        "  \"header\": \"0x%08IX\",\n"
        "  \"user-size\": 8,\n"
        "  \"state\": \"allocated\",\n"
        "  \"heap-type\": \"WinHeap\",\n"
        "  \"analysis\": {\n"
        "    \"block\": \"corrupt\",\n"
        "    \"header\": \"corrupt\",\n"
        "    \"body\": \"(unknown)\",\n"
        "    \"trailer\": \"clean\"\n"
        "  },\n"
        "  \"alloc-thread-id\": 47,\n"
        "  \"alloc-stack\": [\n"
        "    \"0x00000001\", \"0x00000002\"\n"
        "  ]\n"
        "}";
    std::string expected = base::StringPrintf(
        kExpected, block_info.header);
    EXPECT_EQ(expected, json);
  }

  {
    block_info.state = QUARANTINED_FLOODED_BLOCK;
    block_info.free_tid = 32;
    block_info.free_stack[0] = reinterpret_cast<void*>(3);
    block_info.free_stack[1] = reinterpret_cast<void*>(4);
    block_info.free_stack[2] = reinterpret_cast<void*>(5);
    block_info.free_stack_size = 3;
    block_info.heap_type = kWinHeap;
    block_info.milliseconds_since_free = 100;

    crashdata::Value value;
    PopulateBlockInfo(runtime_->shadow(), block_info, true, &value, nullptr);
    std::string json;
    EXPECT_TRUE(crashdata::ToJson(true, &value, &json));
    const char kExpected[] =
        "{\n"
        "  \"header\": \"0x%08IX\",\n"
        "  \"user-size\": 8,\n"
        "  \"state\": \"quarantined (flooded)\",\n"
        "  \"heap-type\": \"WinHeap\",\n"
        "  \"analysis\": {\n"
        "    \"block\": \"corrupt\",\n"
        "    \"header\": \"corrupt\",\n"
        "    \"body\": \"(unknown)\",\n"
        "    \"trailer\": \"clean\"\n"
        "  },\n"
        "  \"alloc-thread-id\": 47,\n"
        "  \"alloc-stack\": [\n"
        "    \"0x00000001\", \"0x00000002\"\n"
        "  ],\n"
        "  \"free-thread-id\": 32,\n"
        "  \"free-stack\": [\n"
        "    \"0x00000003\", \"0x00000004\", \"0x00000005\"\n"
        "  ],\n"
        "  \"milliseconds-since-free\": 100,\n"
        "  \"contents\": {\n"
        "    \"type\": \"blob\",\n"
        "    \"address\": \"0x%08IX\",\n"
        "    \"size\": null,\n"
        "    \"data\": [\n"
        "      \"0x80\", \"0xCA\", \"0x00\", \"0x00\", \"0x10\", \"0x00\","
        " \"0x00\", \"0x00\",\n"
        "      \"0x00\", \"0x00\", \"0x00\", \"0x00\", \"0x00\", \"0x00\","
        " \"0x00\", \"0x00\",\n"
        "      \"0x00\", \"0x00\", \"0x00\", \"0x00\", \"0x00\", \"0x00\","
        " \"0x00\", \"0x00\",\n"
#ifdef _WIN64
        "      \"0x00\", \"0x00\", \"0x00\", \"0x00\", \"0x00\", \"0x00\","
        " \"0x00\", \"0x00\",\n"
#endif
        "      \"0xC3\", \"0xC3\", \"0xC3\", \"0xC3\", \"0x00\", \"0x00\","
        " \"0x00\", \"0x00\",\n"
#ifdef _WIN64
        "      \"0x00\", \"0x00\", \"0x00\", \"0x00\", \"0x00\", \"0x00\","
        " \"0x00\", \"0x00\",\n"
#endif
        "      \"0x00\", \"0x00\", \"0x00\", \"0x00\", \"0x00\", \"0x00\","
        " \"0x00\", \"0x00\",\n"
        "      \"0x00\", \"0x00\", \"0x00\", \"0x00\", \"0x00\", \"0x00\","
        " \"0x00\", \"0x00\"\n"
        "    ]\n"
        "  },\n"
        "  \"shadow\": {\n"
        "    \"type\": \"blob\",\n"
        "    \"address\": \"0x%08IX\",\n"
        "    \"size\": null,\n"
        "    \"data\": [\n"
#ifndef _WIN64
        "      \"0xE0\", \"0xFA\", \"0x00\", \"0xFB\", \"0xFB\", \"0xF4\"\n"
#else
        "      \"0xE0\", \"0xFA\", \"0xFA\", \"0x00\", \"0xFB\", \"0xFB\","
        " \"0xFB\", \"0xF4\"\n"
#endif
        "    ]\n"
        "  }\n"
        "}";
    std::string expected = base::StringPrintf(
        kExpected,
        block_info.header,
        block_info.header,
        BlockShadowAddress());
    EXPECT_EQ(expected, json);
  }
}

TEST_F(AsanErrorInfoTest, PopulateBlockInfoWithMemoryRanges) {
  AsanBlockInfo block_info = {};
  InitAsanBlockInfo(&block_info);

  {
    crashdata::Value info;
    PopulateBlockInfo(runtime_->shadow(), block_info, false, &info, nullptr);
    std::string json;
    EXPECT_TRUE(crashdata::ToJson(true, &info, &json));
    const char kExpected[] =
        "{\n"
        "  \"header\": \"0x%08IX\",\n"
        "  \"user-size\": 8,\n"
        "  \"state\": \"allocated\",\n"
        "  \"heap-type\": \"WinHeap\",\n"
        "  \"analysis\": {\n"
        "    \"block\": \"corrupt\",\n"
        "    \"header\": \"corrupt\",\n"
        "    \"body\": \"(unknown)\",\n"
        "    \"trailer\": \"clean\"\n"
        "  },\n"
        "  \"alloc-thread-id\": 47,\n"
        "  \"alloc-stack\": [\n"
        "    \"0x00000001\", \"0x00000002\"\n"
        "  ]\n"
        "}";
    std::string expected = base::StringPrintf(kExpected, block_info.header);
    EXPECT_EQ(expected, json);
  }

  {
    block_info.state = QUARANTINED_FLOODED_BLOCK;
    block_info.free_tid = 32;
    block_info.free_stack[0] = reinterpret_cast<void*>(3);
    block_info.free_stack[1] = reinterpret_cast<void*>(4);
    block_info.free_stack[2] = reinterpret_cast<void*>(5);
    block_info.free_stack_size = 3;
    block_info.heap_type = kWinHeap;
    block_info.milliseconds_since_free = 100;

    crashdata::Value value;
    MemoryRanges memory_ranges;
    PopulateBlockInfo(runtime_->shadow(), block_info, true, &value,
                      &memory_ranges);
    std::string json;
    EXPECT_TRUE(crashdata::ToJson(true, &value, &json));
    const char kExpected[] =
        "{\n"
        "  \"header\": \"0x%08IX\",\n"
        "  \"user-size\": 8,\n"
        "  \"state\": \"quarantined (flooded)\",\n"
        "  \"heap-type\": \"WinHeap\",\n"
        "  \"analysis\": {\n"
        "    \"block\": \"corrupt\",\n"
        "    \"header\": \"corrupt\",\n"
        "    \"body\": \"(unknown)\",\n"
        "    \"trailer\": \"clean\"\n"
        "  },\n"
        "  \"alloc-thread-id\": 47,\n"
        "  \"alloc-stack\": [\n"
        "    \"0x00000001\", \"0x00000002\"\n"
        "  ],\n"
        "  \"free-thread-id\": 32,\n"
        "  \"free-stack\": [\n"
        "    \"0x00000003\", \"0x00000004\", \"0x00000005\"\n"
        "  ],\n"
        "  \"milliseconds-since-free\": 100,\n"
        "  \"contents\": {\n"
        "    \"type\": \"blob\",\n"
        "    \"address\": \"0x%08zX\",\n"
#ifndef _WIN64
        "    \"size\": 48,\n"
#else
        "    \"size\": 64,\n"
#endif
        "    \"data\": null\n"
        "  },\n"
        "  \"shadow\": {\n"
        "    \"type\": \"blob\",\n"
        "    \"address\": \"0x%08zX\",\n"
#ifndef _WIN64
        "    \"size\": 6,\n"
#else
        "    \"size\": 8,\n"
#endif
        "    \"data\": null\n"
        "  }\n"
        "}";
    std::string expected = base::StringPrintf(
        kExpected, block_info.header, block_info.header, BlockShadowAddress());
    EXPECT_EQ(expected, json);

    ASSERT_EQ(2, memory_ranges.size());
    const char* kExpectedMemoryRangesAddresses[] = {
        reinterpret_cast<const char*>(block_info.header),
        reinterpret_cast<const char*>(BlockShadowAddress())};
#ifndef _WIN64
    size_t kExpectedMemoryRangesSize[] = {48, 6};
#else
    size_t kExpectedMemoryRangesSize[] = {64, 8};
#endif
    for (int i = 0; i < 2; i++) {
      EXPECT_EQ(kExpectedMemoryRangesAddresses[i], memory_ranges[i].first);
      EXPECT_EQ(kExpectedMemoryRangesSize[i], memory_ranges[i].second);
    }
  }
}

TEST_F(AsanErrorInfoTest, PopulateCorruptBlockRange) {
  AsanBlockInfo block_info = {};
  InitAsanBlockInfo(&block_info);

  AsanCorruptBlockRange range = {};
  range.address = reinterpret_cast<void*>(0xBAADF00D);
  range.length = 1024 * 1024;
  range.block_count = 100;
  range.block_info_count = 1;
  range.block_info = &block_info;

  crashdata::Value info;
  PopulateCorruptBlockRange(runtime_->shadow(), range, &info, nullptr);

  std::string json;
  EXPECT_TRUE(crashdata::ToJson(true, &info, &json));
  const char kExpected[] =
      "{\n"
      "  \"address\": \"0xBAADF00D\",\n"
      "  \"length\": 1048576,\n"
      "  \"block-count\": 100,\n"
      "  \"blocks\": [\n"
      "    {\n"
      "      \"header\": \"0x%08IX\",\n"
      "      \"user-size\": 8,\n"
      "      \"state\": \"allocated\",\n"
      "      \"heap-type\": \"WinHeap\",\n"
      "      \"analysis\": {\n"
      "        \"block\": \"corrupt\",\n"
      "        \"header\": \"corrupt\",\n"
      "        \"body\": \"(unknown)\",\n"
      "        \"trailer\": \"clean\"\n"
      "      },\n"
      "      \"alloc-thread-id\": 47,\n"
      "      \"alloc-stack\": [\n"
      "        \"0x00000001\", \"0x00000002\"\n"
      "      ]\n"
      "    }\n"
      "  ]\n"
      "}";
  std::string expected = base::StringPrintf(kExpected, block_info.header);
  EXPECT_EQ(expected, json);
}

TEST_F(AsanErrorInfoTest, PopulateErrorInfo) {
  AsanBlockInfo block_info = {};
  InitAsanBlockInfo(&block_info);

  AsanCorruptBlockRange range = {};
  range.address = reinterpret_cast<void*>(0xBAADF00D);
  range.length = 1024 * 1024;
  range.block_count = 100;
  range.block_info_count = 1;
  range.block_info = &block_info;

  // The 'location' address needs to be at a consistent place in system memory
  // so that shadow memory contents and page bits don't vary, otherwise the
  // test won't be deterministic.
  AsanErrorInfo error_info = {};
  error_info.location = reinterpret_cast<void*>(0x00001000);
  error_info.crash_stack_id = 1234;
  InitAsanBlockInfo(&error_info.block_info);
  error_info.error_type = WILD_ACCESS;
  error_info.access_mode = ASAN_READ_ACCESS;
  error_info.access_size = 4;
  ::strncpy(error_info.shadow_info,
            "shadow info!",
            sizeof(error_info.shadow_info));
  ::strncpy(error_info.shadow_memory,
            "shadow memory!",
            sizeof(error_info.shadow_memory));
  error_info.heap_is_corrupt = true;
  error_info.corrupt_range_count = 10;
  error_info.corrupt_block_count = 200;
  error_info.corrupt_ranges_reported = 1;
  error_info.corrupt_ranges = &range;

  ::common::SetDefaultAsanParameters(&error_info.asan_parameters);

  crashdata::Value info;
  PopulateErrorInfo(runtime_->shadow(), error_info, &info, nullptr);

  std::string json;
  EXPECT_TRUE(crashdata::ToJson(true, &info, &json));
  const char kExpected[] =
      "{\n"
      "  \"location\": \"0x00001000\",\n"
      "  \"crash-stack-id\": 1234,\n"
      "  \"block-info\": {\n"
      "    \"header\": \"0x%08IX\",\n"
      "    \"user-size\": 8,\n"
      "    \"state\": \"allocated\",\n"
      "    \"heap-type\": \"WinHeap\",\n"
      "    \"analysis\": {\n"
      "      \"block\": \"corrupt\",\n"
      "      \"header\": \"corrupt\",\n"
      "      \"body\": \"(unknown)\",\n"
      "      \"trailer\": \"clean\"\n"
      "    },\n"
      "    \"alloc-thread-id\": 47,\n"
      "    \"alloc-stack\": [\n"
      "      \"0x00000001\", \"0x00000002\"\n"
      "    ],\n"
      "    \"contents\": {\n"
      "      \"type\": \"blob\",\n"
      "      \"address\": \"0x%08zX\",\n"
      "      \"size\": null,\n"
      "      \"data\": [\n"
      "        \"0x80\", \"0xCA\", \"0x00\", \"0x00\", \"0x10\", \"0x00\","
      " \"0x00\", \"0x00\",\n"
      "        \"0x00\", \"0x00\", \"0x00\", \"0x00\", \"0x00\", \"0x00\","
      " \"0x00\", \"0x00\",\n"
      "        \"0x00\", \"0x00\", \"0x00\", \"0x00\", \"0x00\", \"0x00\","
      " \"0x00\", \"0x00\",\n"
#ifdef _WIN64
      "        \"0x00\", \"0x00\", \"0x00\", \"0x00\", \"0x00\", \"0x00\","
      " \"0x00\", \"0x00\",\n"
#endif
      "        \"0xC3\", \"0xC3\", \"0xC3\", \"0xC3\", \"0x00\", \"0x00\","
      " \"0x00\", \"0x00\",\n"
#ifdef _WIN64
      "        \"0x00\", \"0x00\", \"0x00\", \"0x00\", \"0x00\", \"0x00\","
      " \"0x00\", \"0x00\",\n"
#endif
      "        \"0x00\", \"0x00\", \"0x00\", \"0x00\", \"0x00\", \"0x00\","
      " \"0x00\", \"0x00\",\n"
      "        \"0x00\", \"0x00\", \"0x00\", \"0x00\", \"0x00\", \"0x00\","
      " \"0x00\", \"0x00\"\n"
      "      ]\n"
      "    },\n"
      "    \"shadow\": {\n"
      "      \"type\": \"blob\",\n"
      "      \"address\": \"0x%08zX\",\n"
      "      \"size\": null,\n"
      "      \"data\": [\n"
#ifndef _WIN64
      "        \"0xE0\", \"0xFA\", \"0x00\", \"0xFB\", \"0xFB\", \"0xF4\"\n"
#else
      "        \"0xE0\", \"0xFA\", \"0xFA\", \"0x00\", \"0xFB\", \"0xFB\","
      " \"0xFB\", \"0xF4\"\n"
#endif
      "      ]\n"
      "    }\n"
      "  },\n"
      "  \"error-type\": \"wild-access\",\n"
      "  \"access-mode\": \"read\",\n"
      "  \"access-size\": 4,\n"
      "  \"shadow-memory-index\": 512,\n"
      "  \"shadow-memory\": {\n"
      "    \"type\": \"blob\",\n"
      "    \"address\": \"0x%08zX\",\n"
      "    \"size\": null,\n"
      "    \"data\": [\n"
      "      \"0xF2\", \"0xF2\", \"0xF2\", \"0xF2\", \"0xF2\", \"0xF2\","
      " \"0xF2\", \"0xF2\",\n"
      "      \"0xF2\", \"0xF2\", \"0xF2\", \"0xF2\", \"0xF2\", \"0xF2\","
      " \"0xF2\", \"0xF2\",\n"
      "      \"0xF2\", \"0xF2\", \"0xF2\", \"0xF2\", \"0xF2\", \"0xF2\","
      " \"0xF2\", \"0xF2\",\n"
      "      \"0xF2\", \"0xF2\", \"0xF2\", \"0xF2\", \"0xF2\", \"0xF2\","
      " \"0xF2\", \"0xF2\",\n"
      "      \"0xF2\", \"0xF2\", \"0xF2\", \"0xF2\", \"0xF2\", \"0xF2\","
      " \"0xF2\", \"0xF2\",\n"
      "      \"0xF2\", \"0xF2\", \"0xF2\", \"0xF2\", \"0xF2\", \"0xF2\","
      " \"0xF2\", \"0xF2\",\n"
      "      \"0xF2\", \"0xF2\", \"0xF2\", \"0xF2\", \"0xF2\", \"0xF2\","
      " \"0xF2\", \"0xF2\",\n"
      "      \"0xF2\", \"0xF2\", \"0xF2\", \"0xF2\", \"0xF2\", \"0xF2\","
      " \"0xF2\", \"0xF2\"\n"
      "    ]\n"
      "  },\n"
      "  \"page-bits-index\": 0,\n"
      "  \"page-bits\": {\n"
      "    \"type\": \"blob\",\n"
      "    \"address\": \"0x%08zX\",\n"
      "    \"size\": null,\n"
      "    \"data\": [\n"
      "      \"0x00\", \"0x00\", \"0x00\"\n"
      "    ]\n"
      "  },\n"
      "  \"heap-is-corrupt\": 1,\n"
      "  \"corrupt-range-count\": 10,\n"
      "  \"corrupt-block-count\": 200,\n"
      "  \"corrupt-ranges\": [\n"
      "    {\n"
      "      \"address\": \"0xBAADF00D\",\n"
      "      \"length\": 1048576,\n"
      "      \"block-count\": 100,\n"
      "      \"blocks\": [\n"
      "        {\n"
      "          \"header\": \"0x%08IX\",\n"
      "          \"user-size\": 8,\n"
      "          \"state\": \"allocated\",\n"
      "          \"heap-type\": \"WinHeap\",\n"
      "          \"analysis\": {\n"
      "            \"block\": \"corrupt\",\n"
      "            \"header\": \"corrupt\",\n"
      "            \"body\": \"(unknown)\",\n"
      "            \"trailer\": \"clean\"\n"
      "          },\n"
      "          \"alloc-thread-id\": 47,\n"
      "          \"alloc-stack\": [\n"
      "            \"0x00000001\", \"0x00000002\"\n"
      "          ]\n"
      "        }\n"
      "      ]\n"
      "    }\n"
      "  ],\n"
      "  \"asan-parameters\": {\n"
      "    \"quarantine-size\": 16777216,\n"
      "    \"trailer-padding-size\": 0,\n"
      "    \"quarantine-block-size\": 4194304,\n"
      "    \"check-heap-on-failure\": 1,\n"
      "    \"enable-zebra-block-heap\": 0,\n"
      "    \"enable-large-block-heap\": 1,\n"
      "    \"enable-allocation-filter\": 0,\n"
      "    \"allocation-guard-rate\": 1.0000000000000000E+00,\n"
      "    \"zebra-block-heap-size\": 16777216,\n"
      "    \"zebra-block-heap-quarantine-ratio\": 2.5000000000000000E-01,\n"
      "    \"large-allocation-threshold\": 20480,\n"
      "    \"quarantine-flood-fill-rate\": 5.0000000000000000E-01\n"
      "  }\n"
      "}";
  AsanErrorShadowMemory shadow_memory = {};
  GetAsanErrorShadowMemory(runtime_->shadow(), error_info.location,
                           &shadow_memory);
  std::string expected =
      base::StringPrintf(kExpected, block_info.header, block_info.header,
                         BlockShadowAddress(), shadow_memory.address,
                         runtime_->shadow()->page_bits(), block_info.header);
  EXPECT_EQ(expected, json);
}

TEST_F(AsanErrorInfoTest, PopulateErrorInfoWithMemoryRanges) {
  AsanBlockInfo block_info = {};
  InitAsanBlockInfo(&block_info);

  AsanCorruptBlockRange range = {};
  range.address = reinterpret_cast<void*>(0xBAADF00D);
  range.length = 1024 * 1024;
  range.block_count = 100;
  range.block_info_count = 1;
  range.block_info = &block_info;

  // The 'location' address needs to be at a consistent place in system memory
  // so that shadow memory contents and page bits don't vary, otherwise the
  // test won't be deterministic.
  AsanErrorInfo error_info = {};
  error_info.location = reinterpret_cast<void*>(0x00001000);
  error_info.crash_stack_id = 1234;
  InitAsanBlockInfo(&error_info.block_info);
  error_info.error_type = WILD_ACCESS;
  error_info.access_mode = ASAN_READ_ACCESS;
  error_info.access_size = 4;
  ::strncpy(error_info.shadow_info, "shadow info!",
            sizeof(error_info.shadow_info));
  ::strncpy(error_info.shadow_memory, "shadow memory!",
            sizeof(error_info.shadow_memory));
  error_info.heap_is_corrupt = true;
  error_info.corrupt_range_count = 10;
  error_info.corrupt_block_count = 200;
  error_info.corrupt_ranges_reported = 1;
  error_info.corrupt_ranges = &range;

  ::common::SetDefaultAsanParameters(&error_info.asan_parameters);

  crashdata::Value info;
  MemoryRanges memory_ranges;
  PopulateErrorInfo(runtime_->shadow(), error_info, &info, &memory_ranges);

  std::string json;
  EXPECT_TRUE(crashdata::ToJson(true, &info, &json));
  const char kExpected[] =
      "{\n"
      "  \"location\": \"0x00001000\",\n"
      "  \"crash-stack-id\": 1234,\n"
      "  \"block-info\": {\n"
      "    \"header\": \"0x%08IX\",\n"
      "    \"user-size\": 8,\n"
      "    \"state\": \"allocated\",\n"
      "    \"heap-type\": \"WinHeap\",\n"
      "    \"analysis\": {\n"
      "      \"block\": \"corrupt\",\n"
      "      \"header\": \"corrupt\",\n"
      "      \"body\": \"(unknown)\",\n"
      "      \"trailer\": \"clean\"\n"
      "    },\n"
      "    \"alloc-thread-id\": 47,\n"
      "    \"alloc-stack\": [\n"
      "      \"0x00000001\", \"0x00000002\"\n"
      "    ],\n"
      "    \"contents\": {\n"
      "      \"type\": \"blob\",\n"
      "      \"address\": \"0x%08IX\",\n"
#ifndef _WIN64
      "      \"size\": 48,\n"
#else
      "      \"size\": 64,\n"
#endif
      "      \"data\": null\n"
      "    },\n"
      "    \"shadow\": {\n"
      "      \"type\": \"blob\",\n"
      "      \"address\": \"0x%08IX\",\n"
#ifndef _WIN64
      "      \"size\": 6,\n"
#else
      "      \"size\": 8,\n"
#endif
      "      \"data\": null\n"
      "    }\n"
      "  },\n"
      "  \"error-type\": \"wild-access\",\n"
      "  \"access-mode\": \"read\",\n"
      "  \"access-size\": 4,\n"
      "  \"shadow-memory-index\": 512,\n"
      "  \"shadow-memory\": {\n"
      "    \"type\": \"blob\",\n"
      "    \"address\": \"0x%08IX\",\n"
      "    \"size\": 64,\n"
      "    \"data\": null\n"
      "  },\n"
      "  \"page-bits-index\": 0,\n"
      "  \"page-bits\": {\n"
      "    \"type\": \"blob\",\n"
      "    \"address\": \"0x%08IX\",\n"
      "    \"size\": 3,\n"
      "    \"data\": null\n"
      "  },\n"
      "  \"heap-is-corrupt\": 1,\n"
      "  \"corrupt-range-count\": 10,\n"
      "  \"corrupt-block-count\": 200,\n"
      "  \"corrupt-ranges\": [\n"
      "    {\n"
      "      \"address\": \"0xBAADF00D\",\n"
      "      \"length\": 1048576,\n"
      "      \"block-count\": 100,\n"
      "      \"blocks\": [\n"
      "        {\n"
      "          \"header\": \"0x%08IX\",\n"
      "          \"user-size\": 8,\n"
      "          \"state\": \"allocated\",\n"
      "          \"heap-type\": \"WinHeap\",\n"
      "          \"analysis\": {\n"
      "            \"block\": \"corrupt\",\n"
      "            \"header\": \"corrupt\",\n"
      "            \"body\": \"(unknown)\",\n"
      "            \"trailer\": \"clean\"\n"
      "          },\n"
      "          \"alloc-thread-id\": 47,\n"
      "          \"alloc-stack\": [\n"
      "            \"0x00000001\", \"0x00000002\"\n"
      "          ]\n"
      "        }\n"
      "      ]\n"
      "    }\n"
      "  ],\n"
      "  \"asan-parameters\": {\n"
      "    \"quarantine-size\": 16777216,\n"
      "    \"trailer-padding-size\": 0,\n"
      "    \"quarantine-block-size\": 4194304,\n"
      "    \"check-heap-on-failure\": 1,\n"
      "    \"enable-zebra-block-heap\": 0,\n"
      "    \"enable-large-block-heap\": 1,\n"
      "    \"enable-allocation-filter\": 0,\n"
      "    \"allocation-guard-rate\": 1.0000000000000000E+00,\n"
      "    \"zebra-block-heap-size\": 16777216,\n"
      "    \"zebra-block-heap-quarantine-ratio\": 2.5000000000000000E-01,\n"
      "    \"large-allocation-threshold\": 20480,\n"
      "    \"quarantine-flood-fill-rate\": 5.0000000000000000E-01\n"
      "  }\n"
      "}";
  AsanErrorShadowMemory shadow_memory = {};
  GetAsanErrorShadowMemory(runtime_->shadow(), error_info.location,
                           &shadow_memory);
  std::string expected =
      base::StringPrintf(kExpected, block_info.header, block_info.header,
                         BlockShadowAddress(), shadow_memory.address,
                         runtime_->shadow()->page_bits(), block_info.header);
  EXPECT_EQ(expected, json);

  // Check memory ranges.
  ASSERT_EQ(4, memory_ranges.size());
  const char* kExpectedMemoryRangesAddresses[] = {
      reinterpret_cast<const char*>(block_info.header),
      reinterpret_cast<const char*>(BlockShadowAddress()),
      reinterpret_cast<const char*>(shadow_memory.address),
      reinterpret_cast<const char*>(runtime_->shadow()->page_bits())};
#ifndef _WIN64
  size_t kExpectedMemoryRangesSize[] = {48, 6, 64, 3};
#else
  size_t kExpectedMemoryRangesSize[] = {64, 8, 64, 3};
#endif
  for (int i = 0; i < memory_ranges.size(); i++) {
    EXPECT_EQ(kExpectedMemoryRangesAddresses[i], memory_ranges[i].first)
        << " Where i = " << i;
    EXPECT_EQ(kExpectedMemoryRangesSize[i], memory_ranges[i].second)
        << " Where i = " << i;
  }
}

TEST_F(AsanErrorInfoTest, CrashdataProtobufToErrorInfo) {
  AsanBlockInfo block_info = {};
  InitAsanBlockInfo(&block_info);

  block_info.state = QUARANTINED_FLOODED_BLOCK;
  block_info.free_tid = 32;
  block_info.free_stack[0] = reinterpret_cast<void*>(3);
  block_info.free_stack[1] = reinterpret_cast<void*>(4);
  block_info.free_stack[2] = reinterpret_cast<void*>(5);
  block_info.free_stack_size = 3;
  block_info.heap_type = kWinHeap;
  block_info.milliseconds_since_free = 100;

  crashdata::Value value;
  PopulateBlockInfo(runtime_->shadow(), block_info, true, &value, nullptr);

  AsanErrorInfo error_info_from_proto = {};
  CrashdataProtobufToErrorInfo(value, &error_info_from_proto);

  EXPECT_EQ(block_info.header, error_info_from_proto.block_info.header);
  EXPECT_EQ(block_info.user_size, error_info_from_proto.block_info.user_size);
  EXPECT_EQ(block_info.state, error_info_from_proto.block_info.state);
  EXPECT_EQ(block_info.heap_type, error_info_from_proto.block_info.heap_type);
  EXPECT_EQ(block_info.alloc_tid, error_info_from_proto.block_info.alloc_tid);
  EXPECT_EQ(block_info.free_tid, error_info_from_proto.block_info.free_tid);
  EXPECT_EQ(block_info.milliseconds_since_free,
            error_info_from_proto.block_info.milliseconds_since_free);
}

}  // namespace asan
}  // namespace agent
