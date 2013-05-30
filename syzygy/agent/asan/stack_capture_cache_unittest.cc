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

#include "syzygy/agent/asan/stack_capture_cache.h"

#include "base/memory/scoped_ptr.h"
#include "gtest/gtest.h"
#include "syzygy/agent/asan/asan_logger.h"

namespace agent {
namespace asan {

namespace {

class TestStackCaptureCache : public StackCaptureCache {
 public:
  explicit TestStackCaptureCache(AsanLogger* logger)
      : StackCaptureCache(logger) {
  }
  TestStackCaptureCache(AsanLogger* logger, size_t max_num_frames)
      : StackCaptureCache(logger, max_num_frames) {
  }

  using StackCaptureCache::Statistics;

  void GetStatistics(Statistics* s) {
    DCHECK(s != NULL);
    base::AutoLock auto_lock(lock_);
    GetStatisticsUnlocked(s);
  }
};

class StackCaptureCacheTest : public testing::Test {
 public:
  void SetUp() OVERRIDE {
    // Setup the "global" state.
    StackCapture::Init();
    StackCaptureCache::Init();
  }
};

}  // namespace

TEST_F(StackCaptureCacheTest, CachePageTest) {
  static const size_t kFrameCounts[] =
      { 5, 10, 30, StackCapture::kMaxNumFrames };

  for (size_t i = 0; i < arraysize(kFrameCounts); ++i) {
    size_t max_num_frames = kFrameCounts[i];
    scoped_ptr<TestStackCaptureCache::CachePage> page(
        new TestStackCaptureCache::CachePage(NULL));

    // Ensure that returning a page works.
    EXPECT_EQ(0u, page->bytes_used());
    StackCapture* s1 = page->GetNextStackCapture(max_num_frames);
    ASSERT_TRUE(s1 != NULL);
    EXPECT_EQ(max_num_frames, s1->max_num_frames());
    EXPECT_EQ(s1->Size(), page->bytes_used());
    page->ReleaseStackCapture(s1);
    EXPECT_EQ(0u, page->bytes_used());

    // Reallocating should get us the same page as the one we just returned.
    StackCapture* s2 = page->GetNextStackCapture(max_num_frames);
    EXPECT_EQ(s1, s2);

    // Figure out how many more allocations the page should give us.
    size_t bytes_left = StackCaptureCache::kCachePageSize - page->bytes_used();
    size_t allocations_left = bytes_left / s2->Size();

    // Ensure we get exactly that many.
    for (size_t j = 0; j < allocations_left; ++j) {
      EXPECT_TRUE(page->GetNextStackCapture(max_num_frames) != NULL);
    }

    // And no more than that.
    EXPECT_TRUE(page->GetNextStackCapture(max_num_frames) == NULL);
  }
}

TEST_F(StackCaptureCacheTest, SaveStackTrace) {
  AsanLogger logger;
  TestStackCaptureCache cache(&logger);
  EXPECT_EQ(StackCapture::kMaxNumFrames, cache.max_num_frames());

  // Capture a stack trace.
  ULONG stack_id = 0;
  void* frames[StackCapture::kMaxNumFrames] = { 0 };
  size_t num_frames = ::CaptureStackBackTrace(
      0, StackCapture::kMaxNumFrames, frames, &stack_id);

  // We should be able to save the captures stack trace.
  const StackCapture* s1 = cache.SaveStackTrace(stack_id, frames, num_frames);
  ASSERT_TRUE(s1 != NULL);
  EXPECT_EQ(StackCapture::kMaxNumFrames, s1->max_num_frames());
  EXPECT_EQ(sizeof(StackCapture), s1->Size());

  // We should get a pointer to the initial stack capture object if we attempt
  // to save the same trace again.
  const StackCapture* s2 = cache.SaveStackTrace(stack_id, frames, num_frames);
  EXPECT_EQ(s1, s2);

  // Capture a new stack trace.
  num_frames = ::CaptureStackBackTrace(
      0, StackCapture::kMaxNumFrames, frames, &stack_id);

  // We should get a pointer to a new stack capture object when we attempt
  // to save a different trace.
  const StackCapture* s3 = cache.SaveStackTrace(stack_id, frames, num_frames);
  EXPECT_NE(s1, s3);
  EXPECT_EQ(StackCapture::kMaxNumFrames, s3->max_num_frames());
  EXPECT_EQ(sizeof(StackCapture), s1->Size());
}

TEST_F(StackCaptureCacheTest, RestrictedStackTraces) {
  AsanLogger logger;
  TestStackCaptureCache cache(&logger, 20);
  EXPECT_EQ(20u, cache.max_num_frames());

  // Capture a stack trace.
  ULONG stack_id = 0;
  void* frames[StackCapture::kMaxNumFrames] = { 0 };
  size_t num_frames = ::CaptureStackBackTrace(
      0, StackCapture::kMaxNumFrames, frames, &stack_id);

  // We should be able to save the captures stack trace.
  const StackCapture* s1 = cache.SaveStackTrace(stack_id, frames, num_frames);
  ASSERT_TRUE(s1 != NULL);
  EXPECT_EQ(20u, s1->max_num_frames());
  EXPECT_GT(sizeof(StackCapture), s1->Size());

  // We should get a pointer to the initial stack capture object if we attempt
  // to save the same trace again.
  const StackCapture* s2 = cache.SaveStackTrace(stack_id, frames, num_frames);
  EXPECT_EQ(s1, s2);

  // Capture a new stack trace.
  num_frames = ::CaptureStackBackTrace(
      0, StackCapture::kMaxNumFrames, frames, &stack_id);

  // We should get a pointer to a new stack capture object when we attempt
  // to save a different trace.
  const StackCapture* s3 = cache.SaveStackTrace(stack_id, frames, num_frames);
  EXPECT_NE(s1, s3);
  EXPECT_EQ(20u, s1->max_num_frames());
  EXPECT_GT(sizeof(StackCapture), s1->Size());
}

TEST_F(StackCaptureCacheTest, MaxNumFrames) {
  AsanLogger logger;
  TestStackCaptureCache cache(&logger);
  size_t max_num_frames = cache.max_num_frames() + 1;
  cache.set_max_num_frames(max_num_frames);
  ASSERT_EQ(max_num_frames, cache.max_num_frames());
}

TEST_F(StackCaptureCacheTest, Statistics) {
  AsanLogger logger;
  TestStackCaptureCache cache(&logger);
  TestStackCaptureCache::Statistics s = {};

  cache.GetStatistics(&s);
  EXPECT_EQ(0u, s.cached);
  EXPECT_EQ(0u, s.saturated);
  EXPECT_EQ(0u, s.unreferenced);
  EXPECT_EQ(0u, s.requested);
  EXPECT_EQ(0u, s.allocated);
  EXPECT_EQ(0u, s.references);

  // Grab a stack capture and insert it.
  StackCapture stack_capture;
  stack_capture.InitFromStack();
  const StackCapture* s1 = cache.SaveStackTrace(stack_capture);
  ASSERT_TRUE(s1 != NULL);
  cache.GetStatistics(&s);
  EXPECT_EQ(1u, s.cached);
  EXPECT_EQ(0u, s.saturated);
  EXPECT_EQ(0u, s.unreferenced);
  EXPECT_EQ(1u, s.requested);
  EXPECT_EQ(1u, s.allocated);
  EXPECT_EQ(1u, s.references);

  // Reinsert the same stack. We expect to get the same pointer back.
  const StackCapture* s2 = cache.SaveStackTrace(stack_capture);
  ASSERT_TRUE(s2 != NULL);
  cache.GetStatistics(&s);
  EXPECT_EQ(s1, s2);
  EXPECT_EQ(1u, s.cached);
  EXPECT_EQ(0u, s.saturated);
  EXPECT_EQ(0u, s.unreferenced);
  EXPECT_EQ(2u, s.requested);
  EXPECT_EQ(1u, s.allocated);
  EXPECT_EQ(2u, s.references);

  // Insert a new stack.
  stack_capture.InitFromStack();
  const StackCapture* s3 = cache.SaveStackTrace(stack_capture);
  ASSERT_TRUE(s3 != NULL);
  cache.GetStatistics(&s);
  EXPECT_EQ(2u, s.cached);
  EXPECT_EQ(0u, s.saturated);
  EXPECT_EQ(0u, s.unreferenced);
  EXPECT_EQ(3u, s.requested);
  EXPECT_EQ(2u, s.allocated);
  EXPECT_EQ(3u, s.references);

  // Return the first stack. This should decrement the total reference count.
  cache.ReleaseStackTrace(s1);
  s1 = NULL;
  cache.GetStatistics(&s);
  EXPECT_EQ(2u, s.cached);
  EXPECT_EQ(0u, s.saturated);
  EXPECT_EQ(0u, s.unreferenced);
  EXPECT_EQ(3u, s.requested);
  EXPECT_EQ(2u, s.allocated);
  EXPECT_EQ(2u, s.references);

  // Return the 2nd stack. This should decrement the reference count, and leave
  // a stack unreferenced.
  cache.ReleaseStackTrace(s2);
  s2 = NULL;
  cache.GetStatistics(&s);
  EXPECT_EQ(2u, s.cached);
  EXPECT_EQ(0u, s.saturated);
  EXPECT_EQ(1u, s.unreferenced);
  EXPECT_EQ(3u, s.requested);
  EXPECT_EQ(2u, s.allocated);
  EXPECT_EQ(1u, s.references);

  // Insert the 3rd stack over and over again. We'll eventually saturate the
  // reference counter and it'll be a permanent part of the cache.
  size_t kEnoughTimesToSaturate = StackCapture::kMaxRefCount;
  for (size_t i = 0; i < kEnoughTimesToSaturate; ++i) {
    const StackCapture* s4 = cache.SaveStackTrace(stack_capture);
    ASSERT_TRUE(s4 != NULL);
    EXPECT_EQ(s3, s4);
  }
  cache.GetStatistics(&s);
  EXPECT_EQ(2u, s.cached);
  EXPECT_EQ(1u, s.saturated);
  EXPECT_EQ(1u, s.unreferenced);
  EXPECT_EQ(3u + kEnoughTimesToSaturate, s.requested);
  EXPECT_EQ(2u, s.allocated);
  EXPECT_EQ(1u + kEnoughTimesToSaturate, s.references);

  // Return the 3rd stack as many times as it was referenced. It should still
  // be saturated.
  for (size_t i = 0; i < kEnoughTimesToSaturate + 1; ++i)
    cache.ReleaseStackTrace(s3);
  s3 = NULL;
  cache.GetStatistics(&s);
  EXPECT_EQ(2u, s.cached);
  EXPECT_EQ(1u, s.saturated);
  EXPECT_EQ(1u, s.unreferenced);
  EXPECT_EQ(3u + kEnoughTimesToSaturate, s.requested);
  EXPECT_EQ(2u, s.allocated);
  EXPECT_EQ(0u, s.references);
}

}  // namespace asan
}  // namespace agent
