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

#include "syzygy/agent/asan/windows_heap_adapter.h"

#include "base/compiler_specific.h"
#include "base/rand_util.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/agent/asan/heap_manager.h"

namespace agent {
namespace asan {

namespace {

using testing::Return;
using testing::_;

// A mock heap manager to make sure that the calls to the Windows heap adapter
// are correctly forwarded.
class LenientMockHeapManager : public HeapManagerInterface {
 public:
  MOCK_METHOD0(CreateHeap, HeapId());
  MOCK_METHOD1(DestroyHeap, bool(HeapId));
  MOCK_METHOD2(Size, size_t(HeapId, const void*));
  MOCK_METHOD2(Allocate, void*(HeapId, size_t));
  MOCK_METHOD2(Free, bool(HeapId, void*));
  MOCK_METHOD1(Lock, void(HeapId));
  MOCK_METHOD1(Unlock, void(HeapId));
};

typedef testing::StrictMock<LenientMockHeapManager> MockHeapManager;

class WindowsHeapAdapterTest : public testing::Test {
 public:
  WindowsHeapAdapterTest() { }

  virtual void SetUp() OVERRIDE {
    WindowsHeapAdapter::SetUp(&mock_heap_manager_);
  }

  virtual void TearDown() OVERRIDE {
    WindowsHeapAdapter::TearDown();
  }

 protected:
  const HeapManagerInterface::HeapId kFakeHeapId =
      static_cast<HeapManagerInterface::HeapId>(0XAABBCCDD);

  // The mock heap manager we delegate to.
  MockHeapManager mock_heap_manager_;
};

}  // namespace

TEST_F(WindowsHeapAdapterTest, HeapCreate) {
  EXPECT_CALL(mock_heap_manager_, CreateHeap()).WillOnce(Return(kFakeHeapId));
  EXPECT_EQ(reinterpret_cast<HANDLE>(kFakeHeapId),
            WindowsHeapAdapter::HeapCreate(0, 0, 0));
}

TEST_F(WindowsHeapAdapterTest, HeapDestroy) {
  EXPECT_CALL(mock_heap_manager_,
              DestroyHeap(kFakeHeapId)).WillOnce(Return(true));
  EXPECT_TRUE(
      WindowsHeapAdapter::HeapDestroy(reinterpret_cast<HANDLE>(kFakeHeapId)));
}

TEST_F(WindowsHeapAdapterTest, HeapAlloc) {
  const size_t kAllocSize = 100;
  void* kFakeAlloc = reinterpret_cast<void*>(0x12345678);
  EXPECT_CALL(mock_heap_manager_, Allocate(kFakeHeapId, kAllocSize)).WillOnce(
      Return(kFakeAlloc));
  void* alloc =
      WindowsHeapAdapter::HeapAlloc(reinterpret_cast<HANDLE>(kFakeHeapId),
                                    0,
                                    kAllocSize);
  ASSERT_EQ(kFakeAlloc, alloc);
}

TEST_F(WindowsHeapAdapterTest, HeapAllocWithZeroMemoryFlag) {
  const size_t kAllocSize = 10;
  uint8 kDummyBuffer[kAllocSize];

  // Fill the array with a non-zero value.
  ::memset(kDummyBuffer, 0xFF, kAllocSize);

  EXPECT_CALL(mock_heap_manager_, Allocate(kFakeHeapId, kAllocSize)).WillOnce(
      Return(reinterpret_cast<void*>(kDummyBuffer)));
  void* alloc =
      WindowsHeapAdapter::HeapAlloc(reinterpret_cast<HANDLE>(kFakeHeapId),
                                    HEAP_ZERO_MEMORY,
                                    kAllocSize);
  EXPECT_EQ(reinterpret_cast<void*>(kDummyBuffer), alloc);
  for (size_t i = 0; i < kAllocSize; ++i)
    EXPECT_EQ(0, kDummyBuffer[i]);
}

TEST_F(WindowsHeapAdapterTest, HeapReAlloc) {
  void* kFakeAlloc = reinterpret_cast<void*>(0x12345678);
  void* kFakeReAlloc = reinterpret_cast<void*>(0x87654321);
  // A successful call to WindowsHeapAdapter::HeapReAlloc should end up calling
  // HeapManagerInterface::Allocate, HeapManagerInterface::Size and
  // HeapManagerInterface::Free.
  const size_t kReAllocSize = 200;
  EXPECT_CALL(mock_heap_manager_, Allocate(kFakeHeapId, kReAllocSize)).WillOnce(
      Return(kFakeReAlloc));
  EXPECT_CALL(mock_heap_manager_, Free(kFakeHeapId, kFakeAlloc)).WillOnce(
      Return(true));
  // Return a size of 0 to avoid trying to copy the old buffer into the new one.
  EXPECT_CALL(mock_heap_manager_, Size(kFakeHeapId, kFakeAlloc)).WillOnce(
      Return(0));
  EXPECT_EQ(kFakeReAlloc,
      WindowsHeapAdapter::HeapReAlloc(reinterpret_cast<HANDLE>(kFakeHeapId),
                                      0,
                                      kFakeAlloc,
                                      kReAllocSize));
}

TEST_F(WindowsHeapAdapterTest, HeapReAllocWithNullSrcPointer) {
  const size_t kReAllocSize = 10;
  void* kFakeReAlloc = reinterpret_cast<void*>(0x87654321);
  EXPECT_CALL(mock_heap_manager_, Allocate(kFakeHeapId, kReAllocSize)).WillOnce(
      Return(kFakeReAlloc));
  EXPECT_EQ(kFakeReAlloc,
      WindowsHeapAdapter::HeapReAlloc(reinterpret_cast<HANDLE>(kFakeHeapId),
                                      0,
                                      NULL,
                                      kReAllocSize));
}

TEST_F(WindowsHeapAdapterTest, HeapReAllocFailForInPlaceReallocations) {
  const size_t kReAllocSize = 10;
  EXPECT_CALL(mock_heap_manager_, Allocate(_, _)).Times(0);
  EXPECT_EQ(NULL,
      WindowsHeapAdapter::HeapReAlloc(reinterpret_cast<HANDLE>(kFakeHeapId),
                                      HEAP_REALLOC_IN_PLACE_ONLY,
                                      NULL,
                                      kReAllocSize));
}

TEST_F(WindowsHeapAdapterTest, HeapReAllocFailOnOOM) {
  const size_t kReAllocSize = 10;
  // Return NULL in the internal call that allocates the new buffer.
  EXPECT_CALL(mock_heap_manager_, Allocate(kFakeHeapId, kReAllocSize)).WillOnce(
      Return(static_cast<void*>(NULL)));
  EXPECT_EQ(NULL,
      WindowsHeapAdapter::HeapReAlloc(reinterpret_cast<HANDLE>(kFakeHeapId),
                                      0,
                                      NULL,
                                      kReAllocSize));
}

TEST_F(WindowsHeapAdapterTest, HeapReallocCopyData) {
  const size_t kAllocSize = 10;
  const size_t kReAllocSize = kAllocSize * 2;
  uint8 kDummyBuffer1[kAllocSize];
  uint8 kDummyBuffer2[kReAllocSize];

  EXPECT_CALL(mock_heap_manager_, Allocate(kFakeHeapId, kAllocSize)).WillOnce(
      Return(reinterpret_cast<void*>(kDummyBuffer1)));
  void* alloc =
      WindowsHeapAdapter::HeapAlloc(reinterpret_cast<HANDLE>(kFakeHeapId),
                                    0,
                                    kAllocSize);
  EXPECT_EQ(reinterpret_cast<void*>(kDummyBuffer1), alloc);
  base::RandBytes(alloc, kAllocSize);

  EXPECT_CALL(mock_heap_manager_, Allocate(kFakeHeapId, kReAllocSize)).WillOnce(
      Return(reinterpret_cast<void*>(kDummyBuffer2)));
  EXPECT_CALL(mock_heap_manager_, Free(kFakeHeapId, alloc)).WillOnce(
      Return(true));
  EXPECT_CALL(mock_heap_manager_, Size(kFakeHeapId, alloc)).WillOnce(
      Return(kAllocSize));
  void* re_alloc =
      WindowsHeapAdapter::HeapReAlloc(reinterpret_cast<HANDLE>(kFakeHeapId),
                                      0,
                                      alloc,
                                      kReAllocSize);

  EXPECT_EQ(0, ::memcmp(alloc, re_alloc, kAllocSize));
}

TEST_F(WindowsHeapAdapterTest, HeapFree) {
  void* kFakeAlloc = reinterpret_cast<void*>(0x12345678);
  EXPECT_CALL(mock_heap_manager_, Free(kFakeHeapId, kFakeAlloc)).WillOnce(
      Return(true));
  ASSERT_TRUE(
      WindowsHeapAdapter::HeapFree(reinterpret_cast<HANDLE>(kFakeHeapId),
                                   0,
                                   kFakeAlloc));
}

TEST_F(WindowsHeapAdapterTest, HeapSize) {
  const size_t kAllocSize = 100;
  const void* kFakeAlloc = reinterpret_cast<const void*>(0x12345678);
  EXPECT_CALL(mock_heap_manager_, Size(kFakeHeapId, kFakeAlloc)).WillOnce(
      Return(kAllocSize));
  EXPECT_EQ(kAllocSize,
            WindowsHeapAdapter::HeapSize(reinterpret_cast<HANDLE>(kFakeHeapId),
                                         0,
                                         kFakeAlloc));
}

TEST_F(WindowsHeapAdapterTest, HeapLock) {
  EXPECT_CALL(mock_heap_manager_, Lock(kFakeHeapId)).Times(1);
  WindowsHeapAdapter::HeapLock(reinterpret_cast<HANDLE>(kFakeHeapId));
}

TEST_F(WindowsHeapAdapterTest, HeapUnlock) {
  EXPECT_CALL(mock_heap_manager_, Unlock(kFakeHeapId)).Times(1);
  WindowsHeapAdapter::HeapUnlock(reinterpret_cast<HANDLE>(kFakeHeapId));
}

}  // namespace asan
}  // namespace agent
