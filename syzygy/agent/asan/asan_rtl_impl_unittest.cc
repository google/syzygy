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

#include "syzygy/agent/asan/asan_rtl_impl.h"

#include <windows.h>  // NOLINT

#include "base/compiler_specific.h"
#include "base/environment.h"
#include "base/file_util.h"
#include "base/logging.h"
#include "base/rand_util.h"
#include "base/scoped_temp_dir.h"
#include "base/string_number_conversions.h"
#include "base/utf_string_conversions.h"
#include "base/debug/debugger.h"
#include "gtest/gtest.h"
#include "syzygy/agent/asan/asan_shadow.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/trace/logger/logger.h"
#include "syzygy/trace/logger/logger_rpc_impl.h"
#include "syzygy/trace/protocol/call_trace_defs.h"

class AsanRtlImplTest : public testing::Test {
 public:
  AsanRtlImplTest() : heap_(NULL) {
  }

  void SetUp() OVERRIDE {
    heap_ = asan_HeapCreate(0, 0, 0);
    ASSERT_TRUE(heap_ != NULL);
  }

  void TearDown() OVERRIDE {
    if (heap_ != NULL) {
      asan_HeapDestroy(heap_);
      heap_ = NULL;
    }
  }

 protected:
  // Arbitrary constant for all size limit.
  static const size_t kMaxAllocSize = 134584;

  // Scratch heap handle valid from SetUp to TearDown.
  HANDLE heap_;
};

TEST_F(AsanRtlImplTest, CreateDestroy) {
  HANDLE heap = asan_HeapCreate(0, 0, 0);
  ASSERT_TRUE(heap != NULL);
  ASSERT_TRUE(asan_HeapDestroy(heap));
}

TEST_F(AsanRtlImplTest, Alloc) {
  for (size_t size = 10; size < kMaxAllocSize; size = size * 5 + 123) {
    void* mem = asan_HeapAlloc(heap_, 0, size);
    ASSERT_TRUE(mem != NULL);
    memset(mem, '\0', size);

    size_t new_size = size;
    while (new_size == size)
      new_size = base::RandInt(size / 2, size * 2);

    void* new_mem = asan_HeapReAlloc(heap_, 0, mem, new_size);
    ASSERT_TRUE(new_mem != NULL);
    ASSERT_NE(mem, new_mem);

    ASSERT_TRUE(asan_HeapFree(heap_, 0, new_mem));
  }
}

TEST_F(AsanRtlImplTest, Size) {
  for (size_t size = 10; size < kMaxAllocSize; size = size * 5 + 123) {
    void* mem = asan_HeapAlloc(heap_, 0, size);
    ASSERT_TRUE(mem != NULL);
    ASSERT_EQ(size, asan_HeapSize(heap_, 0, mem));
    ASSERT_TRUE(asan_HeapFree(heap_, 0, mem));
  }
}

TEST_F(AsanRtlImplTest, Validate) {
  for (size_t size = 10; size < kMaxAllocSize; size = size * 5 + 123) {
    void* mem = asan_HeapAlloc(heap_, 0, size);
    ASSERT_TRUE(mem != NULL);
    ASSERT_TRUE(asan_HeapValidate(heap_, 0, mem));
    ASSERT_TRUE(asan_HeapFree(heap_, 0, mem));
  }
}

TEST_F(AsanRtlImplTest, Compact) {
  // Compact should return a non-zero size.
  ASSERT_LT(0U, asan_HeapCompact(heap_, 0));

  // TODO(siggi): It may not be possible to allocate the size returned due
  //     to padding - fix and test.
}

TEST_F(AsanRtlImplTest, LockUnlock) {
  // We can't really test these, aside from not crashing.
  ASSERT_TRUE(asan_HeapLock(heap_));
  ASSERT_TRUE(asan_HeapUnlock(heap_));
}

TEST_F(AsanRtlImplTest, Walk) {
  // We assume at least two entries to walk through.
  PROCESS_HEAP_ENTRY entry = {};
  ASSERT_TRUE(asan_HeapWalk(heap_, &entry));
  ASSERT_TRUE(asan_HeapWalk(heap_, &entry));
}

TEST_F(AsanRtlImplTest, SetQueryInformation) {
  ULONG compat_flag = -1;
  unsigned long ret = 0;
  // Get the current value of the compatibility flag.
  ASSERT_TRUE(
      asan_HeapQueryInformation(heap_, HeapCompatibilityInformation,
                                &compat_flag, sizeof(compat_flag), &ret));
  ASSERT_EQ(sizeof(compat_flag), ret);
  ASSERT_TRUE(compat_flag != -1);

  // Put the heap in LFH, which should always succeed, except when a debugger
  // is attached. When a debugger is attached, the heap is wedged in certain
  // debug settings.
  if (base::debug::BeingDebugged()) {
    LOG(WARNING) << "Can't test HeapProxy::SetInformation under debugger.";
    return;
  }

  compat_flag = 2;
  ASSERT_TRUE(
      asan_HeapSetInformation(heap_, HeapCompatibilityInformation,
                              &compat_flag, sizeof(compat_flag)));
}

TEST_F(AsanRtlImplTest, SetInformationWithNullHeapPtr) {
  // The documentation of HeapSetInformation specify that the heap handle is
  // optionnal.
  ASSERT_TRUE(
      asan_HeapSetInformation(NULL, HeapEnableTerminationOnCorruption,
                              NULL, 0));
}
