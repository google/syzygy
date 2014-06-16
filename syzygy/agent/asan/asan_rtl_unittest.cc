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

#include <windows.h>

#include "gtest/gtest.h"
#include "syzygy/agent/asan/asan_heap_checker.h"
#include "syzygy/agent/asan/asan_rtl_impl.h"
#include "syzygy/agent/asan/asan_runtime.h"
#include "syzygy/agent/asan/unittest_util.h"

namespace agent {
namespace asan {

namespace {

typedef ScopedVector<AsanBlockInfo> AsanBlockInfoVector;
typedef std::pair<AsanCorruptBlockRange, AsanBlockInfoVector> CorruptRangeInfo;
typedef std::vector<CorruptRangeInfo> CorruptRangeVector;
using testing::ScopedASanAlloc;

// The access check function invoked by the below.
FARPROC check_access_fn = NULL;
// A flag used in asan callback to ensure that a memory error has been detected.
bool memory_error_detected = false;
// A pointer to a context to ensure that we're able to restore the context when
// an asan error is found.
CONTEXT* context_before_hook = NULL;
// This will be used in the asan callback to ensure that we detect the right
// error.
HeapProxy::BadAccessKind expected_error_type = HeapProxy::UNKNOWN_BAD_ACCESS;
// A flag to override the direction flag on special instruction checker.
bool direction_flag_forward = true;
// An arbitrary size for the buffer we allocate in the different unittests.
const size_t kAllocSize = 13;
// The information about the last error.
AsanErrorInfo last_error_info = {};
CorruptRangeVector last_corrupt_ranges;

class AsanRtlTest : public testing::TestAsanRtl {
 public:
  AsanRtlTest() : memory_src_(NULL), memory_dst_(NULL), memory_length_(0),
      memory_size_(0) { }

  void SetUp() OVERRIDE {
    testing::TestAsanRtl::SetUp();
    memory_error_detected = false;
    last_corrupt_ranges.clear();
  }
 protected:
  void AllocMemoryBuffers(int32 length, int32 element_size);
  void FreeMemoryBuffers();

  // Memory buffers used to test special instructions.
  void* memory_src_;
  void* memory_dst_;
  int32 memory_length_;
  int32 memory_size_;
};

void AsanRtlTest::AllocMemoryBuffers(int32 length, int32 element_size) {
  ASSERT_EQ(reinterpret_cast<void*>(NULL), memory_src_);
  ASSERT_EQ(reinterpret_cast<void*>(NULL), memory_dst_);
  ASSERT_EQ(0, memory_length_);
  ASSERT_EQ(0, memory_size_);

  // Keep track of memory size.
  memory_length_ = length;
  memory_size_ = length * element_size;

  // Allocate memory space.
  memory_src_ = HeapAllocFunction(heap_, 0, memory_size_);
  ASSERT_TRUE(memory_src_ != NULL);
  memory_dst_ = HeapAllocFunction(heap_, 0, memory_size_);
  ASSERT_TRUE(memory_dst_ != NULL);

  // Initialize memory.
  memset(memory_src_, 0, memory_size_);
  memset(memory_dst_, 0, memory_size_);
}

void AsanRtlTest::FreeMemoryBuffers() {
  ASSERT_NE(reinterpret_cast<void*>(NULL), memory_src_);
  ASSERT_NE(reinterpret_cast<void*>(NULL), memory_dst_);

  ASSERT_TRUE(HeapFreeFunction(heap_, 0, memory_src_));
  ASSERT_TRUE(HeapFreeFunction(heap_, 0, memory_dst_));

  memory_length_ = 0;
  memory_size_ = 0;
  memory_src_ = NULL;
  memory_dst_ = NULL;
}

#define RTL_CAPTURE_CONTEXT(context, expected_eip) {  \
  /* Save caller save registers. */  \
  __asm push eax  \
  __asm push ecx  \
  __asm push edx  \
  /* Call Capture context. */  \
  __asm push context  \
  __asm call dword ptr[RtlCaptureContext]  \
  /* Restore caller save registers. */  \
  __asm pop edx  \
  __asm pop ecx  \
  __asm pop eax  \
  /* Restore registers which are stomped by RtlCaptureContext. */  \
  __asm push eax  \
  __asm pushfd  \
  __asm mov eax, context  \
  __asm mov dword ptr[eax + CONTEXT.Ebp], ebp  \
  __asm mov dword ptr[eax + CONTEXT.Esp], esp  \
  /* NOTE: we need to add 8 bytes because EAX + EFLAGS are on the stack. */  \
  __asm add dword ptr[eax + CONTEXT.Esp], 8  \
  __asm mov dword ptr[eax + CONTEXT.Eip], offset expected_eip  \
  __asm popfd  \
  __asm pop eax  \
}

// Check if the sections of 2 context are equals.
// @param c1 The first context to check.
// @param c2 The second context to check.
// @param flags The sections to compare.
void ExpectEqualContexts(const CONTEXT& c1, const CONTEXT& c2, DWORD flags) {
  if ((flags & CONTEXT_SEGMENTS) == CONTEXT_SEGMENTS) {
    EXPECT_EQ(c1.SegGs, c2.SegGs);
    EXPECT_EQ(c1.SegFs, c2.SegFs);
    EXPECT_EQ(c1.SegEs, c2.SegEs);
    EXPECT_EQ(c1.SegDs, c2.SegDs);
  }

  if ((flags & CONTEXT_INTEGER) == CONTEXT_INTEGER) {
    EXPECT_EQ(c1.Edi, c2.Edi);
    EXPECT_EQ(c1.Esi, c2.Esi);
    EXPECT_EQ(c1.Ebx, c2.Ebx);
    EXPECT_EQ(c1.Edx, c2.Edx);
    EXPECT_EQ(c1.Ecx, c2.Ecx);
    EXPECT_EQ(c1.Eax, c2.Eax);
  }

  if ((flags & CONTEXT_CONTROL) == CONTEXT_CONTROL) {
    EXPECT_EQ(c1.Ebp, c2.Ebp);
    EXPECT_EQ(c1.Eip, c2.Eip);
    EXPECT_EQ(c1.SegCs, c2.SegCs);
    EXPECT_EQ(c1.EFlags, c2.EFlags);
    EXPECT_EQ(c1.Esp, c2.Esp);
    EXPECT_EQ(c1.SegSs, c2.SegSs);
  }
}

void CheckAccessAndCaptureContexts(
    CONTEXT* before, CONTEXT* after, void* location) {
  __asm {
    pushad
    pushfd

    // Avoid undefined behavior by forcing values.
    mov eax, 0x01234567
    mov ebx, 0x70123456
    mov ecx, 0x12345678
    mov edx, 0x56701234
    mov esi, 0xCCAACCAA
    mov edi, 0xAACCAACC

    RTL_CAPTURE_CONTEXT(before, check_access_expected_eip)

    // Push EDX as we're required to do by the custom calling convention.
    push edx
    // Ptr is the pointer to check.
    mov edx, location
    // Call through.
    call dword ptr[check_access_fn + 0]
 check_access_expected_eip:

    RTL_CAPTURE_CONTEXT(after, check_access_expected_eip)

    popfd
    popad
  }
}

void CheckAccessAndCompareContexts(void* ptr) {
  CONTEXT before = {};
  CONTEXT after = {};

  context_before_hook = &before;
  CheckAccessAndCaptureContexts(&before, &after, ptr);

  ExpectEqualContexts(before, after, CONTEXT_FULL);

  context_before_hook = NULL;
}

void CheckSpecialAccess(CONTEXT* before, CONTEXT* after,
                        void* dst, void* src, int len) {
  __asm {
    pushad
    pushfd

    // Override the direction flag.
    cld
    cmp direction_flag_forward, 0
    jne skip_reverse_direction
    std
 skip_reverse_direction:

    // Avoid undefined behavior by forcing values.
    mov eax, 0x01234567
    mov ebx, 0x70123456
    mov edx, 0x56701234

    // Setup registers used by the special instruction.
    mov ecx, len
    mov esi, src
    mov edi, dst

    RTL_CAPTURE_CONTEXT(before, special_access_expected_eip)

    // Call through.
    call dword ptr[check_access_fn + 0]
 special_access_expected_eip:

    RTL_CAPTURE_CONTEXT(after, special_access_expected_eip)

    popfd
    popad
  }
}

void CheckSpecialAccessAndCompareContexts(void* dst, void* src, int len) {
  CONTEXT before = {};
  CONTEXT after = {};

  context_before_hook = &before;

  CheckSpecialAccess(&before, &after, dst, src, len);

  ExpectEqualContexts(before, after, CONTEXT_FULL);

  context_before_hook = NULL;
}

void AsanErrorCallbackImpl(AsanErrorInfo* error_info, bool compare_context) {
  // TODO(sebmarchand): Stash the error info in a fixture-static variable and
  // assert on specific conditions after the fact.
  EXPECT_NE(reinterpret_cast<AsanErrorInfo*>(NULL), error_info);
  EXPECT_NE(HeapProxy::UNKNOWN_BAD_ACCESS, error_info->error_type);

  EXPECT_EQ(expected_error_type, error_info->error_type);
  if (error_info->error_type >= HeapProxy::USE_AFTER_FREE) {
    // We should at least have the stack trace of the allocation of this block.
    EXPECT_GT(error_info->alloc_stack_size, 0U);
    EXPECT_NE(0U, error_info->alloc_tid);
    if (error_info->error_type == HeapProxy::USE_AFTER_FREE ||
        error_info->error_type == HeapProxy::DOUBLE_FREE) {
      EXPECT_GT(error_info->free_stack_size, 0U);
      EXPECT_NE(0U, error_info->free_tid);
    } else {
      EXPECT_EQ(error_info->free_stack_size, 0U);
      EXPECT_EQ(0U, error_info->free_tid);
    }
  }

  if (error_info->error_type == HeapProxy::HEAP_BUFFER_OVERFLOW) {
    EXPECT_TRUE(strstr(error_info->shadow_info, "beyond") != NULL);
  } else if (error_info->error_type == HeapProxy::HEAP_BUFFER_UNDERFLOW) {
    EXPECT_TRUE(strstr(error_info->shadow_info, "before") != NULL);
  }

  memory_error_detected = true;
  last_error_info = *error_info;

  // Copy the corrupt range's information.
  if (error_info->heap_is_corrupt) {
    EXPECT_GE(1U, error_info->corrupt_range_count);
    for (size_t i = 0; i < error_info->corrupt_range_count; ++i) {
      last_corrupt_ranges.push_back(CorruptRangeInfo());
      CorruptRangeInfo* range_info = &last_corrupt_ranges.back();
      range_info->first = error_info->corrupt_ranges[i];
      AsanBlockInfoVector* block_infos = &range_info->second;
      for (size_t j = 0; j < range_info->first.block_info_count; ++j) {
        AsanBlockInfo* block_info =
            new AsanBlockInfo(range_info->first.block_info[j]);
        for (size_t k = 0;
             k < range_info->first.block_info[j].alloc_stack_size;
             ++k) {
          block_info->alloc_stack[k] =
              range_info->first.block_info[j].alloc_stack[k];
        }
        for (size_t k = 0;
             k < range_info->first.block_info[j].free_stack_size;
             ++k) {
          block_info->free_stack[k] =
              range_info->first.block_info[j].free_stack[k];
        }
        block_infos->push_back(block_info);
      }
    }
  }

  if (compare_context) {
    EXPECT_NE(reinterpret_cast<CONTEXT*>(NULL), context_before_hook);
    ExpectEqualContexts(*context_before_hook,
                        error_info->context,
                        CONTEXT_INTEGER | CONTEXT_CONTROL);
  }
}

void AsanErrorCallback(AsanErrorInfo* error_info) {
  EXPECT_NE(reinterpret_cast<CONTEXT*>(NULL), context_before_hook);
  AsanErrorCallbackImpl(error_info, true);
}

void AsanErrorCallbackWithoutComparingContext(AsanErrorInfo* error_info) {
  AsanErrorCallbackImpl(error_info, false);
}

void AssertMemoryErrorIsDetected(void* ptr,
                                 HeapProxy::BadAccessKind bad_access_type) {
  expected_error_type = bad_access_type;
  memory_error_detected = false;
  CheckAccessAndCompareContexts(ptr);
  ASSERT_TRUE(memory_error_detected);
}

void ExpectSpecialMemoryErrorIsDetected(bool expected,
    void* dst, void* src, int32 length,
    HeapProxy::BadAccessKind bad_access_type) {
  DCHECK(dst != NULL);
  DCHECK(src != NULL);
  ASSERT_TRUE(check_access_fn != NULL);
  expected_error_type = bad_access_type;

  // Setup the callback to detect invalid accesses.
  memory_error_detected = false;

  // Perform memory accesses inside the range.
  ASSERT_NO_FATAL_FAILURE(
      CheckSpecialAccessAndCompareContexts(dst, src, length));

  EXPECT_EQ(expected, memory_error_detected);
}

}  // namespace

TEST_F(AsanRtlTest, GetProcessHeap) {
  HANDLE asan_heap_handle = GetProcessHeapFunction();
  EXPECT_NE(INVALID_HANDLE_VALUE, asan_heap_handle);
  HeapProxy* proxy = HeapProxy::FromHandle(asan_heap_handle);
  EXPECT_NE(reinterpret_cast<HeapProxy*>(NULL), proxy);
  EXPECT_FALSE(proxy->owns_heap());
  EXPECT_EQ(::GetProcessHeap(), proxy->heap());
}

TEST_F(AsanRtlTest, AsanCheckGoodAccess) {
  check_access_fn =
      ::GetProcAddress(asan_rtl_, "asan_check_4_byte_read_access");
  ASSERT_TRUE(check_access_fn != NULL);

  // Run through access checking an allocation that's larger than our
  // block size (8), but not a multiple thereof to exercise all paths
  // in the access check function (save for the failure path).
  ScopedASanAlloc<uint8> mem(this, kAllocSize);
  ASSERT_TRUE(mem.get() != NULL);

  for (size_t i = 0; i < kAllocSize; ++i) {
    ASSERT_NO_FATAL_FAILURE(CheckAccessAndCompareContexts(mem.get() + i));
  }
}

TEST_F(AsanRtlTest, AsanCheckHeapBufferOverflow) {
  check_access_fn =
      ::GetProcAddress(asan_rtl_, "asan_check_4_byte_read_access");
  ASSERT_TRUE(check_access_fn != NULL);

  ScopedASanAlloc<uint8> mem(this, kAllocSize);
  ASSERT_TRUE(mem.get() != NULL);

  SetCallBackFunction(&AsanErrorCallback);
  AssertMemoryErrorIsDetected(mem.get() + kAllocSize,
                              HeapProxy::HEAP_BUFFER_OVERFLOW);
  EXPECT_TRUE(LogContains("previously allocated here"));
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
}

TEST_F(AsanRtlTest, AsanCheckHeapBufferUnderflow) {
  check_access_fn =
      ::GetProcAddress(asan_rtl_, "asan_check_4_byte_read_access");
  ASSERT_TRUE(check_access_fn != NULL);

  const size_t kAllocSize = 13;
  ScopedASanAlloc<uint8> mem(this, kAllocSize);
  ASSERT_TRUE(mem.get() != NULL);

  SetCallBackFunction(&AsanErrorCallback);
  AssertMemoryErrorIsDetected(mem.get() - 1, HeapProxy::HEAP_BUFFER_UNDERFLOW);
  EXPECT_TRUE(LogContains("previously allocated here"));
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
}

TEST_F(AsanRtlTest, AsanCheckUseAfterFree) {
  check_access_fn =
      ::GetProcAddress(asan_rtl_, "asan_check_4_byte_read_access");
  ASSERT_TRUE(check_access_fn != NULL);

  const size_t kAllocSize = 13;
  ScopedASanAlloc<uint8> mem(this, kAllocSize);
  ASSERT_TRUE(mem.get() != NULL);

  SetCallBackFunction(&AsanErrorCallback);
  uint8* mem_ptr = mem.get();
  mem.reset(NULL);
  AssertMemoryErrorIsDetected(mem_ptr, HeapProxy::USE_AFTER_FREE);
  EXPECT_TRUE(LogContains("previously allocated here"));
  EXPECT_TRUE(LogContains("freed here"));
  EXPECT_TRUE(LogContains(HeapProxy::kHeapUseAfterFree));
}

TEST_F(AsanRtlTest, AsanCheckDoubleFree) {
  check_access_fn =
      ::GetProcAddress(asan_rtl_, "asan_check_4_byte_read_access");
  ASSERT_TRUE(check_access_fn != NULL);

  const size_t kAllocSize = 13;
  uint8* mem_ptr = NULL;
  {
    ScopedASanAlloc<uint8> mem(this, kAllocSize);
    ASSERT_TRUE(mem.get() != NULL);
    mem_ptr = mem.get();
  }

  expected_error_type = HeapProxy::DOUBLE_FREE;
  SetCallBackFunction(&AsanErrorCallbackWithoutComparingContext);
  EXPECT_FALSE(HeapFreeFunction(heap_, 0, mem_ptr));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kAttemptingDoubleFree));
  EXPECT_TRUE(LogContains("previously allocated here"));
  EXPECT_TRUE(LogContains("freed here"));
}

TEST_F(AsanRtlTest, AsanCheckWildAccess) {
  check_access_fn =
      ::GetProcAddress(asan_rtl_, "asan_check_4_byte_read_access");
  ASSERT_TRUE(check_access_fn != NULL);

  SetCallBackFunction(&AsanErrorCallback);
  AssertMemoryErrorIsDetected(reinterpret_cast<void*>(0x80000000),
                              HeapProxy::WILD_ACCESS);
  EXPECT_TRUE(LogContains(HeapProxy::kWildAccess));
}

TEST_F(AsanRtlTest, AsanCheckInvalidAccess) {
  check_access_fn =
      ::GetProcAddress(asan_rtl_, "asan_check_4_byte_read_access");
  ASSERT_TRUE(check_access_fn != NULL);

  SetCallBackFunction(&AsanErrorCallback);
  AssertMemoryErrorIsDetected(reinterpret_cast<void*>(0x00000000),
                              HeapProxy::INVALID_ADDRESS);
  EXPECT_TRUE(LogContains(HeapProxy::kInvalidAddress));
}

TEST_F(AsanRtlTest, AsanCheckCorruptBlock) {
  void* mem = HeapAllocFunction(heap_, 0, kAllocSize);
  SetCallBackFunction(&AsanErrorCallbackWithoutComparingContext);
  reinterpret_cast<uint8*>(mem)[-1]--;
  expected_error_type = HeapProxy::CORRUPT_BLOCK;
  EXPECT_TRUE(HeapFreeFunction(heap_, 0, mem));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapCorruptBlock));
  EXPECT_TRUE(LogContains("previously allocated here"));
}

TEST_F(AsanRtlTest, AsanCheckCorruptHeap) {
  check_access_fn =
      ::GetProcAddress(asan_rtl_, "asan_check_4_byte_read_access");
  ASSERT_TRUE(check_access_fn != NULL);

  agent::asan::AsanRuntime* runtime = GetActiveRuntimeFunction();
  ASSERT_NE(reinterpret_cast<agent::asan::AsanRuntime*>(NULL), runtime);
  runtime->params().check_heap_on_failure = true;

  ScopedASanAlloc<uint8> mem(this, kAllocSize);
  ASSERT_TRUE(mem.get() != NULL);

  SetCallBackFunction(&AsanErrorCallbackWithoutComparingContext);
  const size_t kMaxIterations = 10;
  // This can fail because of a checksum collision. However, we run it a handful
  // of times to keep the chances as small as possible.
  for (size_t i = 0; i < kMaxIterations; ++i) {
    mem[kAllocSize]++;
    AssertMemoryErrorIsDetected(mem.get() + kAllocSize,
                                HeapProxy::HEAP_BUFFER_OVERFLOW);
    EXPECT_TRUE(LogContains("previously allocated here"));
    EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));

    if (!last_error_info.heap_is_corrupt && i + 1 < kMaxIterations)
      continue;

    EXPECT_TRUE(last_error_info.heap_is_corrupt);

    size_t block_size = 0;
    void* block_begin = NULL;

    // We can't use the shadow functions here as they'll refer to the instance
    // of the shadow memory which has been statically linked, but the shadow
    // annotations for this block are in the shadow instance which has been
    // instantiated while dynamically loading the runtime library.
    GetAsanExtentFunction(mem.GetAs<void*>(), &block_begin, &block_size);
    EXPECT_NE(reinterpret_cast<void*>(NULL), block_begin);

    EXPECT_EQ(1, last_error_info.corrupt_range_count);
    EXPECT_EQ(1, last_corrupt_ranges.size());
    AsanCorruptBlockRange* corrupt_range = &last_corrupt_ranges[0].first;
    AsanBlockInfoVector* blocks_info = &last_corrupt_ranges[0].second;

    EXPECT_EQ(1, blocks_info->size());
    EXPECT_TRUE((*blocks_info)[0]->corrupt);
    EXPECT_EQ(kAllocSize, (*blocks_info)[0]->user_size);
    EXPECT_EQ(block_begin, (*blocks_info)[0]->header);
    EXPECT_NE(0U, (*blocks_info)[0]->alloc_stack_size);
    for (size_t j = 0; j < (*blocks_info)[0]->alloc_stack_size; ++j) {
      EXPECT_NE(reinterpret_cast<void*>(NULL),
                (*blocks_info)[0]->alloc_stack[j]);
    }
    EXPECT_EQ(0U, (*blocks_info)[0]->free_stack_size);

    // An error should be triggered when we free this block.
    memory_error_detected = false;
    expected_error_type = HeapProxy::CORRUPT_BLOCK;
    mem.reset(NULL);
    EXPECT_TRUE(memory_error_detected);

    break;
  }
}

TEST_F(AsanRtlTest, AsanSingleSpecial1byteInstructionCheckGoodAccess) {
  static const char* function_names[] = {
      "asan_check_1_byte_movs_access",
      "asan_check_1_byte_cmps_access",
      "asan_check_1_byte_stos_access"
  };

  // Setup the callback to detect invalid accesses.
  SetCallBackFunction(&AsanErrorCallback);

  // Allocate memory space.
  AllocMemoryBuffers(kAllocSize, sizeof(uint8));
  uint8* src = reinterpret_cast<uint8*>(memory_src_);
  uint8* dst = reinterpret_cast<uint8*>(memory_dst_);

  // Validate memory accesses.
  for (int32 function = 0; function < arraysize(function_names); ++function) {
    check_access_fn =
        ::GetProcAddress(asan_rtl_, function_names[function]);
    ASSERT_TRUE(check_access_fn != NULL);

    for (int32 i = 0; i < memory_length_; ++i)
      ExpectSpecialMemoryErrorIsDetected(false, &dst[i], &src[i], 0xDEADDEAD,
                                         HeapProxy::UNKNOWN_BAD_ACCESS);
  }

  FreeMemoryBuffers();
}

TEST_F(AsanRtlTest, AsanSingleSpecial2byteInstructionCheckGoodAccess) {
  static const char* function_names[] = {
      "asan_check_2_byte_movs_access",
      "asan_check_2_byte_cmps_access",
      "asan_check_2_byte_stos_access"
  };

  // Setup the callback to detect invalid accesses.
  SetCallBackFunction(&AsanErrorCallback);

  // Allocate memory space.
  AllocMemoryBuffers(kAllocSize, sizeof(uint16));
  uint16* src = reinterpret_cast<uint16*>(memory_src_);
  uint16* dst = reinterpret_cast<uint16*>(memory_dst_);

  // Validate memory accesses.
  for (int32 function = 0; function < arraysize(function_names); ++function) {
    check_access_fn =
        ::GetProcAddress(asan_rtl_, function_names[function]);
    ASSERT_TRUE(check_access_fn != NULL);

    for (int32 i = 0; i < memory_length_; ++i)
      ExpectSpecialMemoryErrorIsDetected(false, &dst[i], &src[i], 0xDEADDEAD,
                                         HeapProxy::UNKNOWN_BAD_ACCESS);
  }

  FreeMemoryBuffers();
}

TEST_F(AsanRtlTest, AsanSingleSpecial4byteInstructionCheckGoodAccess) {
  static const char* function_names[] = {
      "asan_check_4_byte_movs_access",
      "asan_check_4_byte_cmps_access",
      "asan_check_4_byte_stos_access"
  };

  // Setup the callback to detect invalid accesses.
  SetCallBackFunction(&AsanErrorCallback);

  // Allocate memory space.
  AllocMemoryBuffers(kAllocSize, sizeof(uint32));
  uint32* src = reinterpret_cast<uint32*>(memory_src_);
  uint32* dst = reinterpret_cast<uint32*>(memory_dst_);

  // Validate memory accesses.
  for (int32 function = 0; function < arraysize(function_names); ++function) {
    check_access_fn =
        ::GetProcAddress(asan_rtl_, function_names[function]);
    ASSERT_TRUE(check_access_fn != NULL);

    for (int32 i = 0; i < memory_length_; ++i)
      ExpectSpecialMemoryErrorIsDetected(false, &dst[i], &src[i], 0xDEADDEAD,
                                         HeapProxy::UNKNOWN_BAD_ACCESS);
  }

  FreeMemoryBuffers();
}

TEST_F(AsanRtlTest, AsanSingleSpecialInstructionCheckBadAccess) {
  static const char* function_names[] = {
      "asan_check_1_byte_movs_access",
      "asan_check_1_byte_cmps_access",
      "asan_check_2_byte_movs_access",
      "asan_check_2_byte_cmps_access",
      "asan_check_4_byte_movs_access",
      "asan_check_4_byte_cmps_access"
  };

  // Setup the callback to detect invalid accesses.
  SetCallBackFunction(&AsanErrorCallback);

  // Allocate memory space.
  AllocMemoryBuffers(kAllocSize, sizeof(uint32));
  uint32* src = reinterpret_cast<uint32*>(memory_src_);
  uint32* dst = reinterpret_cast<uint32*>(memory_dst_);

  // Validate memory accesses.
  for (int32 function = 0; function < arraysize(function_names); ++function) {
    check_access_fn =
        ::GetProcAddress(asan_rtl_, function_names[function]);
    ASSERT_TRUE(check_access_fn != NULL);

    ExpectSpecialMemoryErrorIsDetected(true, &dst[0], &src[-1], 0xDEADDEAD,
                                       HeapProxy::HEAP_BUFFER_UNDERFLOW);
    ExpectSpecialMemoryErrorIsDetected(true, &dst[-1], &src[0], 0xDEADDEAD,
                                       HeapProxy::HEAP_BUFFER_UNDERFLOW);

    ExpectSpecialMemoryErrorIsDetected(true, &dst[0], &src[memory_length_],
        0xDEADDEAD, HeapProxy::HEAP_BUFFER_OVERFLOW);
    ExpectSpecialMemoryErrorIsDetected(true, &dst[memory_length_], &src[0],
        0xDEADDEAD, HeapProxy::HEAP_BUFFER_OVERFLOW);
  }

  FreeMemoryBuffers();
}

TEST_F(AsanRtlTest, AsanSingleStoInstructionCheckBadAccess) {
  static const char* function_names[] = {
      "asan_check_1_byte_stos_access",
      "asan_check_2_byte_stos_access",
      "asan_check_4_byte_stos_access"
  };

  // Setup the callback to detect invalid accesses.
  SetCallBackFunction(&AsanErrorCallback);

  // Allocate memory space.
  AllocMemoryBuffers(kAllocSize, sizeof(uint32));
  uint32* src = reinterpret_cast<uint32*>(memory_src_);
  uint32* dst = reinterpret_cast<uint32*>(memory_dst_);

  // Validate memory accesses.
  for (int32 function = 0; function < arraysize(function_names); ++function) {
    check_access_fn =
        ::GetProcAddress(asan_rtl_, function_names[function]);
    ASSERT_TRUE(check_access_fn != NULL);

    ExpectSpecialMemoryErrorIsDetected(false, &dst[0], &src[-1], 0xDEAD,
        HeapProxy::HEAP_BUFFER_UNDERFLOW);
    ExpectSpecialMemoryErrorIsDetected(true, &dst[-1], &src[0], 0xDEAD,
        HeapProxy::HEAP_BUFFER_UNDERFLOW);

    ExpectSpecialMemoryErrorIsDetected(false, &dst[0], &src[memory_length_],
        0xDEADDEAD, HeapProxy::HEAP_BUFFER_OVERFLOW);
    ExpectSpecialMemoryErrorIsDetected(true, &dst[memory_length_], &src[0],
        0xDEADDEAD, HeapProxy::HEAP_BUFFER_OVERFLOW);
  }

  FreeMemoryBuffers();
}

TEST_F(AsanRtlTest, AsanPrefixedSpecialInstructionCheckGoodAccess) {
  static const char* function_names[] = {
      "asan_check_repz_4_byte_movs_access",
      "asan_check_repz_4_byte_cmps_access",
      "asan_check_repz_4_byte_stos_access"
  };

  // Setup the callback to detect invalid accesses.
  SetCallBackFunction(&AsanErrorCallback);

  // Allocate memory space.
  AllocMemoryBuffers(kAllocSize, sizeof(uint32));
  uint32* src = reinterpret_cast<uint32*>(memory_src_);
  uint32* dst = reinterpret_cast<uint32*>(memory_dst_);

  // Validate memory accesses.
  for (int32 function = 0; function < arraysize(function_names); ++function) {
    check_access_fn =
        ::GetProcAddress(asan_rtl_, function_names[function]);
    ASSERT_TRUE(check_access_fn != NULL);

    ExpectSpecialMemoryErrorIsDetected(false, &dst[0], &src[0], memory_length_,
                                       HeapProxy::UNKNOWN_BAD_ACCESS);
  }

  FreeMemoryBuffers();
}

TEST_F(AsanRtlTest, AsanPrefixedSpecialInstructionCheckBadAccess) {
  static const char* function_names[] = {
      "asan_check_repz_4_byte_movs_access",
      "asan_check_repz_4_byte_cmps_access",
      "asan_check_repz_4_byte_stos_access"
  };

  // Setup the callback to detect invalid accesses.
  SetCallBackFunction(&AsanErrorCallback);

  // Allocate memory space.
  AllocMemoryBuffers(kAllocSize, sizeof(uint32));
  uint32* src = reinterpret_cast<uint32*>(memory_src_);
  uint32* dst = reinterpret_cast<uint32*>(memory_dst_);

  // Validate memory accesses.
  for (int32 function = 0; function < arraysize(function_names); ++function) {
    check_access_fn =
        ::GetProcAddress(asan_rtl_, function_names[function]);
    ASSERT_TRUE(check_access_fn != NULL);

    ExpectSpecialMemoryErrorIsDetected(true, &dst[0], &src[0],
        memory_length_ + 1, HeapProxy::HEAP_BUFFER_OVERFLOW);
    ExpectSpecialMemoryErrorIsDetected(true, &dst[-1], &src[-1],
        memory_length_, HeapProxy::HEAP_BUFFER_UNDERFLOW);
    ExpectSpecialMemoryErrorIsDetected(true, &dst[-1], &src[0],
        memory_length_, HeapProxy::HEAP_BUFFER_UNDERFLOW);
  }

  FreeMemoryBuffers();
}

TEST_F(AsanRtlTest, AsanDirectionSpecialInstructionCheckGoodAccess) {
  static const char* function_names[] = {
      "asan_check_repz_4_byte_movs_access",
      "asan_check_repz_4_byte_cmps_access",
      "asan_check_repz_4_byte_stos_access"
  };

  // Setup the callback to detect invalid accesses.
  SetCallBackFunction(&AsanErrorCallback);

  // Force direction flag to backward.
  direction_flag_forward = false;

  // Allocate memory space.
  AllocMemoryBuffers(kAllocSize, sizeof(uint32));
  uint32* src = reinterpret_cast<uint32*>(memory_src_);
  uint32* dst = reinterpret_cast<uint32*>(memory_dst_);

  // Validate memory accesses.
  for (int32 function = 0; function < arraysize(function_names); ++function) {
    check_access_fn =
        ::GetProcAddress(asan_rtl_, function_names[function]);
    ASSERT_TRUE(check_access_fn != NULL);

    ExpectSpecialMemoryErrorIsDetected(false, &dst[memory_length_ - 1],
        &src[memory_length_ - 1], memory_length_,
        HeapProxy::UNKNOWN_BAD_ACCESS);
  }

  // Reset direction flag to forward.
  direction_flag_forward = true;

  FreeMemoryBuffers();
}

TEST_F(AsanRtlTest, AsanSpecialInstructionCheckZeroAccess) {
  static const char* function_names[] = {
      "asan_check_repz_1_byte_movs_access",
      "asan_check_repz_1_byte_cmps_access",
      "asan_check_repz_1_byte_stos_access",
      "asan_check_repz_2_byte_movs_access",
      "asan_check_repz_2_byte_cmps_access",
      "asan_check_repz_2_byte_stos_access",
      "asan_check_repz_4_byte_movs_access",
      "asan_check_repz_4_byte_cmps_access",
      "asan_check_repz_4_byte_stos_access"
  };

  // Setup the callback to detect invalid accesses.
  SetCallBackFunction(&AsanErrorCallback);

  // Allocate memory space.
  AllocMemoryBuffers(kAllocSize, sizeof(uint32));
  uint32* src = reinterpret_cast<uint32*>(memory_src_);
  uint32* dst = reinterpret_cast<uint32*>(memory_dst_);

  // Validate memory accesses.
  for (int32 function = 0; function < arraysize(function_names); ++function) {
    check_access_fn =
        ::GetProcAddress(asan_rtl_, function_names[function]);
    ASSERT_TRUE(check_access_fn != NULL);

    // A prefixed instruction with a count of zero do not have side effects.
    ExpectSpecialMemoryErrorIsDetected(false, &dst[-1], &src[-1], 0,
                                       HeapProxy::UNKNOWN_BAD_ACCESS);
  }

  FreeMemoryBuffers();
}

TEST_F(AsanRtlTest, AsanSpecialInstructionCheckShortcutAccess) {
  static const char* function_names[] = {
      "asan_check_repz_1_byte_cmps_access",
      "asan_check_repz_2_byte_cmps_access",
      "asan_check_repz_4_byte_cmps_access",
  };

  // Setup the callback to detect invalid accesses.
  SetCallBackFunction(&AsanErrorCallback);

  // Allocate memory space.
  AllocMemoryBuffers(kAllocSize, sizeof(uint32));
  uint32* src = reinterpret_cast<uint32*>(memory_src_);
  uint32* dst = reinterpret_cast<uint32*>(memory_dst_);

  src[1] = 0x12345667;

  // Validate memory accesses.
  for (int32 function = 0; function < arraysize(function_names); ++function) {
    check_access_fn =
        ::GetProcAddress(asan_rtl_, function_names[function]);
    ASSERT_TRUE(check_access_fn != NULL);

    // Compare instruction stop their execution when values differ.
    ExpectSpecialMemoryErrorIsDetected(false, &dst[0], &src[0],
        memory_length_ + 1, HeapProxy::UNKNOWN_BAD_ACCESS);
  }

  FreeMemoryBuffers();
}

}  // namespace asan
}  // namespace agent
