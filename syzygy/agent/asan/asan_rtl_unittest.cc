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
#include "syzygy/agent/asan/asan_heap.h"
#include "syzygy/agent/asan/asan_runtime.h"
#include "syzygy/agent/asan/asan_shadow.h"
#include "syzygy/agent/asan/unittest_util.h"
#include "syzygy/core/unittest_util.h"

namespace agent {
namespace asan {

namespace {

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

// Shorthand for discussing all the asan runtime functions.
#define ASAN_RTL_FUNCTIONS(F)  \
    F(HANDLE, HeapCreate,  \
      (DWORD options, SIZE_T initial_size, SIZE_T maximum_size))  \
    F(BOOL, HeapDestroy,  \
      (HANDLE heap))  \
    F(LPVOID, HeapAlloc,  \
      (HANDLE heap, DWORD flags, SIZE_T bytes))  \
    F(LPVOID, HeapReAlloc,  \
      (HANDLE heap, DWORD flags, LPVOID mem, SIZE_T bytes))  \
    F(BOOL, HeapFree,  \
      (HANDLE heap, DWORD flags, LPVOID mem))  \
    F(SIZE_T, HeapSize,  \
      (HANDLE heap, DWORD flags, LPCVOID mem))  \
    F(BOOL, HeapValidate,  \
      (HANDLE heap, DWORD flags, LPCVOID mem))  \
    F(SIZE_T, HeapCompact,  \
      (HANDLE heap, DWORD flags))  \
    F(BOOL, HeapLock, (HANDLE heap))  \
    F(BOOL, HeapUnlock, (HANDLE heap))  \
    F(BOOL, HeapWalk,  \
      (HANDLE heap, LPPROCESS_HEAP_ENTRY entry))  \
    F(BOOL, HeapSetInformation,  \
      (HANDLE heap, HEAP_INFORMATION_CLASS info_class,  \
       PVOID info, SIZE_T info_length))  \
    F(BOOL, HeapQueryInformation,  \
      (HANDLE heap, HEAP_INFORMATION_CLASS info_class,  \
       PVOID info, SIZE_T info_length, PSIZE_T return_length))  \
    F(void, SetCallBack,  \
      (void (*callback)(CONTEXT* context, AsanErrorInfo* error_info)))  \

#define DECLARE_ASAN_FUNCTION_PTR(ret, name, args) \
    typedef ret (WINAPI* name##FunctionPtr)args;

ASAN_RTL_FUNCTIONS(DECLARE_ASAN_FUNCTION_PTR)

#undef DECLARE_ASAN_FUNCTION_PTR

class AsanRtlTest : public testing::TestWithAsanLogger {
 public:
  AsanRtlTest() : asan_rtl_(NULL), heap_(NULL),
    memory_src_(NULL), memory_dst_(NULL),
    memory_length_(0), memory_size_(0) {
  }

  void SetUp() OVERRIDE {
    testing::TestWithAsanLogger::SetUp();

    // Load the ASAN runtime library.
    base::FilePath asan_rtl_path = testing::GetExeRelativePath(L"asan_rtl.dll");
    asan_rtl_ = ::LoadLibrary(asan_rtl_path.value().c_str());
    ASSERT_TRUE(asan_rtl_ != NULL);

    // Load all the functions and assert that we find them.
#define LOAD_ASAN_FUNCTION(ret, name, args)  \
    name##Function = reinterpret_cast<name##FunctionPtr>(  \
        ::GetProcAddress(asan_rtl_, "asan_" #name));  \
    ASSERT_TRUE(name##Function != NULL);

    ASAN_RTL_FUNCTIONS(LOAD_ASAN_FUNCTION)

#undef LOAD_ASAN_FUNCTION

    heap_ = HeapCreateFunction(0, 0, 0);
    ASSERT_TRUE(heap_ != NULL);
  }

  void TearDown() OVERRIDE {
    if (heap_ != NULL) {
      HeapDestroyFunction(heap_);
      heap_ = NULL;
    }

    if (asan_rtl_ != NULL) {
      ::FreeLibrary(asan_rtl_);
      asan_rtl_ = NULL;
    }

    testing::TestWithAsanLogger::TearDown();
  }

 protected:
  void AllocMemoryBuffers(int32 length, int32 element_size);
  void FreeMemoryBuffers();

  // The ASAN runtime module to test.
  HMODULE asan_rtl_;

  // Scratch heap handle valid from SetUp to TearDown.
  HANDLE heap_;

  // Memory buffers used to test special instructions.
  void* memory_src_;
  void* memory_dst_;
  int32 memory_length_;
  int32 memory_size_;

  // Declare the function pointers.
#define DECLARE_FUNCTION_PTR_VARIABLE(ret, name, args)  \
    static name##FunctionPtr AsanRtlTest::name##Function;

  ASAN_RTL_FUNCTIONS(DECLARE_FUNCTION_PTR_VARIABLE)

#undef DECLARE_FUNCTION_PTR_VARIABLE
};

// Define the function pointers.
#define DEFINE_FUNCTION_PTR_VARIABLE(ret, name, args)  \
    name##FunctionPtr AsanRtlTest::name##Function;

  ASAN_RTL_FUNCTIONS(DEFINE_FUNCTION_PTR_VARIABLE)

#undef DEFINE_FUNCTION_PTR_VARIABLE

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
}

void AsanErrorCallback(CONTEXT* context, AsanErrorInfo* error_info) {
  // TODO(sebmarchand): Stash the error info in a fixture-static variable and
  // assert on specific conditions after the fact.
  EXPECT_TRUE(context != NULL);
  EXPECT_TRUE(context_before_hook != NULL);
  EXPECT_NE(HeapProxy::UNKNOWN_BAD_ACCESS, error_info->error_type);

  EXPECT_EQ(expected_error_type, error_info->error_type);
  // We should at least have the stack trace of the allocation of this block.
  EXPECT_GT(error_info->alloc_stack_size, 0U);
  if (error_info->error_type == HeapProxy::USE_AFTER_FREE)
    EXPECT_GT(error_info->free_stack_size, 0U);
  else
    EXPECT_EQ(error_info->free_stack_size, 0U);

  if (error_info->error_type == HeapProxy::HEAP_BUFFER_OVERFLOW) {
    EXPECT_TRUE(strstr(error_info->shadow_info, "to the right") != NULL);
  } else if (error_info->error_type == HeapProxy::HEAP_BUFFER_UNDERFLOW) {
    EXPECT_TRUE(strstr(error_info->shadow_info, "to the left") != NULL);
  }

  memory_error_detected = true;
  ExpectEqualContexts(*context_before_hook,
                      *context,
                      CONTEXT_INTEGER | CONTEXT_CONTROL);
}

void AsanErrorCallbackWithoutComparingContext(CONTEXT* context,
                                              AsanErrorInfo* error_info) {
  memory_error_detected = true;
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

TEST_F(AsanRtlTest, AsanCheckGoodAccess) {
  check_access_fn =
      ::GetProcAddress(asan_rtl_, "asan_check_4_byte_read_access");
  ASSERT_TRUE(check_access_fn != NULL);

  // Run through access checking an allocation that's larger than our
  // block size (8), but not a multiple thereof to exercise all paths
  // in the access check function (save for the failure path).
  uint8* mem = reinterpret_cast<uint8*>(
      HeapAllocFunction(heap_, 0, kAllocSize));
  ASSERT_TRUE(mem != NULL);

  for (size_t i = 0; i < kAllocSize; ++i) {
    ASSERT_NO_FATAL_FAILURE(CheckAccessAndCompareContexts(mem + i));
  }

  ASSERT_TRUE(HeapFreeFunction(heap_, 0, mem));
}

TEST_F(AsanRtlTest, AsanCheckHeapBufferOverflow) {
  check_access_fn =
      ::GetProcAddress(asan_rtl_, "asan_check_4_byte_read_access");
  ASSERT_TRUE(check_access_fn != NULL);

  uint8* mem = reinterpret_cast<uint8*>(
      HeapAllocFunction(heap_, 0, kAllocSize));
  ASSERT_TRUE(mem != NULL);

  SetCallBackFunction(&AsanErrorCallback);
  AssertMemoryErrorIsDetected(mem + kAllocSize,
                              HeapProxy::HEAP_BUFFER_OVERFLOW);
  EXPECT_TRUE(HeapFreeFunction(heap_, 0, mem));
  EXPECT_TRUE(LogContains("previously allocated here"));
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
}

TEST_F(AsanRtlTest, AsanCheckHeapBufferUnderflow) {
  check_access_fn =
      ::GetProcAddress(asan_rtl_, "asan_check_4_byte_read_access");
  ASSERT_TRUE(check_access_fn != NULL);

  const size_t kAllocSize = 13;
  uint8* mem = reinterpret_cast<uint8*>(
      HeapAllocFunction(heap_, 0, kAllocSize));
  ASSERT_TRUE(mem != NULL);

  SetCallBackFunction(&AsanErrorCallback);
  AssertMemoryErrorIsDetected(mem - 1, HeapProxy::HEAP_BUFFER_UNDERFLOW);
  EXPECT_TRUE(HeapFreeFunction(heap_, 0, mem));
  EXPECT_TRUE(LogContains("previously allocated here"));
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
}

TEST_F(AsanRtlTest, AsanCheckUseAfterFree) {
  check_access_fn =
      ::GetProcAddress(asan_rtl_, "asan_check_4_byte_read_access");
  ASSERT_TRUE(check_access_fn != NULL);

  const size_t kAllocSize = 13;
  uint8* mem = reinterpret_cast<uint8*>(
      HeapAllocFunction(heap_, 0, kAllocSize));
  ASSERT_TRUE(mem != NULL);

  SetCallBackFunction(&AsanErrorCallback);
  EXPECT_TRUE(HeapFreeFunction(heap_, 0, mem));
  AssertMemoryErrorIsDetected(mem, HeapProxy::USE_AFTER_FREE);
  EXPECT_TRUE(LogContains("previously allocated here"));
  EXPECT_TRUE(LogContains("freed here"));
  EXPECT_TRUE(LogContains(HeapProxy::kHeapUseAfterFree));
}

TEST_F(AsanRtlTest, AsanCheckDoubleFree) {
  check_access_fn =
      ::GetProcAddress(asan_rtl_, "asan_check_4_byte_read_access");
  ASSERT_TRUE(check_access_fn != NULL);

  const size_t kAllocSize = 13;
  uint8* mem = reinterpret_cast<uint8*>(
      HeapAllocFunction(heap_, 0, kAllocSize));
  ASSERT_TRUE(mem != NULL);

  CONTEXT context_before_error = {};
  context_before_hook = &context_before_error;
  SetCallBackFunction(&AsanErrorCallbackWithoutComparingContext);
  EXPECT_TRUE(HeapFreeFunction(heap_, 0, mem));
  EXPECT_FALSE(HeapFreeFunction(heap_, 0, mem));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kAttemptingDoubleFree));
  EXPECT_TRUE(LogContains("previously allocated here"));
  EXPECT_TRUE(LogContains("freed here"));
}

void AsanRtlTest::AllocMemoryBuffers(int32 length, int32 element_size) {
  DCHECK(memory_src_ == NULL);
  DCHECK(memory_dst_ == NULL);
  DCHECK(memory_length_ == 0);
  DCHECK(memory_size_ == 0);

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
  DCHECK(memory_src_ != NULL);
  DCHECK(memory_dst_ != NULL);

  ASSERT_TRUE(HeapFreeFunction(heap_, 0, memory_src_));
  ASSERT_TRUE(HeapFreeFunction(heap_, 0, memory_dst_));

  memory_length_ = 0;
  memory_size_ = 0;
  memory_src_ = NULL;
  memory_dst_ = NULL;
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

} // namespace asan
} // namespace agent
