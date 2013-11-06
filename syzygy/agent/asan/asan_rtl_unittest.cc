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

#include "base/bind.h"
#include "base/file_util.h"
#include "base/synchronization/waitable_event.h"
#include "base/threading/thread.h"
#include "base/win/scoped_handle.h"
#include "gtest/gtest.h"
#include "syzygy/agent/asan/asan_heap.h"
#include "syzygy/agent/asan/asan_rtl_impl.h"
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
    F(WINAPI, HANDLE, HeapCreate,  \
      (DWORD options, SIZE_T initial_size, SIZE_T maximum_size))  \
    F(WINAPI, BOOL, HeapDestroy,  \
      (HANDLE heap))  \
    F(WINAPI, LPVOID, HeapAlloc,  \
      (HANDLE heap, DWORD flags, SIZE_T bytes))  \
    F(WINAPI, LPVOID, HeapReAlloc,  \
      (HANDLE heap, DWORD flags, LPVOID mem, SIZE_T bytes))  \
    F(WINAPI, BOOL, HeapFree,  \
      (HANDLE heap, DWORD flags, LPVOID mem))  \
    F(WINAPI, SIZE_T, HeapSize,  \
      (HANDLE heap, DWORD flags, LPCVOID mem))  \
    F(WINAPI, BOOL, HeapValidate,  \
      (HANDLE heap, DWORD flags, LPCVOID mem))  \
    F(WINAPI, SIZE_T, HeapCompact,  \
      (HANDLE heap, DWORD flags))  \
    F(WINAPI, BOOL, HeapLock, (HANDLE heap))  \
    F(WINAPI, BOOL, HeapUnlock, (HANDLE heap))  \
    F(WINAPI, BOOL, HeapWalk,  \
      (HANDLE heap, LPPROCESS_HEAP_ENTRY entry))  \
    F(WINAPI, BOOL, HeapSetInformation,  \
      (HANDLE heap, HEAP_INFORMATION_CLASS info_class,  \
       PVOID info, SIZE_T info_length))  \
    F(WINAPI, BOOL, HeapQueryInformation,  \
      (HANDLE heap, HEAP_INFORMATION_CLASS info_class,  \
       PVOID info, SIZE_T info_length, PSIZE_T return_length))  \
    F(WINAPI, void, SetCallBack,  \
      (void (*callback)(AsanErrorInfo* error_info)))  \
    F(_cdecl, void*, memcpy,  \
      (void* destination, const void* source,  size_t num))  \
    F(_cdecl, void*, memmove,  \
      (void* destination, const void* source, size_t num))  \
    F(_cdecl, void*, memset, (void* ptr, int value, size_t num))  \
    F(_cdecl, const void*, memchr, (const void* ptr, int value, size_t num))  \
    F(_cdecl, size_t, strcspn, (const char* str1, const char* str2))  \
    F(_cdecl, size_t, strlen, (const char* str))  \
    F(_cdecl, const char*, strrchr, (const char* str, int character))  \
    F(_cdecl, int, strcmp, (const char* str1, const char* str2))  \
    F(_cdecl, const char*, strpbrk, (const char* str1, const char* str2))  \
    F(_cdecl, const char*, strstr, (const char* str1, const char* str2))  \
    F(_cdecl, size_t, strspn, (const char* str1, const char* str2))  \
    F(_cdecl, char*, strncpy,  \
      (char* destination, const char* source, size_t num))  \
    F(_cdecl, char*, strncat,  \
      (char* destination, const char* source, size_t num))  \
    F(_cdecl, void, PoisonMemoryRange, (const void* address, size_t size))  \
    F(_cdecl, void, UnpoisonMemoryRange, (const void* address, size_t size))  \
    F(_cdecl, void, GetAsanObjectSize,  \
      (size_t user_object_size, size_t alignment))  \
    F(_cdecl, void, InitializeObject,  \
      (void* asan_pointer, size_t user_object_size, size_t alignment))  \
    F(_cdecl, void, GetUserExtent,  \
      (const void* asan_pointer, void** user_pointer, size_t* size))  \
    F(_cdecl, void, GetAsanExtent,  \
      (const void* user_pointer, void** asan_pointer, size_t* size))  \
    F(_cdecl, void, QuarantineObject, (void* asan_pointer))  \
    F(_cdecl, void, DestroyObject, (void* asan_pointer))  \
    F(_cdecl, void, CloneObject,  \
      (const void* src_asan_pointer, const void* dst_asan_pointer))  \
    F(WINAPI, LPVOID, ReadFile,  \
      (HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,  \
       LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped))  \
    F(_cdecl, void, SetInterceptorCallback, (void (*callback)()))

#define DECLARE_ASAN_FUNCTION_PTR(convention, ret, name, args) \
  typedef ret (convention* name##FunctionPtr)args;

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
    memory_error_detected = false;

    // Load the ASAN runtime library.
    base::FilePath asan_rtl_path =
        testing::GetExeRelativePath(L"syzyasan_rtl.dll");
    asan_rtl_ = ::LoadLibrary(asan_rtl_path.value().c_str());
    ASSERT_TRUE(asan_rtl_ != NULL);

    // Load all the functions and assert that we find them.
#define LOAD_ASAN_FUNCTION(convention, ret, name, args)  \
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

  HANDLE heap() { return heap_; }

  // Declare the function pointers.
#define DECLARE_FUNCTION_PTR_VARIABLE(convention, ret, name, args)  \
    static name##FunctionPtr AsanRtlTest::name##Function;

  ASAN_RTL_FUNCTIONS(DECLARE_FUNCTION_PTR_VARIABLE)

#undef DECLARE_FUNCTION_PTR_VARIABLE

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
};

// A helper struct to be passed as a destructor of ASan scoped allocation.
struct ASanDeleteHelper {
  explicit ASanDeleteHelper(AsanRtlTest* asan_rtl)
      : asan_rtl_(asan_rtl) {
  }

  void operator()(void* ptr) {
    asan_rtl_->HeapFreeFunction(asan_rtl_->heap(), 0, ptr);
  }
  AsanRtlTest* asan_rtl_;
};

// A scoped_ptr specialization for the ASan allocations.
template <typename T>
class ScopedASanAlloc : public scoped_ptr<T, ASanDeleteHelper> {
 public:
  explicit ScopedASanAlloc(AsanRtlTest* asan_rtl)
      : scoped_ptr(NULL, ASanDeleteHelper(asan_rtl)) {
  }

  ScopedASanAlloc(AsanRtlTest* asan_rtl, size_t size)
      : scoped_ptr(NULL, ASanDeleteHelper(asan_rtl)) {
    Allocate(asan_rtl, size);
  }

  template <typename T2>
  T2* GetAs() {
    return reinterpret_cast<T2*>(get());
  }

  void Allocate(AsanRtlTest* asan_rtl, size_t size) {
    ASSERT_TRUE(asan_rtl != NULL);
    reset(reinterpret_cast<T*>(
        asan_rtl->HeapAllocFunction(asan_rtl->heap(), 0, size * sizeof(T))));
  }

  T operator[](int i) const {
    CHECK(get() != NULL);
    return get()[i];
  }

  T& operator[](int i) {
    CHECK(get() != NULL);
    return get()[i];
  }
};

// Define the function pointers.
#define DEFINE_FUNCTION_PTR_VARIABLE(convention, ret, name, args)  \
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

void AsanErrorCallback(AsanErrorInfo* error_info) {
  // TODO(sebmarchand): Stash the error info in a fixture-static variable and
  // assert on specific conditions after the fact.
  EXPECT_TRUE(context_before_hook != NULL);
  EXPECT_NE(HeapProxy::UNKNOWN_BAD_ACCESS, error_info->error_type);

  EXPECT_EQ(expected_error_type, error_info->error_type);
  if (error_info->error_type >= HeapProxy::USE_AFTER_FREE) {
    // We should at least have the stack trace of the allocation of this block.
    EXPECT_GT(error_info->alloc_stack_size, 0U);
    EXPECT_NE(0U, error_info->alloc_tid);
    if (error_info->error_type == HeapProxy::USE_AFTER_FREE) {
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
  ExpectEqualContexts(*context_before_hook,
                      error_info->context,
                      CONTEXT_INTEGER | CONTEXT_CONTROL);
}

void AsanErrorCallbackWithoutComparingContext(AsanErrorInfo* error_info) {
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

  CONTEXT context_before_error = {};
  context_before_hook = &context_before_error;
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

void AsanRtlTest::AllocMemoryBuffers(int32 length, int32 element_size) {
  DCHECK(memory_src_ == NULL);
  DCHECK(memory_dst_ == NULL);
  DCHECK_EQ(0, memory_length_);
  DCHECK_EQ(0, memory_size_);

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

TEST_F(AsanRtlTest, AsanCheckMemset) {
  const size_t kAllocSize = 13;
  ScopedASanAlloc<uint8> mem(this, kAllocSize);
  ASSERT_TRUE(mem.get() != NULL);
  memory_error_detected = false;

  SetCallBackFunction(&AsanErrorCallbackWithoutComparingContext);
  EXPECT_EQ(mem.get(), memsetFunction(mem.GetAs<void*>(), 0xAA, kAllocSize));
  EXPECT_FALSE(memory_error_detected);
  for (size_t i = 0; i < kAllocSize; ++i)
    EXPECT_EQ(0xAA, mem[i]);

  // mem[-1] points to the block header, we need to make sure that it doesn't
  // contain the value we're looking for.
  uint8 last_block_header_byte = mem[-1];
  mem[-1] = 0;
  EXPECT_EQ(mem.get() - 1, memsetFunction(mem.get() - 1, 0xBB, kAllocSize));
  EXPECT_TRUE(memory_error_detected);
  for (size_t i = 0; i < kAllocSize; ++i)
    EXPECT_EQ(0xBB, mem[i - 1]);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  mem[-1] = last_block_header_byte;
  ResetLog();

  memory_error_detected = false;
  EXPECT_EQ(mem.get(), memsetFunction(mem.get(), 0xCC, kAllocSize + 1));
  for (size_t i = 0; i < kAllocSize + 1; ++i)
    EXPECT_EQ(0xCC, mem[i]);
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  ResetLog();

}

TEST_F(AsanRtlTest, AsanCheckMemchr) {
  const size_t kAllocSize = 13;
  ScopedASanAlloc<uint8> mem(this, kAllocSize);
  ASSERT_TRUE(mem.get() != NULL);
  memset(mem.get(), 0, kAllocSize);
  mem[4] = 0xAA;
  memory_error_detected = false;

  SetCallBackFunction(&AsanErrorCallbackWithoutComparingContext);
  EXPECT_EQ(mem.get() + 4, memchrFunction(mem.get(), mem[4], kAllocSize));
  EXPECT_EQ(NULL, memchrFunction(mem.get(), mem[4] + 1, kAllocSize));
  EXPECT_FALSE(memory_error_detected);

  // mem[-1] points to the block header, we need to make sure that it doesn't
  // contain the value we're looking for.
  uint8 last_block_header_byte = mem[-1];
  mem[-1] = 0;
  EXPECT_EQ(mem.get() + 4, memchrFunction(mem.get() - 1, mem[4], kAllocSize));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  mem[-1] = last_block_header_byte;
  ResetLog();

  memory_error_detected = false;
  EXPECT_EQ(mem.get() + 4, memchrFunction(mem.get() + 1, mem[4], kAllocSize));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  ResetLog();

}

TEST_F(AsanRtlTest, AsanCheckMemmove) {
  const size_t kAllocSize = 13;
  ScopedASanAlloc<uint8> mem_src(this, kAllocSize);
  ASSERT_TRUE(mem_src.get() != NULL);
  memory_error_detected = false;
  // Fill the array with value going from 0 to kAllocSize;
  for (size_t i = 0; i < kAllocSize; ++i)
    mem_src[i] = i;

  SetCallBackFunction(&AsanErrorCallbackWithoutComparingContext);
  // Shift all the value from one index to the right.
  EXPECT_EQ(mem_src.get() + 1,
            memmoveFunction(mem_src.get() + 1, mem_src.get(), kAllocSize - 1));
  EXPECT_FALSE(memory_error_detected);
  EXPECT_EQ(0, mem_src[0]);
  for (size_t i = 1; i < kAllocSize; ++i)
    EXPECT_EQ(i - 1, mem_src[i]);

  // Re-shift them to the left.
  EXPECT_EQ(mem_src.get(),
            memmoveFunction(mem_src.get(), mem_src.get() + 1, kAllocSize));
  EXPECT_TRUE(memory_error_detected);
  for (size_t i = 0; i < kAllocSize - 1; ++i)
    EXPECT_EQ(i, mem_src[i]);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  ResetLog();

  memory_error_detected = false;
  // Shift them to the left one more time.

  // mem_src[-1] points to the block header, we need to make sure that it
  // doesn't contain the value we're looking for.
  uint8 last_block_header_byte = mem_src[-1];
  mem_src[-1] = 0;
  EXPECT_EQ(mem_src.get() - 1,
            memmoveFunction(mem_src.get() - 1, mem_src.get(), kAllocSize));
  EXPECT_TRUE(memory_error_detected);
  for (int i = -1; i < static_cast<int>(kAllocSize) - 2; ++i)
    EXPECT_EQ(i + 1, mem_src[i]);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  mem_src[-1] = last_block_header_byte;
  ResetLog();
}

TEST_F(AsanRtlTest, AsanCheckMemcpy) {
  const size_t kAllocSize = 13;
  ScopedASanAlloc<uint8> mem_src(this, kAllocSize);
  ASSERT_TRUE(mem_src.get() != NULL);
  ScopedASanAlloc<uint8> mem_dst(this, kAllocSize);
  ASSERT_TRUE(mem_dst.get() != NULL);
  memory_error_detected = false;
  // Fill the array with value going from 0 to kAllocSize;
  for (size_t i = 0; i < kAllocSize; ++i) {
    mem_src[i] = i;
    mem_dst[i] = ~i;
  }

  SetCallBackFunction(&AsanErrorCallbackWithoutComparingContext);
  EXPECT_EQ(mem_dst.get(),
            memcpyFunction(mem_dst.get(), mem_src.get(), kAllocSize));
  EXPECT_FALSE(memory_error_detected);
  for (size_t i = 0; i < kAllocSize; ++i)
    EXPECT_EQ(mem_dst[i], mem_src[i]);

  EXPECT_EQ(mem_dst.get(),
            memcpyFunction(mem_dst.get(), mem_src.get(), kAllocSize + 1));
  EXPECT_TRUE(memory_error_detected);
  for (size_t i = 0; i < kAllocSize + 1; ++i)
    EXPECT_EQ(mem_dst[i], mem_src[i]);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  ResetLog();

  memory_error_detected = false;
  uint8 last_block_header_byte = mem_dst[-1];
  mem_dst[-1] = 0;
  EXPECT_EQ(mem_dst.get(),
            memcpyFunction(mem_dst.get(), mem_src.get() - 1, kAllocSize));
  EXPECT_TRUE(memory_error_detected);
  for (int i = -1; i < static_cast<int>(kAllocSize) - 1; ++i)
    EXPECT_EQ(mem_dst[i + 1], mem_src[i]);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  mem_dst[-1] = last_block_header_byte;
  ResetLog();
}

TEST_F(AsanRtlTest, AsanCheckStrcspn) {
  const char* str_value = "abc1";
  ScopedASanAlloc<char> str(this, strlen(str_value) + 1);
  ASSERT_TRUE(str.get() != NULL);
  strcpy(str.get(), str_value);

  const char* keys_value = "12";
  ScopedASanAlloc<char> keys(this, strlen(keys_value) + 1);
  ASSERT_TRUE(keys.get() != NULL);
  strcpy(keys.get(), keys_value);

  SetCallBackFunction(&AsanErrorCallbackWithoutComparingContext);
  memory_error_detected = false;

  EXPECT_EQ(strcspn(str.get(), keys.get()),
            strcspnFunction(str.get(), keys.get()));
  EXPECT_FALSE(memory_error_detected);

  // str[-1] points to the block header, we need to make sure that it doesn't
  // contain the value \0.
  uint8 last_block_header_byte = str[-1];
  str[-1] = 'a';
  EXPECT_EQ(strcspn(str.get() - 1, keys.get()),
            strcspnFunction(str.get() - 1, keys.get()));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  str[-1] = last_block_header_byte;
  ResetLog();

  memory_error_detected = false;
  size_t keys_len = strlen(keys.get());
  keys[keys_len] = 'a';
  keys[keys_len + 1] = 0;
  EXPECT_EQ(strcspn(str.get(), keys.get()),
            strcspnFunction(str.get(), keys.get()));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  ResetLog();
}

TEST_F(AsanRtlTest, AsanCheckStrlen) {
  const char* str_value = "test_strlen";
  ScopedASanAlloc<char> str(this, strlen(str_value) + 1);
  ASSERT_TRUE(str != NULL);
  strcpy(str.get(), str_value);

  SetCallBackFunction(&AsanErrorCallbackWithoutComparingContext);
  memory_error_detected = false;

  EXPECT_EQ(strlen(str.get()), strlenFunction(str.get()));
  EXPECT_FALSE(memory_error_detected);

  // str[-1] points to the block header, we need to make sure that it doesn't
  // contain the value \0.
  uint8 last_block_header_byte = str[-1];
  str[-1] = 'a';
  EXPECT_EQ(strlen(str.get() - 1), strlenFunction(str.get() - 1));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  str[-1] = last_block_header_byte;
  ResetLog();

  memory_error_detected = false;
  size_t str_len = strlen(str.get());
  str[str_len] = 'a';
  str[str_len + 1] = 0;
  EXPECT_EQ(strlen(str.get()), strlenFunction(str.get()));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  ResetLog();
}

TEST_F(AsanRtlTest, AsanCheckStrrchr) {
  const char* str_value = "test_strrchr";
  ScopedASanAlloc<char> str(this, strlen(str_value) + 1);
  ASSERT_TRUE(str != NULL);
  strcpy(str.get(), str_value);

  SetCallBackFunction(&AsanErrorCallbackWithoutComparingContext);
  memory_error_detected = false;

  EXPECT_EQ(strrchr(str.get(), 'c'), strrchrFunction(str.get(), 'c'));
  EXPECT_FALSE(memory_error_detected);
  EXPECT_EQ(strrchr(str.get(), 'z'), strrchrFunction(str.get(), 'z'));
  EXPECT_FALSE(memory_error_detected);

  // str[-1] points to the block header, we need to make sure that it doesn't
  // contain the value \0.
  uint8 last_block_header_byte = str[-1];
  str[-1] = 'a';
  EXPECT_EQ(strrchr(str.get() - 1, 'c'), strrchrFunction(str.get() - 1, 'c'));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  str[-1] = last_block_header_byte;
  ResetLog();

  memory_error_detected = false;
  size_t str_len = strlen(str.get());
  str[str_len] = 'a';
  str[str_len + 1] = 0;
  EXPECT_EQ(strrchr(str.get(), 'c'), strrchrFunction(str.get(), 'c'));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  ResetLog();
}

TEST_F(AsanRtlTest, AsanCheckStrcmp) {
  const char* str_value = "test_strcmp";
  ScopedASanAlloc<char> str(this, strlen(str_value) + 1);
  ASSERT_TRUE(str.get() != NULL);
  strcpy(str.get(), str_value);

  const char* keys_value = "strcmp";
  ScopedASanAlloc<char> keys(this, strlen(keys_value) + 1);
  ASSERT_TRUE(keys != NULL);
  strcpy(keys.get(), keys_value);

  SetCallBackFunction(&AsanErrorCallbackWithoutComparingContext);
  memory_error_detected = false;

  EXPECT_EQ(strcmp(str.get(), keys.get()),
            strcmpFunction(str.get(), keys.get()));
  EXPECT_FALSE(memory_error_detected);

  // str[-1] points to the block header, we need to make sure that it doesn't
  // contain the value \0.
  uint8 last_block_header_byte = str[-1];
  str[-1] = 'a';
  EXPECT_EQ(strcmp(str.get() - 1, keys.get()),
            strcmpFunction(str.get() - 1, keys.get()));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  str[-1] = last_block_header_byte;
  ResetLog();

  memory_error_detected = false;
  size_t keys_len = strlen(keys.get());
  keys[keys_len] = 'a';
  keys[keys_len + 1] = 0;
  EXPECT_EQ(strcmp(str.get(), keys.get()),
            strcmpFunction(str.get(), keys.get()));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  ResetLog();
}

TEST_F(AsanRtlTest, AsanCheckStrpbrk) {
  const char* str_value = "test_strpbrk";
  ScopedASanAlloc<char> str(this, strlen(str_value) + 1);
  ASSERT_TRUE(str != NULL);
  strcpy(str.get(), str_value);

  const char* keys_value = "strpbrk";
  ScopedASanAlloc<char> keys(this, strlen(keys_value) + 1);
  ASSERT_TRUE(keys != NULL);
  strcpy(keys.get(), keys_value);

  SetCallBackFunction(&AsanErrorCallbackWithoutComparingContext);
  memory_error_detected = false;

  EXPECT_EQ(strpbrk(str.get(), keys.get()),
            strpbrkFunction(str.get(), keys.get()));
  EXPECT_FALSE(memory_error_detected);

  // str[-1] points to the block header, we need to make sure that it doesn't
  // contain the value \0.
  uint8 last_block_header_byte = str[-1];
  str[-1] = 'a';
  EXPECT_EQ(strpbrk(str.get() - 1, keys.get()),
            strpbrkFunction(str.get() - 1, keys.get()));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  str[-1] = last_block_header_byte;
  ResetLog();

  memory_error_detected = false;
  size_t keys_len = strlen(keys.get());
  keys[keys_len] = 'a';
  keys[keys_len + 1] = 0;
  EXPECT_EQ(strpbrk(str.get(), keys.get()),
            strpbrkFunction(str.get(), keys.get()));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  ResetLog();
}

TEST_F(AsanRtlTest, AsanCheckStrstr) {
  const char* str_value = "test_strstr";
  ScopedASanAlloc<char> str(this, strlen(str_value) + 1);
  ASSERT_TRUE(str != NULL);
  strcpy(str.get(), str_value);

  const char* keys_value = "strstr";
  ScopedASanAlloc<char> keys(this, strlen(keys_value) + 1);
  ASSERT_TRUE(keys != NULL);
  strcpy(keys.get(), keys_value);

  SetCallBackFunction(&AsanErrorCallbackWithoutComparingContext);
  memory_error_detected = false;

  EXPECT_EQ(strstr(str.get(), keys.get()),
            strstrFunction(str.get(), keys.get()));
  EXPECT_FALSE(memory_error_detected);

  // str[-1] points to the block header, we need to make sure that it doesn't
  // contain the value \0.
  uint8 last_block_header_byte = str[-1];
  str[-1] = 'a';
  EXPECT_EQ(strstr(str.get() - 1, keys.get()),
            strstrFunction(str.get() - 1, keys.get()));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  str[-1] = last_block_header_byte;
  ResetLog();

  memory_error_detected = false;
  size_t keys_len = strlen(keys.get());
  keys[keys_len] = 'a';
  keys[keys_len + 1] = 0;
  EXPECT_EQ(strstr(str.get(), keys.get()),
            strstrFunction(str.get(), keys.get()));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  ResetLog();
}

TEST_F(AsanRtlTest, AsanCheckStrspn) {
  const char* str_value = "test_strspn";
  ScopedASanAlloc<char> str(this, strlen(str_value) + 1);
  ASSERT_TRUE(str != NULL);
  strcpy(str.get(), str_value);

  const char* keys_value = "strspn";
  ScopedASanAlloc<char> keys(this, strlen(keys_value) + 1);
  ASSERT_TRUE(keys != NULL);
  strcpy(keys.get(), keys_value);

  SetCallBackFunction(&AsanErrorCallbackWithoutComparingContext);
  memory_error_detected = false;

  EXPECT_EQ(strspn(str.get(), keys.get()),
            strspnFunction(str.get(), keys.get()));
  EXPECT_FALSE(memory_error_detected);

  // str[-1] points to the block header, we need to make sure that it doesn't
  // contain the value \0.
  uint8 last_block_header_byte = str[-1];
  str[-1] = 'a';
  EXPECT_EQ(strspn(str.get() - 1, keys.get()),
            strspnFunction(str.get() - 1, keys.get()));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  str[-1] = last_block_header_byte;
  ResetLog();

  memory_error_detected = false;
  size_t keys_len = strlen(keys.get());
  keys[keys_len] = 'a';
  keys[keys_len + 1] = 0;
  EXPECT_EQ(strspn(str.get(), keys.get()),
            strspnFunction(str.get(), keys.get()));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  ResetLog();
}

TEST_F(AsanRtlTest, AsanCheckStrncpy) {
  const char* str_value = "test_strncpy";
  ScopedASanAlloc<char> source(this, strlen(str_value) + 1);
  ASSERT_TRUE(source != NULL);
  strcpy(source.get(), str_value);

  const char* long_str_value = "test_strncpy_long_source";
  ScopedASanAlloc<char> long_source(this, strlen(long_str_value) + 1);
  ASSERT_TRUE(long_source.get() != NULL);
  strcpy(long_source.get(), long_str_value);

  ScopedASanAlloc<char> destination(this, strlen(str_value) + 1);
  ASSERT_TRUE(destination != NULL);

  SetCallBackFunction(&AsanErrorCallbackWithoutComparingContext);
  memory_error_detected = false;

  EXPECT_EQ(destination.get(),
            strncpyFunction(destination.get(),
                            source.get(),
                            strlen(str_value)));
  EXPECT_FALSE(memory_error_detected);

  // Test an underflow on the source.
  uint8 last_block_header_byte = source[-1];
  source[-1] = 'a';
  EXPECT_EQ(destination.get(),
            strncpyFunction(destination.get(),
                            source.get() - 1,
                            strlen(str_value)));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  source[-1] = last_block_header_byte;
  ResetLog();

  // Test an underflow on the destination.
  memory_error_detected = false;
  last_block_header_byte = destination[-1];
  destination[-1] = 'a';
  EXPECT_EQ(destination.get() - 1,
            strncpyFunction(destination.get() - 1,
                            source.get(),
                            strlen(str_value)));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  destination[-1] = last_block_header_byte;
  ResetLog();

  // Test an overflow on the destination.
  memory_error_detected = false;
  EXPECT_EQ(destination.get(),
            strncpyFunction(destination.get(),
                            long_source.get(),
                            strlen(long_str_value)));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  ResetLog();

  // Another overflow on the destination.
  memory_error_detected = false;
  EXPECT_EQ(destination,
            strncpyFunction(destination.get(),
                            source.get(),
                            strlen(str_value) + 2));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  ResetLog();

  // Test an overflow on the source.
  size_t source_len = strlen(source.get());
  source[source_len] = 'a';
  source[source_len + 1] = 0;
  memory_error_detected = false;
  EXPECT_EQ(destination.get(), strncpyFunction(destination.get(),
                                               source.get(),
                                               strlen(source.get()) + 1));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  ResetLog();

  memory_error_detected = false;
  EXPECT_EQ(destination.get(), strncpyFunction(destination.get(),
                                               source.get(),
                                               strlen(source.get())));
  EXPECT_FALSE(memory_error_detected);
  ResetLog();
}

TEST_F(AsanRtlTest, AsanCheckStrncat) {
  const char* prefix_value = "test_";
  const char* suffix_value = "strncat";
  char buffer[64];

  ScopedASanAlloc<char> mem(this,
                            strlen(prefix_value) + strlen(suffix_value) + 1);
  ASSERT_TRUE(mem != NULL);
  strcpy(mem.get(), prefix_value);
  strcpy(buffer, prefix_value);

  ScopedASanAlloc<char> suffix(this, strlen(suffix_value) + 1);
  ASSERT_TRUE(mem.get() != NULL);
  strcpy(suffix.get(), suffix_value);

  SetCallBackFunction(&AsanErrorCallbackWithoutComparingContext);
  memory_error_detected = false;

  EXPECT_EQ(mem.get(),
      strncatFunction(mem.get(), suffix.get(), strlen(suffix_value)));
  EXPECT_FALSE(memory_error_detected);
  EXPECT_STRCASEEQ(
      strncat(buffer, suffix.get(), strlen(suffix_value)), mem.get());

  // Test an underflow on the suffix.
  suffix[-1] = 'a';
  uint8 last_block_header_byte = suffix[-1];
  strcpy(mem.get(), prefix_value);
  strcpy(buffer, prefix_value);
  EXPECT_EQ(mem.get(),
      strncatFunction(mem.get(), suffix.get() - 1, strlen(suffix_value)));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  EXPECT_STRCASEEQ(
      strncat(buffer, suffix.get() - 1, strlen(suffix_value)), mem.get());
  suffix[-1] = last_block_header_byte;
  ResetLog();

  // Test an underflow on the destination.
  memory_error_detected = false;
  last_block_header_byte = mem[-1];
  mem[-1] = 'a';
  strcpy(mem.get(), prefix_value);
  strcpy(buffer, prefix_value);
  EXPECT_EQ(mem.get() - 1,
            strncatFunction(mem.get() - 1, suffix.get(), strlen(suffix_value)));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  EXPECT_STRCASEEQ(
      strncat(buffer, suffix.get(), strlen(suffix_value)), mem.get());
  mem[-1] = last_block_header_byte;
  ResetLog();

  // Test an overflow on the suffix.
  size_t suffix_len = strlen(suffix.get());
  suffix[suffix_len] = 'a';
  suffix[suffix_len + 1] = 0;
  memory_error_detected = false;
  strcpy(mem.get(), prefix_value);
  strcpy(buffer, prefix_value);
  EXPECT_EQ(mem.get(),
      strncatFunction(mem.get(), suffix.get(), strlen(suffix.get()) + 1));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  EXPECT_STRCASEEQ(
      strncat(buffer, suffix.get(), strlen(suffix.get())), mem.get());
  ResetLog();
  suffix[suffix_len] = 0;

  // Test an overflow on the destination.
  memory_error_detected = false;
  strcpy(mem.get(), prefix_value);
  strcpy(buffer, prefix_value);
  size_t prefix_len = strlen(prefix_value);
  mem[prefix_len] = 'a';
  mem[prefix_len + 1] = 0;
  buffer[prefix_len] = 'a';
  buffer[prefix_len + 1] = 0;
  EXPECT_EQ(mem.get(),
      strncatFunction(mem.get(), suffix.get(), strlen(suffix.get())));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  EXPECT_STRCASEEQ(
      strncat(buffer, suffix.get(), strlen(suffix.get())), mem.get());
  ResetLog();
}

namespace {

// Helps to test the asan_ReadFile function.
class AsanRtlReadFileTest : public AsanRtlTest {
 public:
  typedef AsanRtlTest Super;

  AsanRtlReadFileTest() : temp_file_handle_(INVALID_HANDLE_VALUE) {
  }

  void SetUp() OVERRIDE {
    Super::SetUp();
    SetCallBackFunction(&AsanErrorCallbackWithoutComparingContext);
    ASSERT_NO_FATAL_FAILURE(CreateTempFile());
  }

  void CreateTempFile() {
    ASSERT_EQ(kTestStringLength,
              file_util::WriteFile(temp_file_.path(),
                                   kTestString,
                                   kTestStringLength));

    temp_file_handle_.Set(::CreateFile(temp_file_.path().value().c_str(),
        GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL));

    ASSERT_NE(INVALID_HANDLE_VALUE, temp_file_handle_.Get());
  }

  static const char kTestString[];
  static const size_t kTestStringLength;

 protected:
  testing::ScopedTempFile temp_file_;

  base::win::ScopedHandle temp_file_handle_;
};

const char AsanRtlReadFileTest::kTestString[] = "Test of asan_ReadFile";
const size_t AsanRtlReadFileTest::kTestStringLength =
    sizeof(AsanRtlReadFileTest::kTestString);

}  // namespace

TEST_F(AsanRtlReadFileTest, AsanReadFile) {
  // Test that the function works correctly with valid parameters. In this case
  // we don't pass an OVERLAPPED structure to the function.
  DWORD bytes_read = 0;
  ScopedASanAlloc<char> alloc(this, kTestStringLength);
  EXPECT_TRUE(ReadFileFunction(temp_file_handle_.Get(),
                               alloc.get(),
                               kTestStringLength,
                               &bytes_read,
                               NULL));
  EXPECT_EQ(kTestStringLength, bytes_read);
  EXPECT_FALSE(memory_error_detected);
}

TEST_F(AsanRtlReadFileTest, AsanReadFileWithOverlapped) {
  ScopedASanAlloc<char> alloc(this, kTestStringLength);
  // Test that the function works correctly with valid parameters. Here we pass
  // an OVERLAPPED structure to the function, which indicates that we want to do
  // the read from a given offset.
  OVERLAPPED overlapped = {};
  // Start the read from the middle of the test string.
  const size_t kOffset = kTestStringLength / 2;
  overlapped.Offset = kOffset;
  DWORD bytes_read = 0;
  EXPECT_TRUE(ReadFileFunction(temp_file_handle_.Get(),
                               alloc.get(),
                               kTestStringLength,
                               &bytes_read,
                               &overlapped));
  EXPECT_EQ(kTestStringLength - kOffset, bytes_read);
  EXPECT_FALSE(memory_error_detected);
}

TEST_F(AsanRtlReadFileTest, AsanReadFileOverflow) {
  // Test that the function works correctly with valid parameters. In this case
  // we don't pass an OVERLAPPED structure to the function.
  DWORD bytes_read = 0;
  ScopedASanAlloc<char> alloc(this, kTestStringLength);
  EXPECT_TRUE(ReadFileFunction(temp_file_handle_.Get(),
                               alloc.get(),
                               kTestStringLength + 1,
                               &bytes_read,
                               NULL));
  EXPECT_EQ(kTestStringLength, bytes_read);
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
}

TEST_F(AsanRtlReadFileTest, AsanReadFileUAFOnOverlapped) {
  ScopedASanAlloc<char> alloc(this, kTestStringLength);
  // Test an use-after-free on the overlapped structure.
  ScopedASanAlloc<OVERLAPPED> overlapped(this, sizeof(OVERLAPPED));
  // Start the read from the middle of the test string.
  const size_t kOffset = kTestStringLength / 2;
  overlapped->Offset = kOffset;
  DWORD bytes_read = 0;
  OVERLAPPED* overlapped_ptr = overlapped.get();
  overlapped.reset(NULL);
  EXPECT_TRUE(ReadFileFunction(temp_file_handle_.Get(),
                               alloc.get(),
                               kTestStringLength,
                               &bytes_read,
                               overlapped_ptr));
  EXPECT_EQ(kTestStringLength - kOffset, bytes_read);
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapUseAfterFree));
}

TEST_F(AsanRtlReadFileTest, AsanReadFileUseAfterFree) {
  // Test if an use-after-free on the destination buffer is correctly detected.
  DWORD bytes_read = 0;
  ScopedASanAlloc<char> alloc(this, kTestStringLength);
  char* alloc_ptr = alloc.get();
  alloc.reset(NULL);
  EXPECT_TRUE(ReadFileFunction(temp_file_handle_.Get(),
                               alloc_ptr,
                               kTestStringLength + 1,
                               &bytes_read,
                               NULL));
  EXPECT_EQ(kTestStringLength, bytes_read);
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapUseAfterFree));
}

namespace {

typedef ScopedASanAlloc<char>* AsanReadFileCallbackData;
AsanReadFileCallbackData callback_data = NULL;

void AsanReadFileCallback() {
  ASSERT_TRUE(callback_data != NULL);
  callback_data->reset(NULL);
}

}  // namespace

TEST_F(AsanRtlReadFileTest, AsanReadFileUAFAfterInternalCall) {
  // This test makes sure that use-after-free on the input buffer given to
  // the ReadFile function are correctly detected.
  ScopedASanAlloc<char> alloc(this, kTestStringLength);
  memset(alloc.get(), 0, kTestStringLength);

  callback_data = &alloc;

  // Set the callback that we want to use once the internal call to ReadFile
  // returns.
  SetInterceptorCallbackFunction(&AsanReadFileCallback);

  // Read from the file using the interceptor, this will call the ReadFile
  // callback once the internal call to ReadFile, and result in freeing the
  // buffer.
  DWORD bytes_read = 0;
  EXPECT_TRUE(ReadFileFunction(temp_file_handle_.Get(),
                               alloc.get(),
                               kTestStringLength,
                               &bytes_read,
                               NULL));

  EXPECT_EQ(kTestStringLength, bytes_read);

  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapUseAfterFree));

  SetInterceptorCallbackFunction(NULL);
}

}  // namespace asan
}  // namespace agent
