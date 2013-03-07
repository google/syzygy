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
      (void (*callback)(CONTEXT* context)))  \

#define DECLARE_ASAN_FUNCTION_PTR(ret, name, args) \
    typedef ret (WINAPI* name##FunctionPtr)args;

ASAN_RTL_FUNCTIONS(DECLARE_ASAN_FUNCTION_PTR)

#undef DECLARE_ASAN_FUNCTION_PTR

class AsanRtlTest : public testing::TestWithAsanLogger {
 public:
  AsanRtlTest() : asan_rtl_(NULL), heap_(NULL) {
  }

  void SetUp() OVERRIDE {
    testing::TestWithAsanLogger::SetUp();

    // Load the ASAN runtime library.
    FilePath asan_rtl_path = testing::GetExeRelativePath(L"asan_rtl.dll");
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
  // The ASAN runtime module to test.
  HMODULE asan_rtl_;

  // Scratch heap handle valid from SetUp to TearDown.
  HANDLE heap_;

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

void __declspec(naked) CheckAccessAndCaptureContexts(CONTEXT* before,
                                                     CONTEXT* after,
                                                     void* ptr) {
  __asm {
    // Capture the CPU context before calling the access check function.
    push dword ptr[esp + 0x4]
    call dword ptr[RtlCaptureContext]

    // Restore eax, which is stomped by RtlCaptureContext.
    mov eax, dword ptr[esp + 0x4]
    mov eax, dword ptr[eax + CONTEXT.Eax]

    // Push edx as we're required to do by the custom calling convention.
    push edx
    // Ptr is the pointer to check.
    mov edx, dword ptr[esp + 0x10]
    // Call through.
    call dword ptr[check_access_fn + 0]

    // Capture the CPU context after calling the access check function.
    push dword ptr[esp + 0x8]
    call dword ptr[RtlCaptureContext]

    ret
  }
}

// We need to disable this warning due to the label in the inline assembly who
// is not compatible with the global optimization.
#pragma warning(push)
#pragma warning(disable: 4740)
void __declspec(naked) CheckAccess(void* ptr) {
  DCHECK(context_before_hook != NULL);
  __asm {
    push dword ptr[context_before_hook]
    call dword ptr[RtlCaptureContext]

    // Fix the values of ebp, esp and eip in the context to make sure they are
    // the same as what they'll be after the call to the hook.
    mov eax, dword ptr[context_before_hook]
    mov dword ptr[eax + CONTEXT.Ebp], ebp
    mov dword ptr[eax + CONTEXT.Esp], esp
    mov dword ptr[eax + CONTEXT.Eip], offset expected_eip

    // Restore eax, which is stomped by RtlCaptureContext.
    mov eax, dword ptr[eax + CONTEXT.Eax]

    // Push edx as we're required to do by the custom calling convention.
    push edx
    // Ptr is the pointer to check.
    mov edx, dword ptr[esp + 0x8]
    // Call through.
    call dword ptr[check_access_fn + 0]
expected_eip:
    ret
  }
}
#pragma warning(pop)

void CheckAccessAndCompareContexts(void* ptr) {
  CONTEXT before = {};
  CONTEXT after = {};

  CheckAccessAndCaptureContexts(&before, &after, ptr);

  ExpectEqualContexts(before, after, CONTEXT_FULL);
}

void AsanErrorCallback(CONTEXT* context) {
  EXPECT_TRUE(context != NULL);
  EXPECT_TRUE(context_before_hook != NULL);

  EXPECT_FALSE(memory_error_detected);
  memory_error_detected = true;
  ExpectEqualContexts(*context_before_hook,
                      *context,
                      CONTEXT_INTEGER | CONTEXT_CONTROL);
}

void AssertMemoryErrorIsDetected(void* ptr) {
  memory_error_detected = false;
  CheckAccess(ptr);
  ASSERT_TRUE(memory_error_detected);
}

}  // namespace

TEST_F(AsanRtlTest, AsanCheckGoodAccess) {
  check_access_fn =
      ::GetProcAddress(asan_rtl_, "asan_check_4_byte_read_access");
  ASSERT_TRUE(check_access_fn != NULL);

  // Run through access checking an allocation that's larger than our
  // block size (8), but not a multiple thereof to exercise all paths
  // in the access check function (save for the failure path).
  const size_t kAllocSize = 13;
  uint8* mem = reinterpret_cast<uint8*>(
      HeapAllocFunction(heap_, 0, kAllocSize));
  ASSERT_TRUE(mem != NULL);

  for (size_t i = 0; i < kAllocSize; ++i) {
    ASSERT_NO_FATAL_FAILURE(CheckAccessAndCompareContexts(mem + i));
  }

  ASSERT_TRUE(HeapFreeFunction(heap_, 0, mem));
}

TEST_F(AsanRtlTest, AsanCheckBadAccess) {
  check_access_fn =
      ::GetProcAddress(asan_rtl_, "asan_check_4_byte_read_access");
  ASSERT_TRUE(check_access_fn != NULL);

  const size_t kAllocSize = 13;
  uint8* mem = reinterpret_cast<uint8*>(
      HeapAllocFunction(heap_, 0, kAllocSize));
  ASSERT_TRUE(mem != NULL);

  CONTEXT context_before_error = {};
  context_before_hook = &context_before_error;
  SetCallBackFunction(&AsanErrorCallback);
  AssertMemoryErrorIsDetected(mem - 1);
  AssertMemoryErrorIsDetected(mem + kAllocSize);
  ASSERT_TRUE(HeapFreeFunction(heap_, 0, mem));
  ASSERT_TRUE(LogContains("heap-buffer-underflow"));
}

} // namespace asan
} // namespace agent
