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

#include "base/compiler_specific.h"
#include "base/logging.h"
#include "base/rand_util.h"
#include "base/debug/debugger.h"
#include "gtest/gtest.h"
#include "syzygy/agent/asan/asan_shadow.h"
#include "syzygy/core/unittest_util.h"

namespace agent {
namespace asan {

namespace {

// Shorthand for discussing all the asan runtime functions.
#define ASAN_RTL_FUNCTIONS(F)  \
    F(HANDLE, HeapCreate,  \
      (DWORD options, SIZE_T initial_size, SIZE_T maximum_size))  \
    F(BOOL, HeapDestroy,   \
      (HANDLE heap))  \
    F(LPVOID, HeapAlloc,   \
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
      (void (*callback)()))  \

#define DECLARE_ASAN_FUNCTION_PTR(ret, name, args) \
    typedef ret (WINAPI* name##FunctionPtr)args;

ASAN_RTL_FUNCTIONS(DECLARE_ASAN_FUNCTION_PTR)

#undef DECLARE_ASAN_FUNCTION_PTR

class AsanRtlTest : public testing::Test {
 public:
  AsanRtlTest() : asan_rtl_(NULL), heap_(NULL) {
  }

  void SetUp() OVERRIDE {
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
  }

 protected:
  // Arbitrary constant for all size limit.
  static const size_t kMaxAllocSize = 134584;

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

} // namespace

TEST_F(AsanRtlTest, CreateDestroy) {
  HANDLE heap = HeapCreateFunction(0, 0, 0);
  ASSERT_TRUE(heap != NULL);
  ASSERT_TRUE(HeapDestroyFunction(heap));
}

TEST_F(AsanRtlTest, Alloc) {
  for (size_t size = 10; size < kMaxAllocSize; size = size * 5 + 123) {
    void* mem = HeapAllocFunction(heap_, 0, size);
    ASSERT_TRUE(mem != NULL);
    memset(mem, '\0', size);

    size_t new_size = size;
    while (new_size == size)
      new_size = base::RandInt(size / 2, size * 2);

    void* new_mem = HeapReAllocFunction(heap_, 0, mem, new_size);
    ASSERT_TRUE(new_mem != NULL);
    ASSERT_NE(mem, new_mem);

    ASSERT_TRUE(HeapFreeFunction(heap_, 0, new_mem));
  }
}

TEST_F(AsanRtlTest, Size) {
  for (size_t size = 10; size < kMaxAllocSize; size = size * 5 + 123) {
    void* mem = HeapAllocFunction(heap_, 0, size);
    ASSERT_TRUE(mem != NULL);
    ASSERT_EQ(size, HeapSizeFunction(heap_, 0, mem));
    ASSERT_TRUE(HeapFreeFunction(heap_, 0, mem));
  }
}

TEST_F(AsanRtlTest, Validate) {
  for (size_t size = 10; size < kMaxAllocSize; size = size * 5 + 123) {
    void* mem = HeapAllocFunction(heap_, 0, size);
    ASSERT_TRUE(mem != NULL);
    ASSERT_TRUE(HeapValidateFunction(heap_, 0, mem));
    ASSERT_TRUE(HeapFreeFunction(heap_, 0, mem));
  }
}

TEST_F(AsanRtlTest, Compact) {
  // Compact should return a non-zero size.
  ASSERT_LT(0U, HeapCompactFunction(heap_, 0));

  // TODO(siggi): It may not be possible to allocate the size returned due
  //     to padding - fix and test.
}

TEST_F(AsanRtlTest, LockUnlock) {
  // We can't really test these, aside from not crashing.
  ASSERT_TRUE(HeapLockFunction(heap_));
  ASSERT_TRUE(HeapUnlockFunction(heap_));
}

TEST_F(AsanRtlTest, Walk) {
  // We assume at least two entries to walk through.
  PROCESS_HEAP_ENTRY entry = {};
  ASSERT_TRUE(HeapWalkFunction(heap_, &entry));
  ASSERT_TRUE(HeapWalkFunction(heap_, &entry));
}

TEST_F(AsanRtlTest, SetQueryInformation) {
  ULONG compat_flag = -1;
  unsigned long ret = 0;
  // Get the current value of the compat flag.
  ASSERT_TRUE(
      HeapQueryInformationFunction(heap_, HeapCompatibilityInformation,
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
      HeapSetInformationFunction(heap_, HeapCompatibilityInformation,
                                 &compat_flag, sizeof(compat_flag)));
}

namespace {

// The access check function invoked by the below.
FARPROC check_access_fn = NULL;
// A flag used in asan callback to ensure that a memory error has been detected.
bool memory_error_detected = false;

void __declspec(naked) CheckAccessAndCaptureContexts(CONTEXT* before,
                                                     CONTEXT* after,
                                                     void* ptr) {
  __asm {
    // Capture the CPU context before calling the access check function.
    push dword ptr[esp + 0x4]
    call dword ptr[RtlCaptureContext]

    // Restore EAX, which is stomped by RtlCaptureContext.
    mov eax, dword ptr[esp + 0x4]
    mov eax, dword ptr[eax + CONTEXT.Eax]

    // Push eax as we're required to do by the custom calling convention.
    push eax
    // Ptr is the pointer to check.
    mov eax, dword ptr[esp + 0x10]
    // Call through.
    call dword ptr[check_access_fn + 0]

    // Capture the CPU context after calling the access check function.
    push dword ptr[esp + 0x8]
    call dword ptr[RtlCaptureContext]

    ret
  }
}

void __declspec(naked) CheckAccess(void* ptr) {
  __asm {
    // Push eax as we're required to do by the custom calling convention.
    push eax
    // Ptr is the pointer to check.
    mov eax, dword ptr[esp + 0x8]
    // Call through.
    call dword ptr[check_access_fn + 0]

    ret
  }
}

void CheckAccessAndCompareContexts(void* ptr) {
  CONTEXT before = {};
  CONTEXT after = {};

  CheckAccessAndCaptureContexts(&before, &after, ptr);

  EXPECT_EQ(before.SegGs, after.SegGs);
  EXPECT_EQ(before.SegFs, after.SegFs);
  EXPECT_EQ(before.SegEs, after.SegEs);
  EXPECT_EQ(before.SegDs, after.SegDs);

  EXPECT_EQ(before.Edi, after.Edi);
  EXPECT_EQ(before.Esi, after.Esi);
  EXPECT_EQ(before.Ebx, after.Ebx);
  EXPECT_EQ(before.Edx, after.Edx);
  EXPECT_EQ(before.Ecx, after.Ecx);
  EXPECT_EQ(before.Eax, after.Eax);

  EXPECT_EQ(before.Ebp, after.Ebp);
  EXPECT_EQ(before.Eip, after.Eip);
  EXPECT_EQ(before.SegCs, after.SegCs);
  EXPECT_EQ(before.EFlags, after.EFlags);
  EXPECT_EQ(before.Esp, after.Esp);
  EXPECT_EQ(before.SegSs, after.SegSs);
}

void AsanErrorCallback() {
  EXPECT_FALSE(memory_error_detected);
  memory_error_detected = true;
}

void AssertMemoryErrorIsDetected(void* ptr) {
  memory_error_detected = false;
  CheckAccess(ptr);
  ASSERT_TRUE(memory_error_detected);
}

}  // namespace

TEST_F(AsanRtlTest, asan_check_good_access) {
  check_access_fn = ::GetProcAddress(asan_rtl_, "asan_check_access");
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

TEST_F(AsanRtlTest, asan_check_bad_access) {
  check_access_fn = ::GetProcAddress(asan_rtl_, "asan_check_access");
  ASSERT_TRUE(check_access_fn != NULL);

  const size_t kAllocSize = 13;
  uint8* mem = reinterpret_cast<uint8*>(
      HeapAllocFunction(heap_, 0, kAllocSize));
  ASSERT_TRUE(mem != NULL);

  SetCallBackFunction(&AsanErrorCallback);
  AssertMemoryErrorIsDetected(mem - 1);
  AssertMemoryErrorIsDetected(mem + kAllocSize);
  ASSERT_TRUE(HeapFreeFunction(heap_, 0, mem));
}

} // namespace asan
} // namespace agent
