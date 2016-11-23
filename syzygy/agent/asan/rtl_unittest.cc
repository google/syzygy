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
#include "syzygy/agent/asan/heap_checker.h"
#include "syzygy/agent/asan/rtl_impl.h"
#include "syzygy/agent/asan/runtime.h"
#include "syzygy/agent/asan/unittest_util.h"
#include "syzygy/testing/laa.h"

namespace agent {
namespace asan {

namespace {

using testing::AsanBlockInfoVector;
using testing::ClangMemoryAccessorTester;
using testing::MemoryAccessorTester;
using testing::ScopedAsanAlloc;
#ifndef _WIN64
using testing::SyzyAsanMemoryAccessorTester;
#endif

// Helper class to check an Asan function. This allows to test different probes
// with different calling conventions.
class AsanFunctionCheck {
 public:
  virtual ~AsanFunctionCheck() {}

  // Memory accessor tested that should be used.
  virtual MemoryAccessorTester* tester() = 0;

  // Name of the function that should be tested.
  virtual const char* function_name() = 0;

  // Try to access |ptr| via |access_fn|.
  virtual void CheckAccess(FARPROC access_fn, void* ptr) = 0;
};

#ifndef _WIN64
// Specialization of the AsanFunctionCheck class to test the probes with the
// SyzyAsan custom calling convention (value to check in EDX).
class SyzyAsanFunctionCheck : public AsanFunctionCheck {
 public:
  MemoryAccessorTester* tester() override { return &tester_; }

  // Name of one of the SyzyAsan probes.
  const char* function_name() override {
    return "asan_check_1_byte_read_access";
  }

  // Check access and ensure that the context hasn't been altered.
  void CheckAccess(FARPROC access_fn, void* ptr) override {
    tester_.CheckAccessAndCompareContexts(access_fn, ptr);
  }

 private:
  // The tester used by this function checker.
  SyzyAsanMemoryAccessorTester tester_;
};
#endif

// Specialization of the AsanFunctionCheck class to test the probes with the
// cdecl calling convention (value to check on the stack).
class ClangAsanFunctionCheck : public AsanFunctionCheck {
 public:
  MemoryAccessorTester* tester() override { return &tester_; }

  // Name of one of the Clang-Asan probes.
  const char* function_name() override { return "__asan_load1"; }

  // Check the access
  void CheckAccess(FARPROC access_fn, void* ptr) override {
    tester_.CheckAccess(access_fn, ptr);
  }

 private:
  // The tester used by this function checker.
  ClangMemoryAccessorTester tester_;
};

// An arbitrary size for the buffer we allocate in the different unittests.
const size_t kAllocSize = 13;

class AsanRtlTest : public testing::TestAsanRtl {
 public:
  AsanRtlTest() : memory_src_(NULL), memory_dst_(NULL), memory_length_(0),
      memory_size_(0) { }

  virtual ~AsanRtlTest() {}

  void SetUp() override {
    testing::TestAsanRtl::SetUp();

    // Setup the callback to detect invalid accesses.
    SetCallBackFunction(&MemoryAccessorTester::AsanErrorCallback);
  }

 protected:
  void AllocMemoryBuffers(int32_t length, int32_t element_size);
  void FreeMemoryBuffers();

  // Memory buffers used to test special instructions.
  void* memory_src_;
  void* memory_dst_;
  int32_t memory_length_;
  int32_t memory_size_;
};

// Specialization of the AsanRtlTest for the test that should be done with
// different sets of probes.
template <class T>
class AsanRtlTypedTest : public AsanRtlTest {
 public:
  ~AsanRtlTypedTest() override {}

 protected:
  T tester_;
};

// Access functions checker that should be used in the typed tests. On 32-bit
// we need to test both the SyzyAsan and the Clang-Asan probes and in 64-bit
// we only test the Clang-Asan ones.
#ifndef _WIN64
typedef ::testing::Types<SyzyAsanFunctionCheck, ClangAsanFunctionCheck>
    CheckAccessTypes;
#else
typedef ::testing::Types<ClangAsanFunctionCheck> CheckAccessTypes;
#endif
TYPED_TEST_CASE(AsanRtlTypedTest, CheckAccessTypes);

void AsanRtlTest::AllocMemoryBuffers(int32_t length, int32_t element_size) {
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
  ::memset(memory_src_, 0, memory_size_);
  ::memset(memory_dst_, 0, memory_size_);
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

}  // namespace

TEST_F(AsanRtlTest, GetProcessHeap) {
  agent::asan::AsanRuntime* runtime = GetActiveRuntimeFunction();
  ASSERT_NE(reinterpret_cast<agent::asan::AsanRuntime*>(NULL), runtime);
  HANDLE asan_heap_handle = GetProcessHeapFunction();
  EXPECT_NE(static_cast<HANDLE>(NULL), asan_heap_handle);
  EXPECT_EQ(reinterpret_cast<HANDLE>(runtime->GetProcessHeap()),
                                     asan_heap_handle);
}

TYPED_TEST(AsanRtlTypedTest, AsanCheckGoodAccess) {
  FARPROC check_access_fn =
      ::GetProcAddress(asan_rtl_, tester_.function_name());
  ASSERT_TRUE(check_access_fn != NULL);

  // Run through access checking an allocation that's larger than our
  // block size (8), but not a multiple thereof to exercise all paths
  // in the access check function (save for the failure path).
  ScopedAsanAlloc<uint8_t> mem(this, kAllocSize);
  ASSERT_TRUE(mem.get() != NULL);

  for (size_t i = 0; i < kAllocSize; ++i) {
    ASSERT_NO_FATAL_FAILURE(
        tester_.CheckAccess(check_access_fn, mem.get() + i));
  }
}

TYPED_TEST(AsanRtlTypedTest, AsanCheckHeapBufferOverflow) {
  FARPROC check_access_fn =
      ::GetProcAddress(asan_rtl_, tester_.function_name());
  ASSERT_TRUE(check_access_fn != NULL);

  ScopedAsanAlloc<uint8_t> mem(this, kAllocSize);
  ASSERT_TRUE(mem.get() != NULL);

  tester_.tester()->AssertMemoryErrorIsDetected(
      check_access_fn, mem.get() + kAllocSize, HEAP_BUFFER_OVERFLOW);
  EXPECT_TRUE(LogContains("previously allocated here"));
  EXPECT_TRUE(LogContains(kHeapBufferOverFlow));
}

TYPED_TEST(AsanRtlTypedTest, AsanCheckHeapBufferUnderflow) {
  FARPROC check_access_fn =
      ::GetProcAddress(asan_rtl_, tester_.function_name());
  ASSERT_TRUE(check_access_fn != NULL);

  ScopedAsanAlloc<uint8_t> mem(this, kAllocSize);
  ASSERT_TRUE(mem.get() != NULL);

  tester_.tester()->AssertMemoryErrorIsDetected(check_access_fn, mem.get() - 1,
                                                HEAP_BUFFER_UNDERFLOW);
  EXPECT_TRUE(LogContains("previously allocated here"));
  EXPECT_TRUE(LogContains(kHeapBufferUnderFlow));
}

TYPED_TEST(AsanRtlTypedTest, AsanCheckUseAfterFree) {
  FARPROC check_access_fn =
      ::GetProcAddress(asan_rtl_, tester_.function_name());
  ASSERT_TRUE(check_access_fn != NULL);

  ScopedAsanAlloc<uint8_t> mem(this, kAllocSize);
  ASSERT_TRUE(mem.get() != NULL);

  uint8_t* mem_ptr = mem.get();
  mem.reset(NULL);

  tester_.tester()->AssertMemoryErrorIsDetected(check_access_fn, mem_ptr,
                                                USE_AFTER_FREE);
  EXPECT_TRUE(LogContains("previously allocated here"));
  EXPECT_TRUE(LogContains("freed here"));
  EXPECT_TRUE(LogContains(kHeapUseAfterFree));
}

TYPED_TEST(AsanRtlTypedTest, AsanCheckDoubleFree) {
  FARPROC check_access_fn =
      ::GetProcAddress(asan_rtl_, tester_.function_name());
  ASSERT_TRUE(check_access_fn != NULL);

  uint8_t* mem_ptr = NULL;
  {
    ScopedAsanAlloc<uint8_t> mem(this, kAllocSize);
    ASSERT_TRUE(mem.get() != NULL);
    mem_ptr = mem.get();
  }

  tester_.tester()->set_expected_error_type(DOUBLE_FREE);
  EXPECT_FALSE(HeapFreeFunction(heap_, 0, mem_ptr));
  EXPECT_TRUE(tester_.tester()->memory_error_detected());
  EXPECT_TRUE(LogContains(kAttemptingDoubleFree));
  EXPECT_TRUE(LogContains("previously allocated here"));
  EXPECT_TRUE(LogContains("freed here"));
}

TYPED_TEST(AsanRtlTypedTest, AsanCheckWildAccess) {
  TEST_ONLY_SUPPORTS_2G();

  FARPROC check_access_fn =
      ::GetProcAddress(asan_rtl_, tester_.function_name());
  ASSERT_TRUE(check_access_fn != NULL);

#ifndef _WIN64
  void* addr = reinterpret_cast<void*>(0x80000000);
#else
  void* addr = reinterpret_cast<void*>(1ULL << 63);
#endif

  tester_.tester()->AssertMemoryErrorIsDetected(check_access_fn, addr,
                                                WILD_ACCESS);
  EXPECT_TRUE(LogContains(kWildAccess));
}

#ifndef _WIN64
// It is not possible to test the near-nullptr access with heap corruption
// execution path since it depends on the unhandled exception filter which is
// not installed in the rtl library.
TYPED_TEST(AsanRtlTypedTest, AsanIgnoreInvalidAccess) {
  FARPROC check_access_fn =
      ::GetProcAddress(asan_rtl_, tester_.function_name());
  ASSERT_TRUE(check_access_fn != NULL);

  // A near-nullptr access should not be reported by SyzyASAN.
  tester_.CheckAccess(check_access_fn, nullptr);
  EXPECT_FALSE(LogContains(kInvalidAddress));
}
#endif

TYPED_TEST(AsanRtlTypedTest, AsanReportInvalidAccess) {
  FARPROC check_access_fn =
      ::GetProcAddress(asan_rtl_, tester_.function_name());
  ASSERT_NE(static_cast<FARPROC>(nullptr), check_access_fn);
  agent::asan::AsanRuntime* runtime = GetActiveRuntimeFunction();
  ASSERT_NE(static_cast<agent::asan::AsanRuntime*>(nullptr), runtime);
  runtime->params().report_invalid_accesses = true;
  tester_.tester()->AssertMemoryErrorIsDetected(
      check_access_fn, static_cast<void*>(nullptr), INVALID_ADDRESS);
  EXPECT_TRUE(LogContains(kInvalidAddress));
}

TYPED_TEST(AsanRtlTypedTest, AsanCheckCorruptBlock) {
  void* mem = HeapAllocFunction(heap_, 0, kAllocSize);
  reinterpret_cast<uint8_t*>(mem)[-1]--;
  tester_.tester()->set_expected_error_type(CORRUPT_BLOCK);
  EXPECT_TRUE(HeapFreeFunction(heap_, 0, mem));
  EXPECT_TRUE(tester_.tester()->memory_error_detected());
  EXPECT_TRUE(LogContains(kHeapCorruptBlock));
  EXPECT_TRUE(LogContains("previously allocated here"));
}

TYPED_TEST(AsanRtlTypedTest, AsanCheckCorruptHeap) {
  FARPROC check_access_fn =
      ::GetProcAddress(asan_rtl_, tester_.function_name());
  ASSERT_TRUE(check_access_fn != nullptr);

  agent::asan::AsanRuntime* runtime = GetActiveRuntimeFunction();
  ASSERT_NE(reinterpret_cast<agent::asan::AsanRuntime*>(NULL), runtime);
  runtime->params().check_heap_on_failure = true;

  ScopedAsanAlloc<uint8_t> mem(this, kAllocSize);
  ASSERT_TRUE(mem.get() != NULL);

  const size_t kMaxIterations = 10;

  // Retrieves the information about this block.
  BlockHeader* header =
      BlockGetHeaderFromBody(reinterpret_cast<BlockBody*>(mem.get()));
  BlockInfo block_info = {};
  EXPECT_TRUE(BlockInfoFromMemory(header, &block_info));

  // We'll update a non essential value of the block trailer to corrupt it.
  uint8_t* mem_in_trailer =
      reinterpret_cast<uint8_t*>(&block_info.trailer->alloc_tid);

  // This can fail because of a checksum collision. However, we run it a handful
  // of times to keep the chances as small as possible.
  for (size_t i = 0; i < kMaxIterations; ++i) {
    (*mem_in_trailer)++;
    tester_.tester()->AssertMemoryErrorIsDetected(
        check_access_fn, mem.get() + kAllocSize, HEAP_BUFFER_OVERFLOW);
    EXPECT_TRUE(LogContains("previously allocated here"));
    EXPECT_TRUE(LogContains(kHeapBufferOverFlow));

    if (!tester_.tester()->last_error_info().heap_is_corrupt &&
        i + 1 < kMaxIterations)
      continue;

    EXPECT_TRUE(tester_.tester()->last_error_info().heap_is_corrupt);

    EXPECT_EQ(1, tester_.tester()->last_error_info().corrupt_range_count);
    EXPECT_EQ(1, tester_.tester()->last_corrupt_ranges().size());
    AsanBlockInfoVector blocks_info =
        tester_.tester()->last_corrupt_ranges()[0].second;

    EXPECT_EQ(1, blocks_info.size());
    EXPECT_EQ(kDataIsCorrupt, blocks_info[0].analysis.block_state);
    EXPECT_EQ(kAllocSize, blocks_info[0].user_size);
    EXPECT_EQ(block_info.header, blocks_info[0].header);
    EXPECT_NE(0U, blocks_info[0].alloc_stack_size);
    for (size_t j = 0; j < blocks_info[0].alloc_stack_size; ++j)
      EXPECT_NE(reinterpret_cast<void*>(NULL), blocks_info[0].alloc_stack[j]);
    EXPECT_EQ(0U, blocks_info[0].free_stack_size);

    // An error should be triggered when we free this block.
    tester_.tester()->set_memory_error_detected(false);
    tester_.tester()->set_expected_error_type(CORRUPT_BLOCK);
    mem.reset(NULL);
    EXPECT_TRUE(tester_.tester()->memory_error_detected());

    break;
  }
}

#ifndef _WIN64
TEST_F(AsanRtlTest, AsanSingleSpecial1byteInstructionCheckGoodAccess) {
  static const char* function_names[] = {"asan_check_1_byte_movs_access",
                                         "asan_check_1_byte_cmps_access",
                                         "asan_check_1_byte_stos_access"};

  // Allocate memory space.
  AllocMemoryBuffers(kAllocSize, sizeof(uint8_t));
  uint8_t* src = reinterpret_cast<uint8_t*>(memory_src_);
  uint8_t* dst = reinterpret_cast<uint8_t*>(memory_dst_);

  // Validate memory accesses.
  for (int32_t function = 0; function < arraysize(function_names); ++function) {
    FARPROC check_access_fn =
        ::GetProcAddress(asan_rtl_, function_names[function]);
    ASSERT_TRUE(check_access_fn != NULL);

    for (int32_t i = 0; i < memory_length_; ++i) {
      SyzyAsanMemoryAccessorTester tester;
      tester.ExpectSpecialMemoryErrorIsDetected(
          check_access_fn, SyzyAsanMemoryAccessorTester::DIRECTION_FORWARD,
          false, &dst[i], &src[i], 0xDEADDEAD, UNKNOWN_BAD_ACCESS);
    }
  }

  FreeMemoryBuffers();
}

TEST_F(AsanRtlTest, AsanSingleSpecial2byteInstructionCheckGoodAccess) {
  static const char* function_names[] = {"asan_check_2_byte_movs_access",
                                         "asan_check_2_byte_cmps_access",
                                         "asan_check_2_byte_stos_access"};

  // Allocate memory space.
  AllocMemoryBuffers(kAllocSize, sizeof(uint16_t));
  uint16_t* src = reinterpret_cast<uint16_t*>(memory_src_);
  uint16_t* dst = reinterpret_cast<uint16_t*>(memory_dst_);

  // Validate memory accesses.
  for (int32_t function = 0; function < arraysize(function_names); ++function) {
    FARPROC check_access_fn =
        ::GetProcAddress(asan_rtl_, function_names[function]);
    ASSERT_TRUE(check_access_fn != NULL);

    for (int32_t i = 0; i < memory_length_; ++i) {
      SyzyAsanMemoryAccessorTester tester;
      tester.ExpectSpecialMemoryErrorIsDetected(
          check_access_fn, SyzyAsanMemoryAccessorTester::DIRECTION_FORWARD,
          false, &dst[i], &src[i], 0xDEADDEAD, UNKNOWN_BAD_ACCESS);
    }
  }

  FreeMemoryBuffers();
}

TEST_F(AsanRtlTest, AsanSingleSpecial4byteInstructionCheckGoodAccess) {
  static const char* function_names[] = {"asan_check_4_byte_movs_access",
                                         "asan_check_4_byte_cmps_access",
                                         "asan_check_4_byte_stos_access"};

  // Allocate memory space.
  AllocMemoryBuffers(kAllocSize, sizeof(uint32_t));
  uint32_t* src = reinterpret_cast<uint32_t*>(memory_src_);
  uint32_t* dst = reinterpret_cast<uint32_t*>(memory_dst_);

  // Validate memory accesses.
  for (int32_t function = 0; function < arraysize(function_names); ++function) {
    FARPROC check_access_fn =
        ::GetProcAddress(asan_rtl_, function_names[function]);
    ASSERT_TRUE(check_access_fn != NULL);

    for (int32_t i = 0; i < memory_length_; ++i) {
      SyzyAsanMemoryAccessorTester tester;
      tester.ExpectSpecialMemoryErrorIsDetected(
          check_access_fn, SyzyAsanMemoryAccessorTester::DIRECTION_FORWARD,
          false, &dst[i], &src[i], 0xDEADDEAD, UNKNOWN_BAD_ACCESS);
    }
  }

  FreeMemoryBuffers();
}

TEST_F(AsanRtlTest, AsanSingleSpecialInstructionCheckBadAccess) {
  static const char* function_names[] = {"asan_check_1_byte_movs_access",
                                         "asan_check_1_byte_cmps_access",
                                         "asan_check_2_byte_movs_access",
                                         "asan_check_2_byte_cmps_access",
                                         "asan_check_4_byte_movs_access",
                                         "asan_check_4_byte_cmps_access"};

  // Allocate memory space.
  AllocMemoryBuffers(kAllocSize, sizeof(uint32_t));
  uint32_t* src = reinterpret_cast<uint32_t*>(memory_src_);
  uint32_t* dst = reinterpret_cast<uint32_t*>(memory_dst_);

  // Validate memory accesses.
  for (int32_t function = 0; function < arraysize(function_names); ++function) {
    FARPROC check_access_fn =
        ::GetProcAddress(asan_rtl_, function_names[function]);
    ASSERT_TRUE(check_access_fn != NULL);

    SyzyAsanMemoryAccessorTester tester;
    tester.ExpectSpecialMemoryErrorIsDetected(
        check_access_fn, SyzyAsanMemoryAccessorTester::DIRECTION_FORWARD, true,
        &dst[0], &src[-1], 0xDEADDEAD, HEAP_BUFFER_UNDERFLOW);
    tester.ExpectSpecialMemoryErrorIsDetected(
        check_access_fn, SyzyAsanMemoryAccessorTester::DIRECTION_FORWARD, true,
        &dst[-1], &src[0], 0xDEADDEAD, HEAP_BUFFER_UNDERFLOW);

    tester.ExpectSpecialMemoryErrorIsDetected(
        check_access_fn, SyzyAsanMemoryAccessorTester::DIRECTION_FORWARD, true,
        &dst[0], &src[memory_length_], 0xDEADDEAD, HEAP_BUFFER_OVERFLOW);
    tester.ExpectSpecialMemoryErrorIsDetected(
        check_access_fn, SyzyAsanMemoryAccessorTester::DIRECTION_FORWARD, true,
        &dst[memory_length_], &src[0], 0xDEADDEAD, HEAP_BUFFER_OVERFLOW);
  }

  FreeMemoryBuffers();
}

TEST_F(AsanRtlTest, AsanSingleStoInstructionCheckBadAccess) {
  static const char* function_names[] = {"asan_check_1_byte_stos_access",
                                         "asan_check_2_byte_stos_access",
                                         "asan_check_4_byte_stos_access"};

  // Allocate memory space.
  AllocMemoryBuffers(kAllocSize, sizeof(uint32_t));
  uint32_t* src = reinterpret_cast<uint32_t*>(memory_src_);
  uint32_t* dst = reinterpret_cast<uint32_t*>(memory_dst_);

  // Validate memory accesses.
  for (int32_t function = 0; function < arraysize(function_names); ++function) {
    FARPROC check_access_fn =
        ::GetProcAddress(asan_rtl_, function_names[function]);
    ASSERT_TRUE(check_access_fn != NULL);

    SyzyAsanMemoryAccessorTester tester;
    tester.ExpectSpecialMemoryErrorIsDetected(
        check_access_fn, SyzyAsanMemoryAccessorTester::DIRECTION_FORWARD, false,
        &dst[0], &src[-1], 0xDEAD, HEAP_BUFFER_UNDERFLOW);
    tester.ExpectSpecialMemoryErrorIsDetected(
        check_access_fn, SyzyAsanMemoryAccessorTester::DIRECTION_FORWARD, true,
        &dst[-1], &src[0], 0xDEAD, HEAP_BUFFER_UNDERFLOW);

    tester.ExpectSpecialMemoryErrorIsDetected(
        check_access_fn, SyzyAsanMemoryAccessorTester::DIRECTION_FORWARD, false,
        &dst[0], &src[memory_length_], 0xDEADDEAD, HEAP_BUFFER_OVERFLOW);
    tester.ExpectSpecialMemoryErrorIsDetected(
        check_access_fn, SyzyAsanMemoryAccessorTester::DIRECTION_FORWARD, true,
        &dst[memory_length_], &src[0], 0xDEADDEAD, HEAP_BUFFER_OVERFLOW);
  }

  FreeMemoryBuffers();
}

TEST_F(AsanRtlTest, AsanPrefixedSpecialInstructionCheckGoodAccess) {
  static const char* function_names[] = {"asan_check_repz_4_byte_lods_access",
                                         "asan_check_repz_4_byte_movs_access",
                                         "asan_check_repz_4_byte_cmps_access",
                                         "asan_check_repz_4_byte_stos_access"};

  // Allocate memory space.
  AllocMemoryBuffers(kAllocSize, sizeof(uint32_t));
  uint32_t* src = reinterpret_cast<uint32_t*>(memory_src_);
  uint32_t* dst = reinterpret_cast<uint32_t*>(memory_dst_);

  // Validate memory accesses.
  for (int32_t function = 0; function < arraysize(function_names); ++function) {
    FARPROC check_access_fn =
        ::GetProcAddress(asan_rtl_, function_names[function]);
    ASSERT_TRUE(check_access_fn != NULL);

    SyzyAsanMemoryAccessorTester tester;
    tester.ExpectSpecialMemoryErrorIsDetected(
        check_access_fn, SyzyAsanMemoryAccessorTester::DIRECTION_FORWARD, false,
        &dst[0], &src[0], memory_length_, UNKNOWN_BAD_ACCESS);
  }

  FreeMemoryBuffers();
}

TEST_F(AsanRtlTest, AsanPrefixedSpecialInstructionCheckBadAccess) {
  static const char* function_names[] = {"asan_check_repz_4_byte_lods_access",
                                         "asan_check_repz_4_byte_movs_access",
                                         "asan_check_repz_4_byte_cmps_access",
                                         "asan_check_repz_4_byte_stos_access"};

  // Allocate memory space.
  AllocMemoryBuffers(kAllocSize, sizeof(uint32_t));
  uint32_t* src = reinterpret_cast<uint32_t*>(memory_src_);
  uint32_t* dst = reinterpret_cast<uint32_t*>(memory_dst_);

  // Validate memory accesses.
  for (int32_t function = 0; function < arraysize(function_names); ++function) {
    FARPROC check_access_fn =
        ::GetProcAddress(asan_rtl_, function_names[function]);
    ASSERT_TRUE(check_access_fn != NULL);

    SyzyAsanMemoryAccessorTester tester;
    tester.ExpectSpecialMemoryErrorIsDetected(
        check_access_fn, SyzyAsanMemoryAccessorTester::DIRECTION_FORWARD, true,
        &dst[0], &src[0], memory_length_ + 1, HEAP_BUFFER_OVERFLOW);
    tester.ExpectSpecialMemoryErrorIsDetected(
        check_access_fn, SyzyAsanMemoryAccessorTester::DIRECTION_FORWARD, true,
        &dst[-1], &src[-1], memory_length_, HEAP_BUFFER_UNDERFLOW);
    tester.ExpectSpecialMemoryErrorIsDetected(
        check_access_fn, SyzyAsanMemoryAccessorTester::DIRECTION_FORWARD, true,
        &dst[-1], &src[0], memory_length_, HEAP_BUFFER_UNDERFLOW);
  }

  FreeMemoryBuffers();
}

TEST_F(AsanRtlTest, AsanDirectionSpecialInstructionCheckGoodAccess) {
  static const char* function_names[] = {"asan_check_repz_4_byte_lods_access",
                                         "asan_check_repz_4_byte_movs_access",
                                         "asan_check_repz_4_byte_cmps_access",
                                         "asan_check_repz_4_byte_stos_access"};

  // Allocate memory space.
  AllocMemoryBuffers(kAllocSize, sizeof(uint32_t));
  uint32_t* src = reinterpret_cast<uint32_t*>(memory_src_);
  uint32_t* dst = reinterpret_cast<uint32_t*>(memory_dst_);

  // Validate memory accesses.
  for (int32_t function = 0; function < arraysize(function_names); ++function) {
    FARPROC check_access_fn =
        ::GetProcAddress(asan_rtl_, function_names[function]);
    ASSERT_TRUE(check_access_fn != NULL);

    SyzyAsanMemoryAccessorTester tester;
    tester.ExpectSpecialMemoryErrorIsDetected(
        check_access_fn, SyzyAsanMemoryAccessorTester::DIRECTION_BACKWARD,
        false, &dst[memory_length_ - 1], &src[memory_length_ - 1],
        memory_length_, UNKNOWN_BAD_ACCESS);
  }

  FreeMemoryBuffers();
}

TEST_F(AsanRtlTest, AsanSpecialInstructionCheckZeroAccess) {
  static const char* function_names[] = {"asan_check_repz_1_byte_lods_access",
                                         "asan_check_repz_1_byte_movs_access",
                                         "asan_check_repz_1_byte_cmps_access",
                                         "asan_check_repz_1_byte_stos_access",
                                         "asan_check_repz_2_byte_lods_access",
                                         "asan_check_repz_2_byte_movs_access",
                                         "asan_check_repz_2_byte_cmps_access",
                                         "asan_check_repz_2_byte_stos_access",
                                         "asan_check_repz_4_byte_lods_access",
                                         "asan_check_repz_4_byte_movs_access",
                                         "asan_check_repz_4_byte_cmps_access",
                                         "asan_check_repz_4_byte_stos_access"};

  // Allocate memory space.
  AllocMemoryBuffers(kAllocSize, sizeof(uint32_t));
  uint32_t* src = reinterpret_cast<uint32_t*>(memory_src_);
  uint32_t* dst = reinterpret_cast<uint32_t*>(memory_dst_);

  // Validate memory accesses.
  for (int32_t function = 0; function < arraysize(function_names); ++function) {
    FARPROC check_access_fn =
        ::GetProcAddress(asan_rtl_, function_names[function]);
    ASSERT_TRUE(check_access_fn != NULL);

    // A prefixed instruction with a count of zero do not have side effects.
    SyzyAsanMemoryAccessorTester tester;
    tester.ExpectSpecialMemoryErrorIsDetected(
        check_access_fn, SyzyAsanMemoryAccessorTester::DIRECTION_FORWARD, false,
        &dst[-1], &src[-1], 0, UNKNOWN_BAD_ACCESS);
  }

  FreeMemoryBuffers();
}

TEST_F(AsanRtlTest, AsanSpecialInstructionCheckShortcutAccess) {
  static const char* function_names[] = {
      "asan_check_repz_1_byte_lods_access",
      "asan_check_repz_1_byte_cmps_access",
      "asan_check_repz_2_byte_cmps_access",
      "asan_check_repz_4_byte_cmps_access",
  };

  // Allocate memory space.
  AllocMemoryBuffers(kAllocSize, sizeof(uint32_t));
  uint32_t* src = reinterpret_cast<uint32_t*>(memory_src_);
  uint32_t* dst = reinterpret_cast<uint32_t*>(memory_dst_);

  src[1] = 0x12345667;

  // Validate memory accesses.
  for (int32_t function = 0; function < arraysize(function_names); ++function) {
    FARPROC check_access_fn =
        ::GetProcAddress(asan_rtl_, function_names[function]);
    ASSERT_TRUE(check_access_fn != NULL);

    // Compare instruction stop their execution when values differ.
    SyzyAsanMemoryAccessorTester tester;
    tester.ExpectSpecialMemoryErrorIsDetected(
        check_access_fn, SyzyAsanMemoryAccessorTester::DIRECTION_FORWARD, false,
        &dst[0], &src[0], memory_length_ + 1, UNKNOWN_BAD_ACCESS);
  }

  FreeMemoryBuffers();
}

TEST_F(AsanRtlTest, AllocationFilterFlag) {
  agent::asan::AsanRuntime* runtime = GetActiveRuntimeFunction();
  SetAllocationFilterFlagFunction();
  EXPECT_TRUE(runtime->allocation_filter_flag());
  ClearAllocationFilterFlagFunction();
  EXPECT_FALSE(runtime->allocation_filter_flag());
  SetAllocationFilterFlagFunction();
  EXPECT_TRUE(runtime->allocation_filter_flag());
}
#endif

namespace {

using ExperimentMap = std::map<std::string, std::string>;

ExperimentMap* experiment_map = nullptr;

static void WINAPI
ExperimentCallback(const char* feature_name, const char* feature_state) {
  ASSERT_TRUE(experiment_map != nullptr);

  // We mandate only one call per named feature.
  bool inserted = experiment_map->insert(std::make_pair(feature_name,
                                                        feature_state)).second;
  ASSERT_TRUE(inserted);
}

}  // namespace

TEST_F(AsanRtlTest, EnumFeatures) {
  typedef void(WINAPI * EnumExperimentsFn)(AsanExperimentCallback callback);

  EnumExperimentsFn enum_experiments_fn = reinterpret_cast<EnumExperimentsFn>(
      ::GetProcAddress(asan_rtl_, "asan_EnumExperiments"));
  ASSERT_TRUE(enum_experiments_fn != nullptr);

  ExperimentMap experiments;
  experiment_map = &experiments;
  enum_experiments_fn(ExperimentCallback);
  experiment_map = nullptr;

  EXPECT_EQ("Enabled", experiments["SyzyASANPageProtections"]);
  EXPECT_EQ("Enabled", experiments["SyzyASANLargeBlockHeap"]);

  // This implicitly asserts the full contents of the map by asserting
  // on the size after looking up the expected keys.
  EXPECT_EQ(2U, experiments.size());
}

}  // namespace asan
}  // namespace agent
