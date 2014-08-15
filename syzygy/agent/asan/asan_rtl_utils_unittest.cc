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

#include "syzygy/agent/asan/asan_rtl_utils.h"

#include <windows.h>

#include "base/bind.h"
#include "base/rand_util.h"
#include "gtest/gtest.h"
#include "syzygy/agent/asan/asan_heap.h"
#include "syzygy/agent/asan/asan_runtime.h"
#include "syzygy/agent/asan/shadow.h"

namespace agent {
namespace asan {

namespace {

using agent::asan::HeapProxy;
using agent::asan::Shadow;

// A flag used in asan callback to ensure that a memory error has been detected.
bool memory_error_detected = false;
// Will save the information about the last ASan error.
AsanErrorInfo last_error_info = {};

void AsanErrorCallBack(AsanErrorInfo* error_info) {
  EXPECT_NE(reinterpret_cast<AsanErrorInfo*>(NULL), error_info);
  memory_error_detected = true;
  last_error_info = *error_info;
}

class TestAsanRuntime : public AsanRuntime {
 public:
  TestAsanRuntime() {
    memory_error_detected = false;
    SetUp(L"");
    SetErrorCallBack(base::Bind(AsanErrorCallBack));
  }

  ~TestAsanRuntime() {
    TearDown();
  }
};

}  // namespace

TEST(AsanRtlUtilsTest, ContextToAsanContext) {
  CONTEXT context = {};
  AsanContext asan_context = {};
  base::RandBytes(reinterpret_cast<void*>(&context), sizeof(context));
  ContextToAsanContext(context, &asan_context);

  EXPECT_EQ(context.Eax, asan_context.original_eax);
  EXPECT_EQ(context.Ebp, asan_context.original_ebp);
  EXPECT_EQ(context.Ebx, asan_context.original_ebx);
  EXPECT_EQ(context.Ecx, asan_context.original_ecx);
  EXPECT_EQ(context.Edi, asan_context.original_edi);
  EXPECT_EQ(context.Edx, asan_context.original_edx);
  EXPECT_EQ(context.Eip, asan_context.original_eip);
  EXPECT_EQ(context.Esi, asan_context.original_esi);
  EXPECT_EQ(context.Esp, asan_context.original_esp);
  EXPECT_EQ(context.EFlags, asan_context.original_eflags);
}

TEST(AsanRtlUtilsTest, ReportBadMemoryAccess) {
  TestAsanRuntime runtime;
  SetAsanRuntimeInstance(&runtime);
  void* bad_location = reinterpret_cast<void*>(0xBAD0ADD5);
  AccessMode access_mode = ASAN_READ_ACCESS;
  size_t access_size = 4;
  AsanContext asan_context = {};
  base::RandBytes(reinterpret_cast<void*>(&asan_context), sizeof(asan_context));
  ReportBadMemoryAccess(bad_location, access_mode, access_size, asan_context);

  EXPECT_TRUE(memory_error_detected);
  EXPECT_EQ(bad_location, last_error_info.location);
  EXPECT_EQ(access_size, last_error_info.access_size);
  EXPECT_EQ(access_mode, last_error_info.access_mode);
  EXPECT_EQ(asan_context.original_eax, last_error_info.context.Eax);
  EXPECT_EQ(asan_context.original_ebp, last_error_info.context.Ebp);
  EXPECT_EQ(asan_context.original_ebx, last_error_info.context.Ebx);
  EXPECT_EQ(asan_context.original_ecx, last_error_info.context.Ecx);
  EXPECT_EQ(asan_context.original_edi, last_error_info.context.Edi);
  EXPECT_EQ(asan_context.original_edx, last_error_info.context.Edx);
  EXPECT_EQ(asan_context.original_eip, last_error_info.context.Eip);
  EXPECT_EQ(asan_context.original_esi, last_error_info.context.Esi);
  EXPECT_EQ(asan_context.original_esp, last_error_info.context.Esp);
  EXPECT_EQ(asan_context.original_eflags, last_error_info.context.EFlags);
}

TEST(AsanRtlUtilsTest, ReportBadAccess) {
  TestAsanRuntime runtime;
  SetAsanRuntimeInstance(&runtime);
  uint8* bad_location = reinterpret_cast<uint8*>(0xBAD0ADD5);
  AccessMode access_mode = ASAN_READ_ACCESS;
  ReportBadAccess(bad_location, access_mode);

  EXPECT_TRUE(memory_error_detected);
  EXPECT_EQ(bad_location, last_error_info.location);
  EXPECT_EQ(access_mode, last_error_info.access_mode);
}

TEST(AsanRtlUtilsTest, TestMemoryRange) {
  TestAsanRuntime runtime;
  SetAsanRuntimeInstance(&runtime);
  AccessMode access_mode = ASAN_READ_ACCESS;
  const size_t kTestBufferSize = 64;
  scoped_ptr<uint8> test_buffer(new uint8[kTestBufferSize]);

  TestMemoryRange(test_buffer.get(), kTestBufferSize, access_mode);
  EXPECT_FALSE(memory_error_detected);

  // Poison the second half of the buffer.
  Shadow::Poison(test_buffer.get() + kTestBufferSize / 2,
                 kTestBufferSize / 2,
                 kUserRedzoneMarker);

  // Test the first half of the buffer, no error should be detected.
  TestMemoryRange(test_buffer.get(), kTestBufferSize / 2, access_mode);
  EXPECT_FALSE(memory_error_detected);

  // Test the second half of the buffer, we should get an invalid access on its
  // last byte.
  TestMemoryRange(test_buffer.get(), kTestBufferSize, access_mode);
  EXPECT_TRUE(memory_error_detected);
  EXPECT_EQ(test_buffer.get() + kTestBufferSize - 1, last_error_info.location);
  EXPECT_EQ(access_mode, last_error_info.access_mode);

  Shadow::Unpoison(test_buffer.get(), kTestBufferSize);
}

TEST(AsanRtlUtilsTest, TestStructure) {
  TestAsanRuntime runtime;
  SetAsanRuntimeInstance(&runtime);
  AccessMode access_mode = ASAN_READ_ACCESS;
  scoped_ptr<double> test_struct(new double);

  TestStructure(test_struct.get(), access_mode);
  EXPECT_FALSE(memory_error_detected);

  Shadow::Poison(test_struct.get(),
                 sizeof(double),
                 kUserRedzoneMarker);

  TestStructure(test_struct.get(), access_mode);
  EXPECT_TRUE(memory_error_detected);
  EXPECT_EQ(test_struct.get(), last_error_info.location);
  EXPECT_EQ(access_mode, last_error_info.access_mode);

  Shadow::Unpoison(test_struct.get(), sizeof(double));
}

}  // namespace asan
}  // namespace agent
