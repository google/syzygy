// Copyright 2013 Google Inc. All Rights Reserved.
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
//
// Common unittest fixtures and utilities for the ASAN runtime library.

#include "syzygy/agent/asan/unittest_util.h"

#include "base/environment.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "syzygy/agent/asan/asan_runtime.h"
#include "syzygy/agent/asan/block.h"
#include "syzygy/agent/asan/shadow.h"
#include "syzygy/agent/asan/stack_capture.h"
#include "syzygy/trace/protocol/call_trace_defs.h"

namespace testing {

using agent::asan::BlockHeader;
using agent::asan::BlockInfo;
using agent::asan::Shadow;
using agent::asan::StackCapture;

const wchar_t kSyzyAsanRtlDll[] = L"syzyasan_rtl.dll";

namespace {

FARPROC check_access_fn = NULL;
bool direction_flag_forward = true;

}  // namespace

MemoryAccessorTester* MemoryAccessorTester::instance_ = NULL;

// Define the function pointers.
#define DEFINE_FUNCTION_PTR_VARIABLE(convention, ret, name, args, argnames)  \
    name##FunctionPtr TestAsanRtl::name##Function;
ASAN_RTL_FUNCTIONS(DEFINE_FUNCTION_PTR_VARIABLE)
#undef DEFINE_FUNCTION_PTR_VARIABLE

// Define versions of all of the functions that expect an error to be thrown by
// the AsanErrorCallback, and in turn raise an exception if the underlying
// function didn't fail.
#define DEFINE_FAILING_FUNCTION(convention, ret, name, args, argnames)  \
  bool name##FunctionFailed args {  \
    __try {  \
      testing::TestAsanRtl::name##Function argnames;  \
    } __except(::GetExceptionCode() == EXCEPTION_ARRAY_BOUNDS_EXCEEDED) {  \
      return true;  \
    }  \
    return false;  \
  }  \
  void testing::TestAsanRtl::name##FunctionFailing args {  \
    ASSERT_TRUE(name##FunctionFailed argnames);  \
  }
ASAN_RTL_FUNCTIONS(DEFINE_FAILING_FUNCTION)
#undef DEFINE_FAILING_FUNCTION

TestWithAsanLogger::TestWithAsanLogger()
    : log_service_instance_(&log_service_), log_contents_read_(false) {
}

void TestWithAsanLogger::SetUp() {
  // Create and open the log file.
  ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
  CHECK(base::CreateTemporaryFileInDir(temp_dir_.path(), &log_file_path_));
  log_file_.reset(base::OpenFile(log_file_path_, "wb"));

  // Configure the environment (to pass the instance id to the agent DLL).
  std::string instance_id;
  scoped_ptr<base::Environment> env(base::Environment::Create());
  env->GetVar(kSyzygyRpcInstanceIdEnvVar, &instance_id);
  instance_id.append(base::StringPrintf(";%ls,%u",
                                        kSyzyAsanRtlDll,
                                        ::GetCurrentProcessId()));
  env->SetVar(kSyzygyRpcInstanceIdEnvVar, instance_id);

  // Configure and start the log service.
  instance_id_ = base::UintToString16(::GetCurrentProcessId());
  log_service_.set_instance_id(instance_id_);
  log_service_.set_destination(log_file_.get());
  log_service_.set_minidump_dir(temp_dir_.path());
  log_service_.set_symbolize_stack_traces(false);
  ASSERT_TRUE(log_service_.Start());

  log_contents_read_ = false;
}

void TestWithAsanLogger::TearDown() {
  log_service_.Stop();
  log_service_.Join();
  log_file_.reset(NULL);
  LogContains("");
}

bool TestWithAsanLogger::LogContains(const base::StringPiece& message) {
  if (!log_contents_read_ && log_file_.get() != NULL) {
    CHECK(base::ReadFileToString(log_file_path_, &log_contents_));
    log_contents_read_ = true;
  }
  return log_contents_.find(message.as_string()) != std::string::npos;
}

void TestWithAsanLogger::DeleteTempFileAndDirectory() {
  log_file_.reset();
  if (temp_dir_.IsValid())
    temp_dir_.Delete();
}

void TestWithAsanLogger::ResetLog() {
  DCHECK(log_file_.get() != NULL);
  CHECK(base::CreateTemporaryFileInDir(temp_dir_.path(), &log_file_path_));
  base::ScopedFILE log_file(base::OpenFile(log_file_path_, "wb"));
  log_service_.set_destination(log_file.get());
  log_file_.reset(log_file.release());
  log_contents_read_ = false;
}

FakeAsanBlock::FakeAsanBlock(HeapProxy* proxy, size_t alloc_alignment_log)
    : proxy(proxy), is_initialized(false),
      alloc_alignment_log(alloc_alignment_log),
      alloc_alignment(1 << alloc_alignment_log), user_ptr(NULL) {
  // Align the beginning of the buffer to the current granularity. Ensure that
  // there's room to store magic bytes in front of this block.
  buffer_align_begin = reinterpret_cast<uint8*>(common::AlignUp(
      reinterpret_cast<size_t>(buffer)+1, alloc_alignment));
}

FakeAsanBlock::~FakeAsanBlock() {
  Shadow::Unpoison(buffer_align_begin, asan_alloc_size);
  ::memset(buffer, 0, sizeof(buffer));
}

bool FakeAsanBlock::InitializeBlock(size_t alloc_size) {
  user_alloc_size = alloc_size;
  asan_alloc_size = proxy->GetAllocSize(alloc_size,
    alloc_alignment);

  // Calculate the size of the zone of the buffer that we use to ensure that
  // we don't corrupt the heap.
  buffer_header_size = buffer_align_begin - buffer;
  buffer_trailer_size = kBufferSize - buffer_header_size -
    asan_alloc_size;
  EXPECT_GT(kBufferSize, asan_alloc_size + buffer_header_size);

  // Initialize the buffer header and trailer.
  ::memset(buffer, kBufferHeaderValue, buffer_header_size);
  ::memset(buffer_align_begin + asan_alloc_size,
    kBufferTrailerValue,
    buffer_trailer_size);

  StackCapture stack;
  stack.InitFromStack();
  // Initialize the ASan block.
  user_ptr = proxy->InitializeAsanBlock(buffer_align_begin,
    alloc_size,
    alloc_alignment_log,
    false,
    stack);
  EXPECT_NE(reinterpret_cast<void*>(NULL), user_ptr);
  BlockHeader* header = agent::asan::BlockGetHeaderFromBody(user_ptr);
  EXPECT_NE(reinterpret_cast<BlockHeader*>(NULL), header);
  BlockInfo block_info = {};
  EXPECT_TRUE(BlockInfoFromMemory(header, &block_info));
  EXPECT_TRUE(common::IsAligned(reinterpret_cast<size_t>(user_ptr),
    alloc_alignment));
  EXPECT_TRUE(common::IsAligned(
      reinterpret_cast<size_t>(buffer_align_begin)+asan_alloc_size,
      agent::asan::kShadowRatio));
  EXPECT_EQ(buffer_align_begin, block_info.block);
  EXPECT_EQ(user_ptr, block_info.body);

  void* expected_user_ptr = reinterpret_cast<void*>(
    buffer_align_begin + std::max(sizeof(BlockHeader),
    alloc_alignment));
  EXPECT_TRUE(user_ptr == expected_user_ptr);

  size_t i = 0;
  // Ensure that the buffer header is accessible and correctly tagged.
  for (; i < buffer_header_size; ++i) {
    EXPECT_EQ(kBufferHeaderValue, buffer[i]);
    EXPECT_TRUE(Shadow::IsAccessible(buffer + i));
  }
  size_t user_block_offset = reinterpret_cast<uint8*>(user_ptr)-buffer;
  // Ensure that the block header isn't accessible.
  for (; i < user_block_offset; ++i)
    EXPECT_FALSE(Shadow::IsAccessible(buffer + i));

  // Ensure that the user block is accessible.
  size_t block_trailer_offset = i + alloc_size;
  for (; i < block_trailer_offset; ++i)
    EXPECT_TRUE(Shadow::IsAccessible(buffer + i));

  // Ensure that the block trailer isn't accessible.
  for (; i < buffer_header_size + asan_alloc_size; ++i)
    EXPECT_FALSE(Shadow::IsAccessible(buffer + i));

  // Ensure that the buffer trailer is accessible and correctly tagged.
  for (; i < kBufferSize; ++i) {
    EXPECT_EQ(kBufferTrailerValue, buffer[i]);
    EXPECT_TRUE(Shadow::IsAccessible(buffer + i));
  }

  is_initialized = true;
  return true;
}

bool FakeAsanBlock::TestBlockMetadata() {
  if (!is_initialized)
    return false;

  // Ensure that the block header is valid. BlockGetHeaderFromBody takes
  // care of checking the magic number in the signature of the block.
  BlockHeader* block_header = agent::asan::BlockGetHeaderFromBody(user_ptr);
  EXPECT_TRUE(block_header != NULL);
  BlockInfo block_info = {};
  EXPECT_TRUE(BlockInfoFromMemory(block_header, &block_info));
  EXPECT_EQ(::GetCurrentThreadId(), block_info.trailer->alloc_tid);
  EXPECT_EQ(user_alloc_size, block_header->body_size);
  EXPECT_TRUE(block_header->alloc_stack != NULL);
  EXPECT_EQ(agent::asan::ALLOCATED_BLOCK, block_header->state);
  const uint8* cursor = buffer_align_begin;
  EXPECT_TRUE(Shadow::IsBlockStartByte(cursor++));
  for (; cursor < user_ptr; ++cursor)
    EXPECT_TRUE(Shadow::IsLeftRedzone(cursor));
  const uint8* aligned_trailer_begin = reinterpret_cast<const uint8*>(
      common::AlignUp(reinterpret_cast<size_t>(user_ptr)+user_alloc_size,
      agent::asan::kShadowRatio));
  for (const uint8* pos = aligned_trailer_begin;
       pos < buffer_align_begin + asan_alloc_size;
       ++pos) {
    EXPECT_TRUE(Shadow::IsRightRedzone(pos));
  }

  return true;
}

bool FakeAsanBlock::MarkBlockAsQuarantined() {
  if (!is_initialized)
    return false;

  BlockHeader* block_header = agent::asan::BlockGetHeaderFromBody(user_ptr);
  EXPECT_NE(reinterpret_cast<BlockHeader*>(NULL), block_header);
  BlockInfo block_info = {};
  BlockInfoFromMemory(block_header, &block_info);
  EXPECT_TRUE(block_header->free_stack == NULL);
  EXPECT_TRUE(block_info.trailer != NULL);
  EXPECT_EQ(0U, block_info.trailer->free_tid);

  StackCapture stack;
  stack.InitFromStack();
  // Mark the block as quarantined.
  proxy->MarkBlockAsQuarantined(buffer_align_begin, stack);
  EXPECT_TRUE(block_header->free_stack != NULL);
  EXPECT_EQ(agent::asan::QUARANTINED_BLOCK, block_header->state);
  EXPECT_EQ(::GetCurrentThreadId(), block_info.trailer->free_tid);

  size_t i = 0;
  // Ensure that the buffer header is accessible and correctly tagged.
  for (; i < buffer_header_size; ++i) {
    EXPECT_EQ(kBufferHeaderValue, buffer[i]);
    EXPECT_TRUE(Shadow::IsAccessible(buffer + i));
  }
  // Ensure that the whole block isn't accessible.
  for (; i < buffer_header_size + asan_alloc_size; ++i)
    EXPECT_FALSE(Shadow::IsAccessible(buffer + i));

  // Ensure that the buffer trailer is accessible and correctly tagged.
  for (; i < kBufferSize; ++i) {
    EXPECT_EQ(kBufferTrailerValue, buffer[i]);
    EXPECT_TRUE(Shadow::IsAccessible(buffer + i));
  }
  return true;
}

namespace {

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

// Check whether 2 contexts are equal.
// @param c1 The first context to check.
// @param c2 The second context to check.
void ExpectEqualContexts(const CONTEXT& c1, const CONTEXT& c2) {
  // Segment registers.
  EXPECT_EQ(static_cast<WORD>(c1.SegGs), static_cast<WORD>(c2.SegGs));
  EXPECT_EQ(static_cast<WORD>(c1.SegFs), static_cast<WORD>(c2.SegFs));
  EXPECT_EQ(static_cast<WORD>(c1.SegEs), static_cast<WORD>(c2.SegEs));
  EXPECT_EQ(static_cast<WORD>(c1.SegDs), static_cast<WORD>(c2.SegDs));

  // General registers.
  EXPECT_EQ(c1.Edi, c2.Edi);
  EXPECT_EQ(c1.Esi, c2.Esi);
  EXPECT_EQ(c1.Ebx, c2.Ebx);
  EXPECT_EQ(c1.Edx, c2.Edx);
  EXPECT_EQ(c1.Ecx, c2.Ecx);
  EXPECT_EQ(c1.Eax, c2.Eax);

  // "Control" registers.
  EXPECT_EQ(c1.Ebp, c2.Ebp);
  EXPECT_EQ(c1.Eip, c2.Eip);
  EXPECT_EQ(static_cast<WORD>(c1.SegCs), static_cast<WORD>(c2.SegCs));
  EXPECT_EQ(c1.EFlags, c2.EFlags);
  EXPECT_EQ(c1.Esp, c2.Esp);
  EXPECT_EQ(static_cast<WORD>(c1.SegSs), static_cast<WORD>(c2.SegSs));
}

}  // namespace

MemoryAccessorTester::MemoryAccessorTester()
    : expected_error_type_(agent::asan::UNKNOWN_BAD_ACCESS),
      memory_error_detected_(false) {
  EXPECT_EQ(static_cast<MemoryAccessorTester*>(NULL), instance_);

  Initialize();
  instance_ = this;
}

MemoryAccessorTester::~MemoryAccessorTester() {
  EXPECT_EQ(this, instance_);
  instance_ = NULL;
}

void MemoryAccessorTester::Initialize() {
  ::memset(&context_before_hook_, 0xCD, sizeof(context_before_hook_));
  ::memset(&context_after_hook_, 0xCE, sizeof(context_after_hook_));
  ::memset(&error_context_, 0xCF, sizeof(error_context_));
  ::memset(&last_error_info_, 0, sizeof(last_error_info_));
}

namespace {

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

}  // namespace

void MemoryAccessorTester::CheckAccessAndCompareContexts(
    FARPROC access_fn, void* ptr) {
  check_access_fn = access_fn;
  CheckAccessAndCaptureContexts(
      &context_before_hook_, &context_after_hook_, ptr);

  ExpectEqualContexts(context_before_hook_, context_after_hook_);
  if (memory_error_detected_)
    ExpectEqualContexts(context_before_hook_, error_context_);

  check_access_fn = NULL;
}

namespace {

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

}  // namespace

void MemoryAccessorTester::CheckSpecialAccessAndCompareContexts(
    FARPROC access_fn, StringOperationDirection direction,
    void* dst, void* src, int len) {
  direction_flag_forward = (direction == DIRECTION_FORWARD);
  check_access_fn = access_fn;

  CheckSpecialAccess(
      &context_before_hook_, &context_after_hook_, dst, src, len);

  ExpectEqualContexts(context_before_hook_, context_after_hook_);
  if (memory_error_detected_)
    ExpectEqualContexts(context_before_hook_, error_context_);

  check_access_fn = NULL;
}

void MemoryAccessorTester::AsanErrorCallbackImpl(AsanErrorInfo* error_info) {
  // TODO(sebmarchand): Stash the error info in a fixture-static variable and
  // assert on specific conditions after the fact.
  EXPECT_NE(reinterpret_cast<AsanErrorInfo*>(NULL), error_info);
  EXPECT_NE(agent::asan::UNKNOWN_BAD_ACCESS, error_info->error_type);

  EXPECT_EQ(expected_error_type_, error_info->error_type);
  if (error_info->error_type >= agent::asan::USE_AFTER_FREE) {
    // We should at least have the stack trace of the allocation of this block.
    EXPECT_GT(error_info->alloc_stack_size, 0U);
    EXPECT_NE(0U, error_info->alloc_tid);
    if (error_info->error_type == agent::asan::USE_AFTER_FREE ||
      error_info->error_type == agent::asan::DOUBLE_FREE) {
      EXPECT_GT(error_info->free_stack_size, 0U);
      EXPECT_NE(0U, error_info->free_tid);
    } else {
      EXPECT_EQ(error_info->free_stack_size, 0U);
      EXPECT_EQ(0U, error_info->free_tid);
    }
  }

  if (error_info->error_type == agent::asan::HEAP_BUFFER_OVERFLOW) {
    EXPECT_TRUE(strstr(error_info->shadow_info, "beyond") != NULL);
  } else if (error_info->error_type == agent::asan::HEAP_BUFFER_UNDERFLOW) {
    EXPECT_TRUE(strstr(error_info->shadow_info, "before") != NULL);
  }

  memory_error_detected_ = true;
  last_error_info_ = *error_info;

  // Copy the corrupt range's information.
  if (error_info->heap_is_corrupt) {
    EXPECT_GE(1U, error_info->corrupt_range_count);
    for (size_t i = 0; i < error_info->corrupt_range_count; ++i) {
      last_corrupt_ranges_.push_back(CorruptRangeInfo());
      CorruptRangeInfo* range_info = &last_corrupt_ranges_.back();
      range_info->first = error_info->corrupt_ranges[i];
      AsanBlockInfoVector* block_infos = &range_info->second;
      for (size_t j = 0; j < range_info->first.block_info_count; ++j) {
        agent::asan::AsanBlockInfo* block_info =
          new agent::asan::AsanBlockInfo(range_info->first.block_info[j]);
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

  error_context_ = error_info->context;
}

void MemoryAccessorTester::AsanErrorCallback(AsanErrorInfo* error_info) {
  ASSERT_NE(reinterpret_cast<MemoryAccessorTester*>(NULL), instance_);

  instance_->AsanErrorCallbackImpl(error_info);
}

void MemoryAccessorTester::AssertMemoryErrorIsDetected(
  FARPROC access_fn, void* ptr, BadAccessKind bad_access_type) {
  expected_error_type_ = bad_access_type;
  memory_error_detected_ = false;
  CheckAccessAndCompareContexts(access_fn, ptr);
  ASSERT_TRUE(memory_error_detected_);
}

void MemoryAccessorTester::ExpectSpecialMemoryErrorIsDetected(
    FARPROC access_fn, StringOperationDirection direction,
    bool expect_error, void* dst, void* src, int32 length,
    BadAccessKind bad_access_type) {
  DCHECK(dst != NULL);
  DCHECK(src != NULL);
  ASSERT_TRUE(check_access_fn == NULL);

  expected_error_type_ = bad_access_type;

  // Setup the callback to detect invalid accesses.
  memory_error_detected_ = false;

  // Perform memory accesses inside the range.
  ASSERT_NO_FATAL_FAILURE(
      CheckSpecialAccessAndCompareContexts(
          access_fn, direction, dst, src, length));

  EXPECT_EQ(expect_error, memory_error_detected_);
  check_access_fn = NULL;
}

}  // namespace testing
