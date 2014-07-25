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
#include "base/string_number_conversions.h"
#include "base/stringprintf.h"
#include "base/utf_string_conversions.h"
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
  CHECK(file_util::CreateTemporaryFileInDir(temp_dir_.path(), &log_file_path_));
  log_file_.reset(file_util::OpenFile(log_file_path_, "wb"));

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
    CHECK(file_util::ReadFileToString(log_file_path_, &log_contents_));
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
  CHECK(file_util::CreateTemporaryFileInDir(temp_dir_.path(), &log_file_path_));
  file_util::ScopedFILE log_file(file_util::OpenFile(log_file_path_, "wb"));
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

}  // namespace testing
