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
// Common unittest fixtures and utilities for the Asan runtime library.

#include "syzygy/agent/asan/unittest_util.h"

#include <algorithm>

#include "base/bind.h"
#include "base/command_line.h"
#include "base/environment.h"
#include "base/debug/alias.h"
#include "base/process/kill.h"
#include "base/process/launch.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "syzygy/agent/asan/block.h"
#include "syzygy/agent/asan/error_info.h"
#include "syzygy/agent/asan/rtl_impl.h"
#include "syzygy/agent/asan/runtime.h"
#include "syzygy/agent/common/stack_capture.h"
#include "syzygy/trace/protocol/call_trace_defs.h"

namespace testing {

namespace {

typedef agent::asan::HeapManagerInterface::HeapId HeapId;

using agent::asan::BlockHeader;
using agent::asan::BlockInfo;
using agent::asan::BlockLayout;
using agent::common::StackCapture;

}  // namespace

const wchar_t kSyzyAsanRtlDll[] = L"syzyasan_rtl.dll";
// The maximum time we're willing to wait for the logger process to get
// started/killed. This is very generous, but also prevents the unittests
// from hanging if the event never fires.
static const size_t kLoggerTimeOutMs = 10000;

namespace {

FARPROC check_access_fn = NULL;
bool direction_flag_forward = true;

// An exception filter that grabs and sets an exception pointer, and
// triggers only for access violations.
DWORD AccessViolationFilter(EXCEPTION_POINTERS* e, EXCEPTION_POINTERS** pe) {
  if (e->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
    *pe = e;
    return EXCEPTION_EXECUTE_HANDLER;
  }
  return EXCEPTION_CONTINUE_SEARCH;
}

// Tries to access the given address, validating whether or not an
// access violation occurs.
bool TestReadAccess(void* address, bool expect_access_violation) {
  uint8_t* m = reinterpret_cast<uint8_t*>(address);
  ULONG_PTR p = reinterpret_cast<ULONG_PTR>(address);

  // Try a read.
  uint8_t value = 0;
  EXCEPTION_POINTERS* e = NULL;
  __try {
    value = m[0];
    if (expect_access_violation)
      return false;
  }
  __except(AccessViolationFilter(GetExceptionInformation(), &e)) {
    if (!expect_access_violation)
      return false;
    if (e->ExceptionRecord == NULL ||
      e->ExceptionRecord->NumberParameters < 2 ||
      e->ExceptionRecord->ExceptionInformation[1] != p) {
      return false;
    }
    return true;
  }

  // Ensure that |value| doesn't get optimized away. If so, the attempted
  // read never occurs.
  base::debug::Alias(&value);

  return true;
}

// Tries to write at the given address, validating whether or not an
// access violation occurs.
bool TestWriteAccess(void* address, bool expect_access_violation) {
  uint8_t* m = reinterpret_cast<uint8_t*>(address);
  ULONG_PTR p = reinterpret_cast<ULONG_PTR>(address);

  // Try a write.
  EXCEPTION_POINTERS* e = NULL;
  __try {
    m[0] = 0;
    if (expect_access_violation)
      return false;
  }
  __except(AccessViolationFilter(GetExceptionInformation(), &e)) {
    if (!expect_access_violation)
      return false;
    if (e->ExceptionRecord == NULL ||
      e->ExceptionRecord->NumberParameters < 2 ||
      e->ExceptionRecord->ExceptionInformation[1] != p) {
      return false;
    }
  }

  return true;
}

// Tries to access (read/write) at the given address, validating whether or
// not an access violation occurs.
bool TestAccess(void* address, bool expect_access_violation) {
  return TestReadAccess(address, expect_access_violation) &&
    TestWriteAccess(address, expect_access_violation);
}

}  // namespace

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
    : logger_running_(false), log_contents_read_(false) {
}

void TestWithAsanLogger::SetUp() {
  // Create the log file.
  ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
  CHECK(base::CreateTemporaryFileInDir(temp_dir_.path(), &log_file_path_));

  // Open files used to redirect standard in/out/err of the logger, to not
  // pollute the console.
  logger_stdin_file_.reset(base::OpenFile(
      temp_dir_.path().AppendASCII("agent_logger_stdin.txt"), "w"));
  CHECK(logger_stdin_file_);
  logger_stdout_file_.reset(base::OpenFile(
      temp_dir_.path().AppendASCII("agent_logger_stdout.txt"), "w"));
  CHECK(logger_stdout_file_);
  logger_stderr_file_.reset(base::OpenFile(
      temp_dir_.path().AppendASCII("agent_logger_stderr.txt"), "w"));
  CHECK(logger_stderr_file_);

  // Save the environment we found.
  std::unique_ptr<base::Environment> env(base::Environment::Create());
  env->GetVar(kSyzygyRpcInstanceIdEnvVar, &old_logger_env_);
  env->GetVar(common::kSyzyAsanOptionsEnvVar, &old_asan_options_env_);

  // Configure the environment (to pass the instance id to the agent DLL).
  // We append "-0" to the process id to avoid potential conflict with other
  // tests.
  instance_id_ = base::UintToString16(::GetCurrentProcessId()) + L"-0";
  AppendToLoggerEnv(base::StringPrintf("%ls,%ls",
                                       kSyzyAsanRtlDll,
                                       instance_id_.c_str()));
  env->UnSetVar(common::kSyzyAsanOptionsEnvVar);

  log_contents_read_ = false;
  StartLogger();
}

void TestWithAsanLogger::TearDown() {
  StopLogger();

  // Restore the environment variable as we found it.
  std::unique_ptr<base::Environment> env(base::Environment::Create());
  env->SetVar(kSyzygyRpcInstanceIdEnvVar, old_logger_env_);
  env->SetVar(common::kSyzyAsanOptionsEnvVar, old_asan_options_env_);
}

bool TestWithAsanLogger::LogContains(const base::StringPiece& message) {
  if (!log_contents_read_ && logger_running_) {
    CHECK(base::ReadFileToString(log_file_path_, &log_contents_));
    log_contents_read_ = true;
  }
  return log_contents_.find(message.as_string()) != std::string::npos;
}

void TestWithAsanLogger::DeleteTempFileAndDirectory() {
  StopLogger();
  logger_stdin_file_.reset();
  logger_stdout_file_.reset();
  logger_stderr_file_.reset();
  if (temp_dir_.IsValid())
    temp_dir_.Delete();
}

void TestWithAsanLogger::StartLogger() {
  // Launch the logger as a separate process and make sure it succeeds.
  base::CommandLine cmd_line(testing::GetExeRelativePath(L"agent_logger.exe"));
  cmd_line.AppendSwitchNative("instance-id", instance_id_);
  cmd_line.AppendSwitchNative("output-file", log_file_path_.value());
  cmd_line.AppendSwitchNative("minidump-dir", temp_dir_.path().value());
  cmd_line.AppendArgNative(L"start");
  base::LaunchOptions options;
  options.start_hidden = true;
  options.stdin_handle = reinterpret_cast<HANDLE>(
      _get_osfhandle(_fileno(logger_stdin_file_.get())));
  options.stdout_handle = reinterpret_cast<HANDLE>(
      _get_osfhandle(_fileno(logger_stdout_file_.get())));
  options.stderr_handle = reinterpret_cast<HANDLE>(
      _get_osfhandle(_fileno(logger_stderr_file_.get())));
  options.inherit_handles = true;  // As per documentation.
  base::Process process = base::LaunchProcess(cmd_line, options);
  ASSERT_TRUE(process.IsValid());

  // Wait for the logger to be ready before continuing.
  std::wstring event_name;
  trace::agent_logger::AgentLogger::GetSyzygyAgentLoggerEventName(
      instance_id_, &event_name);
  base::win::ScopedHandle event(
      ::CreateEvent(NULL, FALSE, FALSE, event_name.c_str()));
  ::WaitForSingleObject(event.Get(), kLoggerTimeOutMs);
  logger_running_ = true;
}

void TestWithAsanLogger::StopLogger() {
  if (!logger_running_)
    return;
  // Launch the logger as a separate process to stop it and make sure it
  // succeeds.
  base::CommandLine cmd_line(base::FilePath(L"agent_logger.exe"));
  cmd_line.AppendSwitchNative("instance-id", instance_id_);
  cmd_line.AppendArgNative(L"stop");
  base::LaunchOptions options;
  options.start_hidden = true;
  base::Process process = base::LaunchProcess(cmd_line, options);
  ASSERT_TRUE(process.IsValid());

  int exit_code = 0;
  ASSERT_TRUE(process.WaitForExitWithTimeout(
      base::TimeDelta::FromMilliseconds(kLoggerTimeOutMs), &exit_code));
  logger_running_ = false;
}

void TestWithAsanLogger::ResetLog() {
  StopLogger();
  CHECK(base::CreateTemporaryFileInDir(temp_dir_.path(), &log_file_path_));
  StartLogger();
  log_contents_read_ = false;
}

void TestWithAsanLogger::AppendToLoggerEnv(const std::string &instance) {
  std::string instance_id;
  std::unique_ptr<base::Environment> env(base::Environment::Create());
  env->GetVar(kSyzygyRpcInstanceIdEnvVar, &instance_id);

  instance_id.append(";");
  instance_id.append(instance);

  env->SetVar(kSyzygyRpcInstanceIdEnvVar, instance_id);
}

FakeAsanBlock::FakeAsanBlock(Shadow* shadow,
                             uint32_t alloc_alignment_log,
                             StackCaptureCache* stack_cache)
    : is_initialized(false), alloc_alignment_log(alloc_alignment_log),
      alloc_alignment(1 << alloc_alignment_log), shadow_(shadow),
      stack_cache(stack_cache) {
  DCHECK_NE(static_cast<Shadow*>(nullptr), shadow);
  DCHECK_NE(static_cast<StackCaptureCache*>(nullptr), stack_cache);
  // Align the beginning of the buffer to the current granularity. Ensure that
  // there's room to store magic bytes in front of this block.
  buffer_align_begin = reinterpret_cast<uint8_t*>(
      common::AlignUp(reinterpret_cast<size_t>(buffer) + 1, alloc_alignment));
  ::memset(&block_info, 0, sizeof(block_info));
}

FakeAsanBlock::~FakeAsanBlock() {
  EXPECT_NE(0U, block_info.block_size);
  shadow_->Unpoison(buffer_align_begin, block_info.block_size);
  ::memset(buffer, 0, sizeof(buffer));
}

bool FakeAsanBlock::InitializeBlock(uint32_t alloc_size) {
  BlockLayout layout = {};
  EXPECT_TRUE(BlockPlanLayout(alloc_alignment,
                              alloc_alignment,
                              alloc_size,
                              0,
                              0,
                              &layout));

  // Initialize the Asan block.
  BlockInitialize(layout, buffer_align_begin, &block_info);
  EXPECT_NE(reinterpret_cast<void*>(NULL), block_info.body);

  StackCapture stack;
  stack.InitFromStack();
  block_info.header->alloc_stack = stack_cache->SaveStackTrace(stack);

  shadow_->PoisonAllocatedBlock(block_info);
  BlockSetChecksum(block_info);

  // Calculate the size of the zone of the buffer that we use to ensure that
  // we don't corrupt the heap.
  buffer_header_size = buffer_align_begin - buffer;
  buffer_trailer_size = kBufferSize - buffer_header_size -
      block_info.block_size;
  EXPECT_GT(kBufferSize, layout.block_size + buffer_header_size);

  // Initialize the buffer header and trailer.
  ::memset(buffer, kBufferHeaderValue, buffer_header_size);
  ::memset(buffer_align_begin + block_info.block_size, kBufferTrailerValue,
      buffer_trailer_size);

  EXPECT_TRUE(common::IsAligned(reinterpret_cast<size_t>(block_info.body),
      alloc_alignment));
  EXPECT_TRUE(common::IsAligned(
      reinterpret_cast<size_t>(buffer_align_begin) + block_info.block_size,
      agent::asan::kShadowRatio));
  EXPECT_EQ(buffer_align_begin, block_info.RawBlock());

  void* expected_user_ptr = reinterpret_cast<void*>(
      buffer_align_begin + std::max(static_cast<uint32_t>(sizeof(BlockHeader)),
                                    alloc_alignment));
  EXPECT_EQ(block_info.body, expected_user_ptr);

  size_t i = 0;
  // Ensure that the buffer header is accessible and correctly tagged.
  for (; i < buffer_header_size; ++i) {
    EXPECT_EQ(kBufferHeaderValue, buffer[i]);
    EXPECT_TRUE(shadow_->IsAccessible(buffer + i));
  }
  size_t user_block_offset = block_info.RawBody() - buffer;
  // Ensure that the block header isn't accessible.
  for (; i < user_block_offset; ++i)
    EXPECT_FALSE(shadow_->IsAccessible(buffer + i));

  // Ensure that the user block is accessible.
  size_t block_trailer_offset = i + alloc_size;
  for (; i < block_trailer_offset; ++i)
    EXPECT_TRUE(shadow_->IsAccessible(buffer + i));

  // Ensure that the block trailer isn't accessible.
  for (; i < buffer_header_size + block_info.block_size; ++i)
    EXPECT_FALSE(shadow_->IsAccessible(buffer + i));

  // Ensure that the buffer trailer is accessible and correctly tagged.
  for (; i < kBufferSize; ++i) {
    EXPECT_EQ(kBufferTrailerValue, buffer[i]);
    EXPECT_TRUE(shadow_->IsAccessible(buffer + i));
  }

  is_initialized = true;
  return true;
}

bool FakeAsanBlock::TestBlockMetadata() {
  if (!is_initialized)
    return false;

  // Ensure that the block header is valid. BlockGetHeaderFromBody takes
  // care of checking the magic number in the signature of the block.
  BlockHeader* block_header = block_info.header;
  EXPECT_NE(static_cast<BlockHeader*>(NULL), block_header);
  BlockInfo block_info = {};
  EXPECT_TRUE(BlockInfoFromMemory(block_header, &block_info));
  const uint8_t* cursor = buffer_align_begin;
  EXPECT_EQ(::GetCurrentThreadId(), block_info.trailer->alloc_tid);
  EXPECT_TRUE(block_header->alloc_stack != NULL);
  EXPECT_EQ(agent::asan::ALLOCATED_BLOCK, block_header->state);
  EXPECT_TRUE(shadow_->IsBlockStartByte(cursor++));
  for (; cursor < block_info.RawBody(); ++cursor)
    EXPECT_TRUE(shadow_->IsLeftRedzone(cursor));
  const uint8_t* aligned_trailer_begin =
      reinterpret_cast<const uint8_t*>(common::AlignUp(
          reinterpret_cast<size_t>(block_info.body) + block_info.body_size,
          agent::asan::kShadowRatio));
  for (const uint8_t* pos = aligned_trailer_begin;
       pos < buffer_align_begin + block_info.block_size; ++pos) {
    EXPECT_TRUE(shadow_->IsRightRedzone(pos));
  }

  return true;
}

bool FakeAsanBlock::MarkBlockAsQuarantinedImpl(bool flood_filled) {
  if (!is_initialized)
    return false;

  EXPECT_NE(static_cast<BlockHeader*>(NULL), block_info.header);
  EXPECT_TRUE(block_info.header->free_stack == NULL);
  EXPECT_TRUE(block_info.trailer != NULL);
  EXPECT_EQ(0U, block_info.trailer->free_tid);

  shadow_->MarkAsFreed(block_info.body, block_info.body_size);
  StackCapture stack;
  stack.InitFromStack();
  block_info.header->free_stack = stack_cache->SaveStackTrace(stack);
  block_info.trailer->free_tid = ::GetCurrentThreadId();
  block_info.trailer->free_ticks = ::GetTickCount();

  if (flood_filled) {
    block_info.header->state = agent::asan::QUARANTINED_FLOODED_BLOCK;
    ::memset(block_info.body, agent::asan::kBlockFloodFillByte,
             block_info.body_size);
  } else {
    block_info.header->state = agent::asan::QUARANTINED_BLOCK;
  }

  BlockSetChecksum(block_info);

  size_t i = 0;
  // Ensure that the buffer header is accessible and correctly tagged.
  for (; i < buffer_header_size; ++i) {
    EXPECT_EQ(kBufferHeaderValue, buffer[i]);
    EXPECT_TRUE(shadow_->IsAccessible(buffer + i));
  }
  // Ensure that the whole block isn't accessible.
  for (; i < buffer_header_size + block_info.block_size; ++i)
    EXPECT_FALSE(shadow_->IsAccessible(buffer + i));

  // Ensure that the buffer trailer is accessible and correctly tagged.
  for (; i < kBufferSize; ++i) {
    EXPECT_EQ(kBufferTrailerValue, buffer[i]);
    EXPECT_TRUE(shadow_->IsAccessible(buffer + i));
  }
  return true;
}

bool FakeAsanBlock::MarkBlockAsQuarantined() {
  return MarkBlockAsQuarantinedImpl(false);
}

bool FakeAsanBlock::MarkBlockAsQuarantinedFlooded() {
  return MarkBlockAsQuarantinedImpl(true);
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
void ExpectEqualContexts(const CONTEXT& c1,
                         const CONTEXT& c2,
                         bool ignore_flags) {
  // Segment registers.
  EXPECT_EQ(static_cast<WORD>(c1.SegGs), static_cast<WORD>(c2.SegGs));
  EXPECT_EQ(static_cast<WORD>(c1.SegFs), static_cast<WORD>(c2.SegFs));
  EXPECT_EQ(static_cast<WORD>(c1.SegEs), static_cast<WORD>(c2.SegEs));
  EXPECT_EQ(static_cast<WORD>(c1.SegDs), static_cast<WORD>(c2.SegDs));

#ifndef _WIN64
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
#endif
  EXPECT_EQ(static_cast<WORD>(c1.SegCs), static_cast<WORD>(c2.SegCs));
  if (!ignore_flags)
    EXPECT_EQ(c1.EFlags, c2.EFlags);
#ifndef _WIN64
  EXPECT_EQ(c1.Esp, c2.Esp);
#endif
  EXPECT_EQ(static_cast<WORD>(c1.SegSs), static_cast<WORD>(c2.SegSs));
}

}  // namespace

MemoryAccessorTester* MemoryAccessorTester::instance_ = nullptr;

MemoryAccessorTester::MemoryAccessorTester()
    : expected_error_type_(agent::asan::UNKNOWN_BAD_ACCESS),
      memory_error_detected_(false) {
  Initialize();
}

MemoryAccessorTester::~MemoryAccessorTester() {
  DCHECK_NE(static_cast<MemoryAccessorTester*>(nullptr), instance_);
  instance_ = nullptr;
}

void MemoryAccessorTester::Initialize() {
  DCHECK_EQ(static_cast<MemoryAccessorTester*>(nullptr), instance_);
  instance_ = this;
  ::memset(&error_context_, 0xCF, sizeof(error_context_));
  ::memset(&last_error_info_, 0, sizeof(last_error_info_));
}

void MemoryAccessorTester::AsanErrorCallbackImpl(AsanErrorInfo* error_info) {
  EXPECT_NE(reinterpret_cast<AsanErrorInfo*>(NULL), error_info);
  EXPECT_NE(agent::asan::UNKNOWN_BAD_ACCESS, error_info->error_type);

  EXPECT_EQ(expected_error_type_, error_info->error_type);
  if (error_info->error_type >= agent::asan::USE_AFTER_FREE) {
    // We should at least have the stack trace of the allocation of this block.
    EXPECT_GT(error_info->block_info.alloc_stack_size, 0U);
    EXPECT_NE(0U, error_info->block_info.alloc_tid);
    if (error_info->error_type == agent::asan::USE_AFTER_FREE ||
        error_info->error_type == agent::asan::DOUBLE_FREE) {
      EXPECT_GT(error_info->block_info.free_stack_size, 0U);
      EXPECT_NE(0U, error_info->block_info.free_tid);
    } else {
      EXPECT_EQ(error_info->block_info.free_stack_size, 0U);
      EXPECT_EQ(0U, error_info->block_info.free_tid);
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
        agent::asan::AsanBlockInfo block_info = range_info->first.block_info[j];
        for (size_t k = 0; k < range_info->first.block_info[j].alloc_stack_size;
             ++k) {
          block_info.alloc_stack[k] =
              range_info->first.block_info[j].alloc_stack[k];
        }
        for (size_t k = 0; k < range_info->first.block_info[j].free_stack_size;
             ++k) {
          block_info.free_stack[k] =
              range_info->first.block_info[j].free_stack[k];
        }
        block_infos->push_back(block_info);
      }
    }
  }

  error_context_ = error_info->context;
}

void MemoryAccessorTester::AsanErrorCallback(AsanErrorInfo* error_info) {
  DCHECK_NE(static_cast<MemoryAccessorTester*>(nullptr), instance_);
  instance_->AsanErrorCallbackImpl(error_info);
}

#ifndef _WIN64
SyzyAsanMemoryAccessorTester::SyzyAsanMemoryAccessorTester()
    : ignore_flags_(false) {
}
SyzyAsanMemoryAccessorTester::SyzyAsanMemoryAccessorTester(
    IgnoreFlags /* ignore_flags */)
    : ignore_flags_(true) {
}

void SyzyAsanMemoryAccessorTester::Initialize() {
  ::memset(&context_before_hook_, 0xCD, sizeof(context_before_hook_));
  ::memset(&context_after_hook_, 0xCE, sizeof(context_after_hook_));
  MemoryAccessorTester::Initialize();
}

void SyzyAsanMemoryAccessorTester::AssertMemoryErrorIsDetected(
    FARPROC access_fn,
    void* ptr,
    BadAccessKind bad_access_type) {
  expected_error_type_ = bad_access_type;
  CheckAccessAndCompareContexts(access_fn, ptr);
  ASSERT_TRUE(memory_error_detected_);
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

void SyzyAsanMemoryAccessorTester::CheckAccessAndCompareContexts(
    FARPROC access_fn,
    void* ptr) {
  memory_error_detected_ = false;

  check_access_fn = access_fn;

  CheckAccessAndCaptureContexts(
      &context_before_hook_, &context_after_hook_, ptr);

  ExpectEqualContexts(context_before_hook_, context_after_hook_, ignore_flags_);
  if (memory_error_detected_) {
    ExpectEqualContexts(context_before_hook_, error_context_, ignore_flags_);
  }

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

void SyzyAsanMemoryAccessorTester::CheckSpecialAccessAndCompareContexts(
    FARPROC access_fn,
    StringOperationDirection direction,
    void* dst,
    void* src,
    int len) {
  memory_error_detected_ = false;

  direction_flag_forward = (direction == DIRECTION_FORWARD);
  check_access_fn = access_fn;

  CheckSpecialAccess(
      &context_before_hook_, &context_after_hook_, dst, src, len);

  ExpectEqualContexts(context_before_hook_, context_after_hook_, ignore_flags_);
  if (memory_error_detected_) {
    ExpectEqualContexts(context_before_hook_, error_context_, ignore_flags_);
  }

  check_access_fn = NULL;
}

void SyzyAsanMemoryAccessorTester::ExpectSpecialMemoryErrorIsDetected(
    FARPROC access_fn,
    StringOperationDirection direction,
    bool expect_error,
    void* dst,
    void* src,
    int32_t length,
    BadAccessKind bad_access_type) {
  DCHECK(dst != NULL);
  DCHECK(src != NULL);
  ASSERT_TRUE(check_access_fn == NULL);

  expected_error_type_ = bad_access_type;

  // Perform memory accesses inside the range.
  ASSERT_NO_FATAL_FAILURE(
      CheckSpecialAccessAndCompareContexts(
          access_fn, direction, dst, src, length));

  EXPECT_EQ(expect_error, memory_error_detected_);
  check_access_fn = NULL;
}
#endif

void ClangMemoryAccessorTester::CheckAccess(FARPROC access_fn, void* ptr) {
  memory_error_detected_ = false;
  check_access_fn = access_fn;
  reinterpret_cast<void (*)(const void*)>(access_fn)(ptr);
  check_access_fn = NULL;
}

void ClangMemoryAccessorTester::AssertMemoryErrorIsDetected(
    FARPROC access_fn,
    void* ptr,
    BadAccessKind bad_access_type) {
  expected_error_type_ = bad_access_type;
  reinterpret_cast<void (*)(const void*)>(access_fn)(ptr);
  ASSERT_TRUE(memory_error_detected_);
}

TestMemoryInterceptors::TestMemoryInterceptors()
    : heap_(NULL), src_(NULL), dst_(NULL) {
}

void TestMemoryInterceptors::SetUp() {
  testing::TestWithAsanLogger::SetUp();

  // Make sure the logging routes to our instance.
  AppendToLoggerEnv(base::StringPrintf("syzyasan_rtl_unittests.exe,%u",
                                        ::GetCurrentProcessId()));

  asan_runtime_.SetUp(std::wstring());

  // Heap checking on error is expensive, so turn it down here.
  asan_runtime_.params().check_heap_on_failure = false;

  agent::asan::SetUpRtl(&asan_runtime_);

  asan_runtime_.SetErrorCallBack(
      base::Bind(testing::MemoryAccessorTester::AsanErrorCallback));
  heap_ = asan_HeapCreate(0, 0, 0);
  ASSERT_TRUE(heap_ != NULL);

  src_ = reinterpret_cast<byte*>(asan_HeapAlloc(heap_, 0, kAllocSize));
  dst_ = reinterpret_cast<byte*>(asan_HeapAlloc(heap_, 0, kAllocSize));
  ASSERT_TRUE(src_ && dst_);

  // String instructions may compare memory contents and bail early on
  // differences, so fill the buffers to make sure the checks go the full
  // distance.
  ::memset(src_, 0xFF, kAllocSize);
  ::memset(dst_, 0xFF, kAllocSize);
}

void TestMemoryInterceptors::TearDown() {
  if (heap_ != NULL) {
    asan_HeapFree(heap_, 0, src_);
    asan_HeapFree(heap_, 0, dst_);

    asan_HeapDestroy(heap_);
    heap_ = NULL;
  }
  agent::asan::TearDownRtl();
  asan_runtime_.TearDown();
  testing::TestWithAsanLogger::TearDown();
}

#ifndef _WIN64
void TestMemoryInterceptors::TestValidAccess(
    const InterceptFunction* fns, size_t num_fns) {
  for (size_t i = 0; i < num_fns; ++i) {
    const InterceptFunction& fn = fns[i];

    SyzyAsanMemoryAccessorTester tester;
    tester.CheckAccessAndCompareContexts(
        reinterpret_cast<FARPROC>(fn.function), src_);

    ASSERT_FALSE(tester.memory_error_detected());
  }
}

void TestMemoryInterceptors::TestValidAccessIgnoreFlags(
    const InterceptFunction* fns, size_t num_fns) {
  for (size_t i = 0; i < num_fns; ++i) {
    const InterceptFunction& fn = fns[i];

    SyzyAsanMemoryAccessorTester tester(
        SyzyAsanMemoryAccessorTester::IGNORE_FLAGS);
    tester.CheckAccessAndCompareContexts(
        reinterpret_cast<FARPROC>(fn.function), src_);

    ASSERT_FALSE(tester.memory_error_detected());
  }
}

void TestMemoryInterceptors::TestOverrunAccess(
    const InterceptFunction* fns, size_t num_fns) {
  for (size_t i = 0; i < num_fns; ++i) {
    const InterceptFunction& fn = fns[i];

    SyzyAsanMemoryAccessorTester tester;
    tester.AssertMemoryErrorIsDetected(
        reinterpret_cast<FARPROC>(fn.function), src_ + kAllocSize,
        SyzyAsanMemoryAccessorTester::BadAccessKind::HEAP_BUFFER_OVERFLOW);

    ASSERT_TRUE(tester.memory_error_detected());
  }
}

void TestMemoryInterceptors::TestOverrunAccessIgnoreFlags(
    const InterceptFunction* fns, size_t num_fns) {
  for (size_t i = 0; i < num_fns; ++i) {
    const InterceptFunction& fn = fns[i];

    SyzyAsanMemoryAccessorTester tester(
        SyzyAsanMemoryAccessorTester::IGNORE_FLAGS);
    tester.AssertMemoryErrorIsDetected(
        reinterpret_cast<FARPROC>(fn.function),
        src_ + kAllocSize,
        MemoryAccessorTester::BadAccessKind::HEAP_BUFFER_OVERFLOW);

    ASSERT_TRUE(tester.memory_error_detected());
  }
}

void TestMemoryInterceptors::TestUnderrunAccess(
    const InterceptFunction* fns, size_t num_fns) {
  for (size_t i = 0; i < num_fns; ++i) {
    const InterceptFunction& fn = fns[i];

    // TODO(someone): the 32 byte access checker does not fire on 32 byte
    //     underrun. I guess the checkers test a single shadow byte at most
    //     whereas it'd be more correct for access checkers to test as many
    //     shadow bytes as is appropriate for the range of memory they touch.
    SyzyAsanMemoryAccessorTester tester;
    tester.AssertMemoryErrorIsDetected(
        reinterpret_cast<FARPROC>(fn.function),
        src_ - 8,
        MemoryAccessorTester::BadAccessKind::HEAP_BUFFER_UNDERFLOW);

    ASSERT_TRUE(tester.memory_error_detected());
  }
}

void TestMemoryInterceptors::TestUnderrunAccessIgnoreFlags(
    const InterceptFunction* fns, size_t num_fns) {
  for (size_t i = 0; i < num_fns; ++i) {
    const InterceptFunction& fn = fns[i];

    // TODO(someone): the 32 byte access checker does not fire on 32 byte
    //     underrun. I guess the checkers test a single shadow byte at most
    //     whereas it'd be more correct for access checkers to test as many
    //     shadow bytes as is appropriate for the range of memory they touch.
    SyzyAsanMemoryAccessorTester tester(
        SyzyAsanMemoryAccessorTester::IGNORE_FLAGS);
    tester.AssertMemoryErrorIsDetected(
        reinterpret_cast<FARPROC>(fn.function),
        src_ - 8,
        MemoryAccessorTester::BadAccessKind::HEAP_BUFFER_UNDERFLOW);

    ASSERT_TRUE(tester.memory_error_detected());
  }
}

void TestMemoryInterceptors::TestStringValidAccess(
    const StringInterceptFunction* fns, size_t num_fns) {
  for (size_t i = 0; i < num_fns; ++i) {
    const StringInterceptFunction& fn = fns[i];

    SyzyAsanMemoryAccessorTester tester;
    tester.CheckSpecialAccessAndCompareContexts(
        reinterpret_cast<FARPROC>(fn.function),
        SyzyAsanMemoryAccessorTester::DIRECTION_FORWARD, dst_, src_,
        static_cast<int>(kAllocSize / fn.size));
    ASSERT_FALSE(tester.memory_error_detected());

    tester.CheckSpecialAccessAndCompareContexts(
        reinterpret_cast<FARPROC>(fn.function),
        SyzyAsanMemoryAccessorTester::DIRECTION_BACKWARD,
        dst_ + kAllocSize - fn.size, src_ + kAllocSize - fn.size,
        static_cast<int>(kAllocSize / fn.size));

    ASSERT_FALSE(tester.memory_error_detected());
  }
}

void TestMemoryInterceptors::TestStringOverrunAccess(
    const StringInterceptFunction* fns, size_t num_fns) {
  for (size_t i = 0; i < num_fns; ++i) {
    const StringInterceptFunction& fn = fns[i];

    SyzyAsanMemoryAccessorTester tester;
    size_t oob_len = 0;
    byte* oob_dst = NULL;
    byte* oob_src = NULL;

    // Half the string function intercepts are for rep-prefixed instructions,
    // which count on "ecx", and the other half is for non-prefixed
    // instructions that always perform a single access.
    // Compute appropriate pointers for both variants, forwards.
    if (fn.uses_counter) {
      oob_len = kAllocSize / fn.size;
      oob_dst = dst_ + fn.size;
      oob_src = src_ + fn.size;
    } else {
      oob_len = 1;
      oob_dst = dst_ + kAllocSize;
      oob_src = src_ + kAllocSize;
    }

    ASSERT_NE(agent::asan::ASAN_UNKNOWN_ACCESS, fn.dst_access_mode);
    // Overflow on dst forwards.
    tester.ExpectSpecialMemoryErrorIsDetected(
        reinterpret_cast<FARPROC>(fn.function),
        SyzyAsanMemoryAccessorTester::DIRECTION_FORWARD, true, oob_dst, src_,
        static_cast<int>(oob_len),
        MemoryAccessorTester::BadAccessKind::HEAP_BUFFER_OVERFLOW);

    if (fn.src_access_mode != agent::asan::ASAN_UNKNOWN_ACCESS) {
      // Overflow on src forwards.
      tester.ExpectSpecialMemoryErrorIsDetected(
          reinterpret_cast<FARPROC>(fn.function),
          SyzyAsanMemoryAccessorTester::DIRECTION_FORWARD, true, dst_, oob_src,
          static_cast<int>(oob_len),
          MemoryAccessorTester::BadAccessKind::HEAP_BUFFER_OVERFLOW);
    }

    // Compute appropriate pointers for both variants, backwards.
    if (fn.uses_counter) {
      oob_len = kAllocSize / fn.size;
    } else {
      oob_len = 1;
    }

    oob_dst = dst_ + kAllocSize;
    oob_src = src_ + kAllocSize;

    ASSERT_NE(agent::asan::ASAN_UNKNOWN_ACCESS, fn.dst_access_mode);
    // Overflow on dst backwards.
    tester.ExpectSpecialMemoryErrorIsDetected(
        reinterpret_cast<FARPROC>(fn.function),
        SyzyAsanMemoryAccessorTester::DIRECTION_BACKWARD, true, oob_dst,
        src_ + kAllocSize - fn.size, static_cast<int>(oob_len),
        MemoryAccessorTester::BadAccessKind::HEAP_BUFFER_OVERFLOW);

    if (fn.src_access_mode != agent::asan::ASAN_UNKNOWN_ACCESS) {
      // Overflow on src backwards.
      tester.ExpectSpecialMemoryErrorIsDetected(
          reinterpret_cast<FARPROC>(fn.function),
          SyzyAsanMemoryAccessorTester::DIRECTION_BACKWARD, true,
          dst_ + kAllocSize - fn.size, oob_dst, static_cast<int>(oob_len),
          MemoryAccessorTester::BadAccessKind::HEAP_BUFFER_OVERFLOW);
    }
  }
}
#endif

void TestMemoryInterceptors::TestClangValidAccess(
    const ClangInterceptFunction* fns,
    size_t num_fns) {
  for (size_t i = 0; i < num_fns; ++i) {
    const ClangInterceptFunction& fn = fns[i];

    ClangMemoryAccessorTester tester;
    tester.CheckAccess(reinterpret_cast<FARPROC>(fn.function), src_);

    ASSERT_FALSE(tester.memory_error_detected());
  }
}

void TestMemoryInterceptors::TestClangOverrunAccess(
    const ClangInterceptFunction* fns,
    size_t num_fns) {
  for (size_t i = 0; i < num_fns; ++i) {
    const ClangInterceptFunction& fn = fns[i];

    ClangMemoryAccessorTester tester;
    tester.AssertMemoryErrorIsDetected(
        reinterpret_cast<FARPROC>(fn.function), src_ + kAllocSize,
        MemoryAccessorTester::BadAccessKind::HEAP_BUFFER_OVERFLOW);

    ASSERT_TRUE(tester.memory_error_detected());
  }
}

void TestMemoryInterceptors::TestClangUnderrunAccess(
    const ClangInterceptFunction* fns,
    size_t num_fns) {
  for (size_t i = 0; i < num_fns; ++i) {
    const ClangInterceptFunction& fn = fns[i];
    ClangMemoryAccessorTester tester;
    tester.AssertMemoryErrorIsDetected(
        reinterpret_cast<FARPROC>(fn.function), src_ - 8,
        MemoryAccessorTester::BadAccessKind::HEAP_BUFFER_UNDERFLOW);

    ASSERT_TRUE(tester.memory_error_detected());
  }
}

bool IsAccessible(void* address) {
  return testing::TestAccess(address, false);
}

bool IsNotAccessible(void* address) {
  return testing::TestAccess(address, true);
}

DebugShadow::Metadata::Metadata()
    : address(nullptr), size(0),
      marker(agent::asan::kHeapAddressableMarker) {
}

DebugShadow::Metadata::Metadata(
    const void* address, size_t size, ShadowMarker marker)
    : address(address), size(size), marker(marker) {
  stack_capture.InitFromStack();
}

DebugShadow::Metadata::Metadata(const Metadata& rhs)
    : address(rhs.address), size(rhs.size), marker(rhs.marker) {
  if (rhs.stack_capture.num_frames() > 0) {
    stack_capture.InitFromExistingStack(rhs.stack_capture);
  }
}

DebugShadow::Metadata& DebugShadow::Metadata::operator=(const Metadata& rhs) {
  address = rhs.address;
  size = rhs.size;
  marker = rhs.marker;
  if (rhs.stack_capture.num_frames() > 0) {
    stack_capture.InitFromExistingStack(rhs.stack_capture);
  }
  return *this;
}

void DebugShadow::SetShadowMemory(
    const void* address, size_t length, ShadowMarker marker) {
  ClearIntersection(address, length);
  if (marker != agent::asan::kHeapAddressableMarker) {
    Range range(reinterpret_cast<uintptr_t>(address), length);
    Metadata data(address, length, marker);

    ShadowAddressSpace::RangeMapIter it;
    CHECK(shadow_address_space_.Insert(range, data, &it));

    // If this is memory being returned to a reserved pool, then potentially
    // merge with neighboring such ranges. This keeps the address space as
    // human legible as possible.
    if (marker == agent::asan::kAsanReservedMarker) {
      auto it1 = it;
      auto it2 = it;
      bool merge = false;
      Metadata data = it->second;

      // Check to see if there's a range to the left, and if it needs to be
      // merged.
      if (it != shadow_address_space_.begin()) {
        it1--;
        if (it1->first.end() == it->first.start() &&
            it1->second.marker == it->second.marker) {
          merge = true;
          if (it1->second.size >= data.size)
            data = it1->second;
        } else {
          ++it1;
        }
      }

      // Check to see if there's a range to the right, and if it needs to be
      // merged.
      ++it2;
      if (it2 != shadow_address_space_.end()) {
        if (it->first.end() == it2->first.start() &&
            it->second.marker == it2->second.marker) {
          merge = true;
          if (it2->second.size > data.size)
            data = it2->second;
        } else {
          --it2;
        }
      } else {
        --it2;
      }

      if (merge) {
        Range range(it1->first.start(),
                    it2->first.end() - it1->first.start());
        CHECK(shadow_address_space_.SubsumeInsert(range, data));
      }
    }
  }
}

void DebugShadow::GetPointerAndSizeImpl(
    void const** self, size_t* size) const {
  DCHECK_NE(static_cast<void**>(nullptr), self);
  DCHECK_NE(static_cast<size_t*>(nullptr), size);
  *self = this;
  *size = sizeof(*this);
}

void DebugShadow::ClearIntersection(const void* addr, size_t size) {
  uintptr_t start = reinterpret_cast<uintptr_t>(addr);

  auto range = Range(reinterpret_cast<uintptr_t>(addr), size);
  ShadowAddressSpace::RangeMapIterPair iter_pair =
      shadow_address_space_.FindIntersecting(range);

  bool reinsert_head_range = false;
  Range head_range;
  Metadata head_data;

  bool reinsert_tail_range = false;
  Range tail_range;
  Metadata tail_data;

  // If the range is non-empty then remember the portion of the head and tail
  // ranges to be reinserted, if any.
  if (iter_pair.first != iter_pair.second) {
    auto it = iter_pair.first;
    if (it->first.start() < start) {
      reinsert_head_range = true;
      head_range = Range(
          it->first.start(),
          start - it->first.start());
      head_data = it->second;
    }

    it = iter_pair.second;
    --it;
    if (start + size < it->first.end()) {
      reinsert_tail_range = true;
      tail_range = Range(
          range.end(),
          it->first.end() - range.end());
      tail_data = it->second;
    }
  }

  // Delete the entire range.
  shadow_address_space_.Remove(iter_pair);
  if (reinsert_head_range)
    CHECK(shadow_address_space_.Insert(head_range, head_data));
  if (reinsert_tail_range)
    CHECK(shadow_address_space_.Insert(tail_range, tail_data));
}

}  // namespace testing
