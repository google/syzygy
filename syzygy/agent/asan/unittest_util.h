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

#ifndef SYZYGY_AGENT_ASAN_UNITTEST_UTIL_H_
#define SYZYGY_AGENT_ASAN_UNITTEST_UTIL_H_

#include <string>
#include <utility>
#include <vector>

#include "base/bind.h"
#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/memory/ref_counted.h"
#include "base/strings/string_piece.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/agent/asan/block.h"
#include "syzygy/agent/asan/error_info.h"
#include "syzygy/agent/asan/heap.h"
#include "syzygy/agent/asan/logger.h"
#include "syzygy/agent/asan/memory_notifier.h"
#include "syzygy/agent/asan/page_protection_helpers.h"
#include "syzygy/agent/asan/runtime.h"
#include "syzygy/agent/asan/shadow.h"
#include "syzygy/agent/asan/stack_capture_cache.h"
#include "syzygy/agent/asan/memory_notifiers/null_memory_notifier.h"
#include "syzygy/agent/common/stack_capture.h"
#include "syzygy/core/address.h"
#include "syzygy/core/address_space.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/trace/agent_logger/agent_logger.h"
#include "syzygy/trace/agent_logger/agent_logger_rpc_impl.h"

namespace testing {

using agent::asan::AsanErrorInfo;
using agent::asan::memory_notifiers::NullMemoryNotifier;
using agent::asan::Shadow;
using agent::asan::StackCaptureCache;

// The default name of the runtime library DLL.
extern const wchar_t kSyzyAsanRtlDll[];

// A unittest fixture that sets up a OnExceptionCallback for use with
// BlockInfoFromMemory and BlockGetHeaderFromBody. This is the base fixture
// class for all ASAN-related test fixtures declared in this file.
class LenientOnExceptionCallbackTest : public testing::Test {
 public:
  MOCK_METHOD1(OnExceptionCallback, void(EXCEPTION_POINTERS*));

  void SetUp() override {
    testing::Test::SetUp();
    agent::asan::SetOnExceptionCallback(
        base::Bind(&LenientOnExceptionCallbackTest::OnExceptionCallback,
                   base::Unretained(this)));
  }

  void TearDown() override {
    agent::asan::ClearOnExceptionCallback();
    testing::Test::TearDown();
  }
};
typedef testing::StrictMock<LenientOnExceptionCallbackTest>
    OnExceptionCallbackTest;

// A unittest fixture that ensures that an Asan logger instance is up and
// running for the duration of the test. Output is captured to a file so that
// its contents can be read after the test if necessary.
class TestWithAsanLogger : public OnExceptionCallbackTest {
 public:
  TestWithAsanLogger();

  // @name testing::Test overrides.
  // @{
  void SetUp() override;
  void TearDown() override;
  // @}

  // @name Accessors.
  // @{
  const std::wstring& instance_id() const { return instance_id_; }
  const base::FilePath& log_file_path() const { return log_file_path_; }
  const base::FilePath& temp_dir() const { return temp_dir_.path(); }
  // @}

  bool LogContains(const base::StringPiece& message);

  // Delete the temporary file used for the logging and its directory.
  void DeleteTempFileAndDirectory();

  // Starts the logger process.
  void StartLogger();

  // Stops the logger process.
  void StopLogger();

  // Reset the log contents.
  void ResetLog();

  // Appends @p instance to the RPC logger instance environment variable.
  void AppendToLoggerEnv(const std::string &instance);

 private:
  // The instance ID used by the running logger instance.
  std::wstring instance_id_;

  // The path to the log file where the the logger instance will write.
  base::FilePath log_file_path_;

  // Status of the logger process.
  bool logger_running_;

  // A temporary directory into which the log file will be written.
  base::ScopedTempDir temp_dir_;

  // The contents of the log. These are read by calling LogContains.
  bool log_contents_read_;
  std::string log_contents_;

  // Value of the logger instance environment variable before SetUp.
  std::string old_logger_env_;

  // Value of the asan options environment variable before SetUp.
  std::string old_asan_options_env_;

  // Redirection files for the logger.
  base::ScopedFILE logger_stdin_file_;
  base::ScopedFILE logger_stdout_file_;
  base::ScopedFILE logger_stderr_file_;
};

// Shorthand for discussing all the asan runtime functions.
#ifndef _WIN64
#define ASAN_RTL_FUNCTIONS(F)                                                  \
  F(WINAPI, HANDLE, GetProcessHeap, (), ())                                    \
  F(WINAPI, HANDLE, HeapCreate,                                                \
    (DWORD options, SIZE_T initial_size, SIZE_T maximum_size),                 \
    (options, initial_size, maximum_size))                                     \
  F(WINAPI, BOOL, HeapDestroy, (HANDLE heap), (heap))                          \
  F(WINAPI, LPVOID, HeapAlloc, (HANDLE heap, DWORD flags, SIZE_T bytes),       \
    (heap, flags, bytes))                                                      \
  F(WINAPI, LPVOID, HeapReAlloc,                                               \
    (HANDLE heap, DWORD flags, LPVOID mem, SIZE_T bytes),                      \
    (heap, flags, mem, bytes))                                                 \
  F(WINAPI, BOOL, HeapFree, (HANDLE heap, DWORD flags, LPVOID mem),            \
    (heap, flags, mem))                                                        \
  F(WINAPI, SIZE_T, HeapSize, (HANDLE heap, DWORD flags, LPCVOID mem),         \
    (heap, flags, mem))                                                        \
  F(WINAPI, BOOL, HeapValidate, (HANDLE heap, DWORD flags, LPCVOID mem),       \
    (heap, flags, mem))                                                        \
  F(WINAPI, SIZE_T, HeapCompact, (HANDLE heap, DWORD flags), (heap, flags))    \
  F(WINAPI, BOOL, HeapLock, (HANDLE heap), (heap))                             \
  F(WINAPI, BOOL, HeapUnlock, (HANDLE heap), (heap))                           \
  F(WINAPI, BOOL, HeapWalk, (HANDLE heap, LPPROCESS_HEAP_ENTRY entry),         \
    (heap, entry))                                                             \
  F(WINAPI, BOOL, HeapSetInformation,                                          \
    (HANDLE heap, HEAP_INFORMATION_CLASS info_class, PVOID info,               \
     SIZE_T info_length),                                                      \
    (heap, info_class, info, info_length))                                     \
  F(WINAPI, BOOL, HeapQueryInformation,                                        \
    (HANDLE heap, HEAP_INFORMATION_CLASS info_class, PVOID info,               \
     SIZE_T info_length, PSIZE_T return_length),                               \
    (heap, info_class, info, info_length, return_length))                      \
  F(WINAPI, void, SetCallBack, (void (*callback)(AsanErrorInfo * error_info)), \
    (callback))                                                                \
  F(_cdecl, void*, memcpy,                                                     \
    (void* destination, const void* source, size_t num),                       \
    (destination, source, num))                                                \
  F(_cdecl, void*, memmove,                                                    \
    (void* destination, const void* source, size_t num),                       \
    (destination, source, num))                                                \
  F(_cdecl, void*, memset, (void* ptr, int value, size_t num),                 \
    (ptr, value, num))                                                         \
  F(_cdecl, const void*, memchr, (const void* ptr, int value, size_t num),     \
    (ptr, value, num))                                                         \
  F(_cdecl, size_t, strcspn, (const char* str1, const char* str2),             \
    (str1, str2))                                                              \
  F(_cdecl, size_t, strlen, (const char* str), (str))                          \
  F(_cdecl, size_t, strnlen, (const char* str, size_t max_len),                \
    (str, max_len))                                                            \
  F(_cdecl, const char*, strrchr, (const char* str, int character),            \
    (str, character))                                                          \
  F(_cdecl, const wchar_t*, wcsrchr, (const wchar_t* str, int character),      \
    (str, character))                                                          \
  F(_cdecl, const wchar_t*, wcschr, (const wchar_t* str, int character),       \
    (str, character))                                                          \
  F(_cdecl, int, strcmp, (const char* str1, const char* str2), (str1, str2))   \
  F(_cdecl, const char*, strpbrk, (const char* str1, const char* str2),        \
    (str1, str2))                                                              \
  F(_cdecl, const char*, strstr, (const char* str1, const char* str2),         \
    (str1, str2))                                                              \
  F(_cdecl, size_t, wcsnlen, (const wchar_t* str, size_t max_len),             \
    (str, max_len))                                                            \
  F(_cdecl, const wchar_t*, wcsstr,                                            \
    (const wchar_t* str1, const wchar_t* str2), (str1, str2))                  \
  F(_cdecl, size_t, strspn, (const char* str1, const char* str2),              \
    (str1, str2))                                                              \
  F(_cdecl, char*, strncpy,                                                    \
    (char* destination, const char* source, size_t num),                       \
    (destination, source, num))                                                \
  F(_cdecl, char*, strncat,                                                    \
    (char* destination, const char* source, size_t num),                       \
    (destination, source, num))                                                \
  F(WINAPI, BOOL, ReadFile,                                                    \
    (HANDLE file_handle, LPVOID buffer, DWORD bytes_to_read,                   \
     LPDWORD bytes_read, LPOVERLAPPED overlapped),                             \
    (file_handle, buffer, bytes_to_read, bytes_read, overlapped))              \
  F(WINAPI, BOOL, WriteFile,                                                   \
    (HANDLE file_handle, LPCVOID buffer, DWORD bytes_to_write,                 \
     LPDWORD bytes_written, LPOVERLAPPED overlapped),                          \
    (file_handle, buffer, bytes_to_write, bytes_written, overlapped))          \
  F(_cdecl, void, SetInterceptorCallback, (void (*callback)()), (callback))    \
  F(WINAPI, agent::asan::AsanRuntime*, GetActiveRuntime, (), ())               \
  F(WINAPI, void, InitializeCrashReporter, (), ())                             \
  F(WINAPI, void, SetAllocationFilterFlag, (), ())                             \
  F(WINAPI, void, ClearAllocationFilterFlag, (), ())
#else
// A copy of the previous block minus {Set,Clear}AllocationFilterFlag functions,
// as they're not implemented on win64.
// TODO: remove this once {Set,Clear}AllocationFilterFlag are implemented.
#define ASAN_RTL_FUNCTIONS(F)                                                  \
  F(WINAPI, HANDLE, GetProcessHeap, (), ())                                    \
  F(WINAPI, HANDLE, HeapCreate,                                                \
    (DWORD options, SIZE_T initial_size, SIZE_T maximum_size),                 \
    (options, initial_size, maximum_size))                                     \
  F(WINAPI, BOOL, HeapDestroy, (HANDLE heap), (heap))                          \
  F(WINAPI, LPVOID, HeapAlloc, (HANDLE heap, DWORD flags, SIZE_T bytes),       \
    (heap, flags, bytes))                                                      \
  F(WINAPI, LPVOID, HeapReAlloc,                                               \
    (HANDLE heap, DWORD flags, LPVOID mem, SIZE_T bytes),                      \
    (heap, flags, mem, bytes))                                                 \
  F(WINAPI, BOOL, HeapFree, (HANDLE heap, DWORD flags, LPVOID mem),            \
    (heap, flags, mem))                                                        \
  F(WINAPI, SIZE_T, HeapSize, (HANDLE heap, DWORD flags, LPCVOID mem),         \
    (heap, flags, mem))                                                        \
  F(WINAPI, BOOL, HeapValidate, (HANDLE heap, DWORD flags, LPCVOID mem),       \
    (heap, flags, mem))                                                        \
  F(WINAPI, SIZE_T, HeapCompact, (HANDLE heap, DWORD flags), (heap, flags))    \
  F(WINAPI, BOOL, HeapLock, (HANDLE heap), (heap))                             \
  F(WINAPI, BOOL, HeapUnlock, (HANDLE heap), (heap))                           \
  F(WINAPI, BOOL, HeapWalk, (HANDLE heap, LPPROCESS_HEAP_ENTRY entry),         \
    (heap, entry))                                                             \
  F(WINAPI, BOOL, HeapSetInformation,                                          \
    (HANDLE heap, HEAP_INFORMATION_CLASS info_class, PVOID info,               \
     SIZE_T info_length),                                                      \
    (heap, info_class, info, info_length))                                     \
  F(WINAPI, BOOL, HeapQueryInformation,                                        \
    (HANDLE heap, HEAP_INFORMATION_CLASS info_class, PVOID info,               \
     SIZE_T info_length, PSIZE_T return_length),                               \
    (heap, info_class, info, info_length, return_length))                      \
  F(WINAPI, void, SetCallBack, (void (*callback)(AsanErrorInfo * error_info)), \
    (callback))                                                                \
  F(_cdecl, void*, memcpy,                                                     \
    (void* destination, const void* source, size_t num),                       \
    (destination, source, num))                                                \
  F(_cdecl, void*, memmove,                                                    \
    (void* destination, const void* source, size_t num),                       \
    (destination, source, num))                                                \
  F(_cdecl, void*, memset, (void* ptr, int value, size_t num),                 \
    (ptr, value, num))                                                         \
  F(_cdecl, const void*, memchr, (const void* ptr, int value, size_t num),     \
    (ptr, value, num))                                                         \
  F(_cdecl, size_t, strcspn, (const char* str1, const char* str2),             \
    (str1, str2))                                                              \
  F(_cdecl, size_t, strlen, (const char* str), (str))                          \
  F(_cdecl, size_t, strnlen, (const char* str, size_t max_len),                \
    (str, max_len))                                                            \
  F(_cdecl, const char*, strrchr, (const char* str, int character),            \
    (str, character))                                                          \
  F(_cdecl, const wchar_t*, wcsrchr, (const wchar_t* str, int character),      \
    (str, character))                                                          \
  F(_cdecl, const wchar_t*, wcschr, (const wchar_t* str, int character),       \
    (str, character))                                                          \
  F(_cdecl, int, strcmp, (const char* str1, const char* str2), (str1, str2))   \
  F(_cdecl, const char*, strpbrk, (const char* str1, const char* str2),        \
    (str1, str2))                                                              \
  F(_cdecl, const char*, strstr, (const char* str1, const char* str2),         \
    (str1, str2))                                                              \
  F(_cdecl, size_t, wcsnlen, (const wchar_t* str, size_t max_len),             \
    (str, max_len))                                                            \
  F(_cdecl, const wchar_t*, wcsstr,                                            \
    (const wchar_t* str1, const wchar_t* str2), (str1, str2))                  \
  F(_cdecl, size_t, strspn, (const char* str1, const char* str2),              \
    (str1, str2))                                                              \
  F(_cdecl, char*, strncpy,                                                    \
    (char* destination, const char* source, size_t num),                       \
    (destination, source, num))                                                \
  F(_cdecl, char*, strncat,                                                    \
    (char* destination, const char* source, size_t num),                       \
    (destination, source, num))                                                \
  F(WINAPI, BOOL, ReadFile,                                                    \
    (HANDLE file_handle, LPVOID buffer, DWORD bytes_to_read,                   \
     LPDWORD bytes_read, LPOVERLAPPED overlapped),                             \
    (file_handle, buffer, bytes_to_read, bytes_read, overlapped))              \
  F(WINAPI, BOOL, WriteFile,                                                   \
    (HANDLE file_handle, LPCVOID buffer, DWORD bytes_to_write,                 \
     LPDWORD bytes_written, LPOVERLAPPED overlapped),                          \
    (file_handle, buffer, bytes_to_write, bytes_written, overlapped))          \
  F(_cdecl, void, SetInterceptorCallback, (void (*callback)()), (callback))    \
  F(WINAPI, agent::asan::AsanRuntime*, GetActiveRuntime, (), ())               \
  F(WINAPI, void, InitializeCrashReporter, (), ())
#endif

// Declare pointer types for the intercepted functions.
#define DECLARE_ASAN_FUNCTION_PTR(convention, ret, name, args, argnames) \
  typedef ret (convention* name##FunctionPtr)args;
ASAN_RTL_FUNCTIONS(DECLARE_ASAN_FUNCTION_PTR)
#undef DECLARE_ASAN_FUNCTION_PTR

class TestAsanRtl : public testing::TestWithAsanLogger {
 public:
  TestAsanRtl() : asan_rtl_(NULL), heap_(NULL) {
  }

  void SetUp() override {
    testing::TestWithAsanLogger::SetUp();

    // Load the Asan runtime library.
    base::FilePath asan_rtl_path =
        testing::GetExeRelativePath(L"syzyasan_rtl.dll");
    asan_rtl_ = ::LoadLibrary(asan_rtl_path.value().c_str());
    ASSERT_TRUE(asan_rtl_ != NULL);

    // Load all the functions and assert that we find them.
#define LOAD_ASAN_FUNCTION(convention, ret, name, args, argnames)  \
    name##Function = reinterpret_cast<name##FunctionPtr>(  \
        ::GetProcAddress(asan_rtl_, "asan_" #name));  \
    ASSERT_TRUE(name##Function != NULL);

    ASAN_RTL_FUNCTIONS(LOAD_ASAN_FUNCTION)

#undef LOAD_ASAN_FUNCTION

    heap_ = HeapCreateFunction(0, 0, 0);
    ASSERT_TRUE(heap_ != NULL);

    agent::asan::AsanRuntime* runtime = GetActiveRuntimeFunction();
    ASSERT_NE(reinterpret_cast<agent::asan::AsanRuntime*>(NULL), runtime);
    // Disable the heap checking as this really slows down the unittests.
    runtime->params().check_heap_on_failure = false;
  }

  void TearDown() override {
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

  // Declare pointers to intercepted functions.
#define DECLARE_FUNCTION_PTR_VARIABLE(convention, ret, name, args, argnames)  \
    static name##FunctionPtr name##Function;
  ASAN_RTL_FUNCTIONS(DECLARE_FUNCTION_PTR_VARIABLE)
#undef DECLARE_FUNCTION_PTR_VARIABLE

  // Define versions of all of the functions that expect an error to be thrown
  // by the AsanErrorCallback, and in turn raise an exception if the underlying
  // function didn't fail.
#define DECLARE_FAILING_FUNCTION(convention, ret, name, args, argnames)  \
    static void name##FunctionFailing args;
  ASAN_RTL_FUNCTIONS(DECLARE_FAILING_FUNCTION)
#undef DECLARE_FAILING_FUNCTION

 protected:
  // The AsanAsan runtime module to test.
  HMODULE asan_rtl_;

  // Scratch heap handle valid from SetUp to TearDown.
  HANDLE heap_;
};

// A helper struct to be passed as a destructor of Asan scoped allocation.
struct AsanDeleteHelper {
  explicit AsanDeleteHelper(TestAsanRtl* asan_rtl)
      : asan_rtl_(asan_rtl) {
  }

  void operator()(void* ptr) {
    asan_rtl_->HeapFreeFunction(asan_rtl_->heap(), 0, ptr);
  }
  TestAsanRtl* asan_rtl_;
};

// A std::unique_ptr specialization for the Asan allocations.
template <typename T>
class ScopedAsanAlloc : public std::unique_ptr<T, AsanDeleteHelper> {
 public:
  explicit ScopedAsanAlloc(TestAsanRtl* asan_rtl)
      : std::unique_ptr<T, AsanDeleteHelper>(NULL, AsanDeleteHelper(asan_rtl)) {
  }

  ScopedAsanAlloc(TestAsanRtl* asan_rtl, size_t size)
      : std::unique_ptr<T, AsanDeleteHelper>(NULL, AsanDeleteHelper(asan_rtl)) {
    Allocate(asan_rtl, size);
  }

  ScopedAsanAlloc(TestAsanRtl* asan_rtl, size_t size, const T* value)
      : std::unique_ptr<T, AsanDeleteHelper>(NULL, AsanDeleteHelper(asan_rtl)) {
    Allocate(asan_rtl, size);
    ::memcpy(get(), value, size * sizeof(T));
  }

  template <typename T2>
  T2* GetAs() {
    return reinterpret_cast<T2*>(get());
  }

  void Allocate(TestAsanRtl* asan_rtl, size_t size) {
    ASSERT_TRUE(asan_rtl != NULL);
    reset(reinterpret_cast<T*>(
        asan_rtl->HeapAllocFunction(asan_rtl->heap(), 0, size * sizeof(T))));
    ::memset(get(), 0, size * sizeof(T));
  }

  T operator[](size_t i) const {
    CHECK(get() != NULL);
    return get()[i];
  }

  T& operator[](size_t i) {
    CHECK(get() != NULL);
    return get()[i];
  }
};

// A unittest fixture that initializes an Asan runtime instance.
class TestWithAsanRuntime : public OnExceptionCallbackTest {
 public:
  TestWithAsanRuntime() {
    runtime_ = new agent::asan::AsanRuntime();
    owns_runtime_ = true;
  }

  explicit TestWithAsanRuntime(agent::asan::AsanRuntime* runtime)
      : runtime_(runtime), owns_runtime_(false) {
    CHECK_NE(reinterpret_cast<agent::asan::AsanRuntime*>(NULL), runtime_);
  }

  ~TestWithAsanRuntime() {
    CHECK_NE(reinterpret_cast<agent::asan::AsanRuntime*>(NULL), runtime_);
    if (owns_runtime_)
      delete runtime_;
    runtime_ = NULL;
  }

  void SetUp() override {
    CHECK_NE(reinterpret_cast<agent::asan::AsanRuntime*>(NULL), runtime_);
    testing::Test::SetUp();
    runtime_->SetUp(L"");
  }

  void TearDown() override {
    CHECK_NE(reinterpret_cast<agent::asan::AsanRuntime*>(NULL), runtime_);
    runtime_->TearDown();
    testing::Test::TearDown();
  }

 protected:
  // The runtime instance used by the tests.
  agent::asan::AsanRuntime* runtime_;

  // Indicates if we own the runtime instance.
  bool owns_runtime_;
};

// A unittest fixture to test the bookkeeping functions.
struct FakeAsanBlock {
  static const size_t kMaxAlignmentLog = 13;
  static const size_t kMaxAlignment = 1 << kMaxAlignmentLog;
  // If we want to test the alignments up to 4096 we need a buffer of at least
  // 3 * 4096 bytes:
  // +--- 0 <= size < 4096 bytes---+---4096 bytes---+--4096 bytes--+
  // ^buffer                       ^aligned_buffer  ^user_pointer
  static const size_t kBufferSize = 3 * kMaxAlignment;
  static const uint8_t kBufferHeaderValue = 0xAE;
  static const uint8_t kBufferTrailerValue = 0xEA;

  FakeAsanBlock(Shadow* shadow,
                uint32_t alloc_alignment_log,
                StackCaptureCache* stack_cache);

  ~FakeAsanBlock();

  // Initialize an Asan block in the buffer.
  // @param alloc_size The user size of the Asan block.
  // @returns true on success, false otherwise.
  bool InitializeBlock(uint32_t alloc_size);

  // Ensures that this block has a valid block header.
  bool TestBlockMetadata();

  // Mark the current Asan block as quarantined.
  bool MarkBlockAsQuarantinedImpl(bool flood_filled);

  // Mark the current Asan block as quarantined.
  bool MarkBlockAsQuarantined();

  // Mark the current Asan block as quarantined and flooded.
  bool MarkBlockAsQuarantinedFlooded();

  // The buffer we use internally.
  uint8_t buffer[kBufferSize];

  // The information about the block once it has been initialized.
  agent::asan::BlockInfo block_info;

  // The alignment of the current allocation.
  uint32_t alloc_alignment;
  uint32_t alloc_alignment_log;

  // The sizes of the different sub-structures in the buffer.
  size_t buffer_header_size;
  size_t buffer_trailer_size;

  // The pointers to the different sub-structures in the buffer.
  uint8_t* buffer_align_begin;

  // Indicate if the buffer has been initialized.
  bool is_initialized;

  // The shadow memory that will be modified.
  Shadow* shadow_;

  // The cache that will store the stack traces of this block.
  StackCaptureCache* stack_cache;
};

// A mock memory notifier. Useful when testing objects that have a memory
// notifier dependency.
class MockMemoryNotifier : public agent::asan::MemoryNotifierInterface {
 public:
  // Constructor.
  MockMemoryNotifier() { }

  // Virtual destructor.
  virtual ~MockMemoryNotifier() { }

  // @name MemoryNotifierInterface implementation.
  // @{
  MOCK_METHOD2(NotifyInternalUse, void(const void*, size_t));
  MOCK_METHOD2(NotifyFutureHeapUse, void(const void*, size_t));
  MOCK_METHOD2(NotifyReturnedToOS, void(const void*, size_t));
  // @}

 private:
  DISALLOW_COPY_AND_ASSIGN(MockMemoryNotifier);
};

// A mock HeapInterface.
class LenientMockHeap : public agent::asan::HeapInterface {
 public:
  LenientMockHeap() { }
  virtual ~LenientMockHeap() { }
  MOCK_CONST_METHOD0(GetHeapType, agent::asan::HeapType());
  MOCK_CONST_METHOD0(GetHeapFeatures, uint32_t());
  MOCK_METHOD1(Allocate, void*(uint32_t));
  MOCK_METHOD1(Free, bool(void*));
  MOCK_METHOD1(IsAllocated, bool(const void*));
  MOCK_METHOD1(GetAllocationSize, uint32_t(const void*));
  MOCK_METHOD0(Lock, void());
  MOCK_METHOD0(Unlock, void());
  MOCK_METHOD0(TryLock, bool());
};
typedef testing::StrictMock<LenientMockHeap> MockHeap;

typedef std::vector<agent::asan::AsanBlockInfo> AsanBlockInfoVector;
typedef std::pair<agent::asan::AsanCorruptBlockRange, AsanBlockInfoVector>
    CorruptRangeInfo;
typedef std::vector<CorruptRangeInfo> CorruptRangeVector;

// A helper for testing the memory accessor instrumentation functions.
//
// This is an abstract class that should be overridden for each types
// of probes (with a different calling convention).
class MemoryAccessorTester {
 public:
  typedef agent::asan::BadAccessKind BadAccessKind;

  MemoryAccessorTester();
  virtual ~MemoryAccessorTester();

  // Call |access_fn| to test an access on |ptr| and make sure that an invalid
  // access of type |bad_access_kind| is detected.
  virtual void AssertMemoryErrorIsDetected(FARPROC access_fn,
                                           void* ptr,
                                           BadAccessKind bad_access_type) = 0;

  // The callback used to report the errors.
  static void AsanErrorCallback(AsanErrorInfo* error_info);

  void set_expected_error_type(BadAccessKind expected) {
    expected_error_type_ = expected;
  }
  bool memory_error_detected() const { return memory_error_detected_; }
  void set_memory_error_detected(bool memory_error_detected) {
    memory_error_detected_ = memory_error_detected;
  }

  const AsanErrorInfo& last_error_info() const { return last_error_info_; }
  const CorruptRangeVector& last_corrupt_ranges() const {
    return last_corrupt_ranges_;
  }

 protected:
  virtual void Initialize();
  void AsanErrorCallbackImpl(AsanErrorInfo* error_info);

  // This will be used in the asan callback to ensure that we detect the right
  // error.
  BadAccessKind expected_error_type_;
  // A flag used in asan callback to ensure that a memory error has been
  // detected.
  bool memory_error_detected_;

  // Context captured on error.
  CONTEXT error_context_;

  // The information about the last error.
  AsanErrorInfo last_error_info_;
  CorruptRangeVector last_corrupt_ranges_;

  // Prevent from instantiating several instances of this class at the same
  // time as the instance gets used as a callback by the runtime.
  static MemoryAccessorTester* instance_;
};

#ifndef _WIN64
// Specialization of a |MemoryAccessorTester| for the probes with the SyzyAsan
// custom calling convention.
class SyzyAsanMemoryAccessorTester : public MemoryAccessorTester {
 public:
  enum IgnoreFlags {
    IGNORE_FLAGS
  };

  SyzyAsanMemoryAccessorTester();
  explicit SyzyAsanMemoryAccessorTester(IgnoreFlags ignore_flags);
  virtual ~SyzyAsanMemoryAccessorTester() {}

  // Checks that @p access_fn doesn't raise exceptions on access checking
  // @p ptr, and that @p access_fn doesn't modify any registers or flags
  // when executed.
  void CheckAccessAndCompareContexts(FARPROC access_fn, void* ptr);

  // Checks that @p access_fn generates @p bad_access_type on checking @p ptr.
  void AssertMemoryErrorIsDetected(FARPROC access_fn,
                                   void* ptr,
                                   BadAccessKind bad_access_type) override;

  enum StringOperationDirection {
    DIRECTION_FORWARD,
    DIRECTION_BACKWARD
  };

  // Checks that @p access_fn doesn't raise exceptions on access checking
  // for a given @p direction, @p src, @p dst and @p len.
  void CheckSpecialAccessAndCompareContexts(
      FARPROC access_fn, StringOperationDirection direction,
      void* dst, void* src, int len);

  // Checks that @p access_fn generates @p bad_access_type on access checking
  // for a given @p direction, @p src, @p dst and @p len.
  void ExpectSpecialMemoryErrorIsDetected(FARPROC access_fn,
                                          StringOperationDirection direction,
                                          bool expect_error,
                                          void* dst,
                                          void* src,
                                          int32_t length,
                                          BadAccessKind bad_access_type);

 protected:
  void Initialize() override;

  // Indicates whether to ignore changes to the flags register.
  bool ignore_flags_;

  // The pre- and post-invocation contexts.
  CONTEXT context_before_hook_;
  CONTEXT context_after_hook_;
};
#endif

// Specialization of a |MemoryAccessorTester| for the probes with the Clang
// calling convention (cdecl).
class ClangMemoryAccessorTester : public MemoryAccessorTester {
 public:
  ClangMemoryAccessorTester() {}
  virtual ~ClangMemoryAccessorTester() {}

  void AssertMemoryErrorIsDetected(FARPROC access_fn,
                                   void* ptr,
                                   BadAccessKind bad_access_type) override;

  void CheckAccess(FARPROC access_fn, void* ptr);
};

// A fixture class for testing memory interceptors.
class TestMemoryInterceptors : public TestWithAsanLogger {
 public:
  // Redefine some enums for local use.
  enum AccessMode {
    AsanReadAccess = agent::asan::ASAN_READ_ACCESS,
    AsanWriteAccess = agent::asan::ASAN_WRITE_ACCESS,
    AsanUnknownAccess = agent::asan::ASAN_UNKNOWN_ACCESS,
  };

  struct InterceptFunction {
    void(*function)();
    size_t size;
  };

  struct ClangInterceptFunction {
    void (*function)(const void*);
    size_t size;
  };

  struct StringInterceptFunction {
    void(*function)();
    size_t size;
    AccessMode dst_access_mode;
    AccessMode src_access_mode;
    bool uses_counter;
  };

  static const bool kCounterInit_ecx = true;
  static const bool kCounterInit_1 = false;

  TestMemoryInterceptors();
  void SetUp() override;
  void TearDown() override;

#ifndef _WIN64
  template <size_t N>
  void TestValidAccess(const InterceptFunction(&fns)[N]) {
    TestValidAccess(fns, N);
  }
  template <size_t N>
  void TestOverrunAccess(const InterceptFunction(&fns)[N]) {
    TestOverrunAccess(fns, N);
  }
  template <size_t N>
  void TestUnderrunAccess(const InterceptFunction(&fns)[N]) {
    TestUnderrunAccess(fns, N);
  }
  template <size_t N>
  void TestValidAccessIgnoreFlags(const InterceptFunction (&fns)[N]) {
    TestValidAccessIgnoreFlags(fns, N);
  }
  template <size_t N>
  void TestOverrunAccessIgnoreFlags(const InterceptFunction (&fns)[N]) {
    TestOverrunAccessIgnoreFlags(fns, N);
  }
  template <size_t N>
  void TestUnderrunAccessIgnoreFlags(const InterceptFunction (&fns)[N]) {
    TestUnderrunAccessIgnoreFlags(fns, N);
  }
  template <size_t N>
  void TestStringValidAccess(const StringInterceptFunction (&fns)[N]) {
    TestStringValidAccess(fns, N);
  }
  template <size_t N>
  void TestStringOverrunAccess(const StringInterceptFunction (&fns)[N]) {
    TestStringOverrunAccess(fns, N);
  }
#endif
  template <size_t N>
  void TestValidAccess(const ClangInterceptFunction(&fns)[N]) {
    TestClangValidAccess(fns, N);
  }
  template <size_t N>
  void TestOverrunAccess(const ClangInterceptFunction(&fns)[N]) {
    TestClangOverrunAccess(fns, N);
  }
  template <size_t N>
  void TestUnderrunAccess(const ClangInterceptFunction(&fns)[N]) {
    TestClangUnderrunAccess(fns, N);
  }

 protected:
#ifndef _WIN64
  void TestValidAccess(const InterceptFunction* fns, size_t num_fns);
  void TestValidAccessIgnoreFlags(const InterceptFunction* fns,
                                  size_t num_fns);
  void TestOverrunAccess(const InterceptFunction* fns, size_t num_fns);
  void TestOverrunAccessIgnoreFlags(const InterceptFunction* fns,
                                    size_t num_fns);
  void TestUnderrunAccess(const InterceptFunction* fns, size_t num_fns);
  void TestUnderrunAccessIgnoreFlags(const InterceptFunction* fns,
                                     size_t num_fns);
  void TestStringValidAccess(
      const StringInterceptFunction* fns, size_t num_fns);
  void TestStringOverrunAccess(
      const StringInterceptFunction* fns, size_t num_fns);
#endif
  void TestClangValidAccess(const ClangInterceptFunction* fns, size_t num_fns);
  void TestClangOverrunAccess(const ClangInterceptFunction* fns,
                              size_t num_fns);
  void TestClangUnderrunAccess(const ClangInterceptFunction* fns,
                               size_t num_fns);

  const size_t kAllocSize = 64;

  agent::asan::AsanRuntime asan_runtime_;
  HANDLE heap_;

  // Convenience allocs of kAllocSize. Valid from SetUp to TearDown.
  byte* src_;
  byte* dst_;
};

// A very lightweight dummy heap to be used in stress testing the
// HeapAllocator. Lock and Unlock are noops, so this is not thread
// safe.
class DummyHeap : public agent::asan::HeapInterface {
 public:
  ~DummyHeap() override { }
  agent::asan::HeapType GetHeapType() const override {
    return agent::asan::kUnknownHeapType;
  }
  uint32_t GetHeapFeatures() const override { return 0; }
  void* Allocate(uint32_t bytes) override { return ::malloc(bytes); }
  bool Free(void* alloc) override { ::free(alloc); return true; }
  bool IsAllocated(const void* alloc) override { return false; }
  uint32_t GetAllocationSize(const void* alloc) override { return 0; }
  void Lock() override { return; }
  void Unlock() override { return; }
  bool TryLock() override { return true; }
};

// Test read and write access.
// Use carefully, since it will try to overwrite the value at @p address with 0.
// @returns true if the address is readable and writable, false otherwise.
bool IsAccessible(void* address);

// Test read and write access.
// Use carefully, since it will try to overwrite the value at @p address with 0.
// @returns true if the address is neither readable nor writable,
//     false otherwise.
bool IsNotAccessible(void* address);

// A scoped block access helper. Removes block protections when created via
// BlockProtectNone, and restores them via BlockProtectAuto.
// TODO(chrisha): Consider recording the fact the block protections on this
//     block are being blocked in some synchronous manner. This will prevent
//     the page protections from being added during the lifetime of this
//     object.
class ScopedBlockAccess {
 public:
  // Constructor. Unprotects the provided block.
  // @param block_info The block whose protections are to be modified.
  // @parma shadow The shadow memory to be updated.
  explicit ScopedBlockAccess(const agent::asan::BlockInfo& block_info,
                             Shadow* shadow)
      : block_info_(block_info), shadow_(shadow) {
    BlockProtectNone(block_info_, shadow_);
  }

  // Destructor. Restores protections on the provided block.
  ~ScopedBlockAccess() { BlockProtectAuto(block_info_, shadow_); }

 private:
  const agent::asan::BlockInfo& block_info_;
  Shadow* shadow_;
};

// A debugging shadow class. This keeps extra details in the form of an address
// space with stack traces. This makes it much easier to track down
// inconsistencies in the shadow memory.
class DebugShadow : public Shadow {
 public:
  using ShadowMarker = agent::asan::ShadowMarker;

  DebugShadow() : Shadow() {
  }

  explicit DebugShadow(size_t length)
      : Shadow(length) {
  }

  ~DebugShadow() override {
    // If the shadow has been properly used it will be completely empty by the
    // time it is torn down.
    CHECK(shadow_address_space_.empty());
  }

 protected:
  // @name Shadow implementation.
  // @{
  void SetShadowMemory(
      const void* address, size_t length, ShadowMarker marker) override;
  void GetPointerAndSizeImpl(void const** self, size_t* size) const override;
  // @}

 private:
  using StackCapture = agent::common::StackCapture;

  // Holds details about a given range of shadow memory. Persists the
  // original size of a region, even if it is subsequently fragmented.
  struct Metadata {
    const void* address;
    size_t size;
    ShadowMarker marker;
    StackCapture stack_capture;

    // Explicitly enable copy and assignment.
    Metadata();
    Metadata(const void* address, size_t size, ShadowMarker marker);
    Metadata(const Metadata& rhs);
    Metadata& operator=(const Metadata& rhs);
  };
  using ShadowAddressSpace =
      core::AddressSpace<uintptr_t, size_t, Metadata>;
  using Range = ShadowAddressSpace::Range;

  // Ensure that the given range has been cleared from the address-space,
  // readying it for a subsequent insertion.
  void ClearIntersection(const void* addr, size_t size);

  // An alternative view of shadow memory. Accessible regions are not
  // displayed. Neighboring regions of the same type are merged.
  ShadowAddressSpace shadow_address_space_;
};

}  // namespace testing

#endif  // SYZYGY_AGENT_ASAN_UNITTEST_UTIL_H_
