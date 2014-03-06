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

#include "base/file_util.h"
#include "base/string_piece.h"
#include "base/files/scoped_temp_dir.h"
#include "gtest/gtest.h"
#include "syzygy/agent/asan/asan_heap.h"
#include "syzygy/agent/asan/asan_runtime.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/trace/agent_logger/agent_logger.h"
#include "syzygy/trace/agent_logger/agent_logger_rpc_impl.h"

namespace testing {

using agent::asan::AsanErrorInfo;

// The default name of the runtime library DLL.
extern const wchar_t kSyzyAsanRtlDll[];

// A unittest fixture that ensures that an ASAN logger instance is up and
// running for the duration of the test. Output is captured to a file so that
// its contents can be read after the test if necessary.
class TestWithAsanLogger : public testing::Test {
 public:
  TestWithAsanLogger();

  // @name testing::Test overrides.
  // @{
  void SetUp() OVERRIDE;
  void TearDown() OVERRIDE;
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

  // Reset the log contents.
  void ResetLog();

 private:
  // The log service instance.
  trace::agent_logger::AgentLogger log_service_;

  // Manages the binding between the RPC stub functions and a log service
  // instance.
  trace::agent_logger::RpcLoggerInstanceManager log_service_instance_;

  // The instance ID used by the running logger instance.
  std::wstring instance_id_;

  // The path to the log file where the the logger instance will write.
  base::FilePath log_file_path_;

  // The open file handle, if any to which the logger instance will write.
  file_util::ScopedFILE log_file_;

  // A temporary directory into which the log file will be written.
  base::ScopedTempDir temp_dir_;

  // The contents of the log. These are read by calling LogContains.
  bool log_contents_read_;
  std::string log_contents_;
};

// Shorthand for discussing all the asan runtime functions.
#define ASAN_RTL_FUNCTIONS(F)  \
    F(WINAPI, HANDLE, GetProcessHeap, ())  \
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
    F(_cdecl, const wchar_t*, wcsrchr, (const wchar_t* str, int character))  \
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
    F(WINAPI, BOOL, ReadFile,  \
      (HANDLE file_handle, LPVOID buffer, DWORD bytes_to_read,  \
       LPDWORD bytes_read, LPOVERLAPPED overlapped))  \
    F(WINAPI, BOOL, WriteFile,  \
      (HANDLE file_handle, LPCVOID buffer, DWORD bytes_to_write,  \
       LPDWORD bytes_written, LPOVERLAPPED overlapped))  \
    F(_cdecl, void, SetInterceptorCallback, (void (*callback)()))

#define DECLARE_ASAN_FUNCTION_PTR(convention, ret, name, args) \
  typedef ret (convention* name##FunctionPtr)args;

ASAN_RTL_FUNCTIONS(DECLARE_ASAN_FUNCTION_PTR)

#undef DECLARE_ASAN_FUNCTION_PTR

class TestAsanRtl : public testing::TestWithAsanLogger {
 public:
  TestAsanRtl() : asan_rtl_(NULL), heap_(NULL) {
  }

  void SetUp() OVERRIDE {
    testing::TestWithAsanLogger::SetUp();

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
    static name##FunctionPtr TestAsanRtl::name##Function;

  ASAN_RTL_FUNCTIONS(DECLARE_FUNCTION_PTR_VARIABLE)

#undef DECLARE_FUNCTION_PTR_VARIABLE

 protected:
  // The ASAN runtime module to test.
  HMODULE asan_rtl_;

  // Scratch heap handle valid from SetUp to TearDown.
  HANDLE heap_;
};

// A helper struct to be passed as a destructor of ASan scoped allocation.
struct ASanDeleteHelper {
  explicit ASanDeleteHelper(TestAsanRtl* asan_rtl)
      : asan_rtl_(asan_rtl) {
  }

  void operator()(void* ptr) {
    asan_rtl_->HeapFreeFunction(asan_rtl_->heap(), 0, ptr);
  }
  TestAsanRtl* asan_rtl_;
};

// A scoped_ptr specialization for the ASan allocations.
template <typename T>
class ScopedASanAlloc : public scoped_ptr<T, ASanDeleteHelper> {
 public:
  explicit ScopedASanAlloc(TestAsanRtl* asan_rtl)
      : scoped_ptr(NULL, ASanDeleteHelper(asan_rtl)) {
  }

  ScopedASanAlloc(TestAsanRtl* asan_rtl, size_t size)
      : scoped_ptr(NULL, ASanDeleteHelper(asan_rtl)) {
    Allocate(asan_rtl, size);
  }

  ScopedASanAlloc(TestAsanRtl* asan_rtl, size_t size, const T* value)
      : scoped_ptr(NULL, ASanDeleteHelper(asan_rtl)) {
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

  T operator[](int i) const {
    CHECK(get() != NULL);
    return get()[i];
  }

  T& operator[](int i) {
    CHECK(get() != NULL);
    return get()[i];
  }
};

}  // namespace testing

#endif  // SYZYGY_AGENT_ASAN_UNITTEST_UTIL_H_
