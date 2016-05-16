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
//
// Memory Profiler unittests.

#include "syzygy/agent/memprof/memprof.h"

#include <windows.h>

#include "base/scoped_native_library.h"
#include "base/files/file_enumerator.h"
#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/message_loop/message_loop.h"
#include "base/threading/platform_thread.h"
#include "base/threading/thread.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/common/process_utils.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/unittest_util.h"
#include "syzygy/trace/common/unittest_util.h"
#include "syzygy/trace/parse/parser.h"
#include "syzygy/trace/parse/unittest_util.h"
#include "syzygy/trace/protocol/call_trace_defs.h"
#include "syzygy/trace/service/service.h"
#include "syzygy/trace/service/service_rpc_impl.h"

namespace agent {
namespace memprof {

namespace {

using ::common::GetCurrentProcessModules;
using ::common::ModuleVector;
using testing::_;
using testing::AllOf;
using testing::Return;
using testing::StrictMockParseEventHandler;
using trace::service::RpcServiceInstanceManager;
using trace::service::Service;
using trace::parser::Parser;
using trace::parser::ParseEventHandler;

// Function pointers for various Heap API functions.
typedef HANDLE (WINAPI *HeapCreatePtr)(DWORD, SIZE_T, SIZE_T);
typedef BOOL (WINAPI *HeapDestroyPtr)(HANDLE);
typedef LPVOID (WINAPI *HeapAllocPtr)(HANDLE, DWORD, SIZE_T);
typedef BOOL (WINAPI *HeapFreePtr)(HANDLE, DWORD, LPVOID);

class MemoryProfilerTest : public testing::Test {
 public:
  MemoryProfilerTest()
      : module_(nullptr),
        heap_create_(nullptr),
        heap_destroy_(nullptr),
        heap_alloc_(nullptr),
        heap_free_(nullptr) {
  }

  virtual void SetUp() override {
    testing::Test::SetUp();

    // Create a temporary directory for the call trace files.
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());

    service_.SetEnvironment();
  }

  virtual void TearDown() override {
    UnloadDll();

    // Stop the call trace service.
    service_.Stop();
  }

  void StartService() {
    service_.Start(temp_dir_.path());
  }

  void StopService() {
    service_.Stop();
  }

  void ReplayLogs() {
    // Stop the service if it's running.
    ASSERT_NO_FATAL_FAILURE(StopService());

    Parser parser;
    ASSERT_TRUE(parser.Init(&handler_));

    // Queue up the trace file(s) we engendered.
    base::FileEnumerator enumerator(temp_dir_.path(),
                                    false,
                                    base::FileEnumerator::FILES);
    size_t num_files = 0;
    while (true) {
      base::FilePath trace_file = enumerator.Next();
      if (trace_file.empty())
        break;
      ASSERT_TRUE(parser.OpenTraceFile(trace_file));
      ++num_files;
    }
    EXPECT_GT(num_files, 0U);
    ASSERT_TRUE(parser.Consume());
  }

  void LoadDll() {
    ASSERT_TRUE(module_ == NULL);
    static const wchar_t kClientDll[] = L"memprof.dll";
    ASSERT_EQ(NULL, ::GetModuleHandle(kClientDll));
    module_ = ::LoadLibrary(kClientDll);
    ASSERT_TRUE(module_ != nullptr);

    heap_create_ = reinterpret_cast<HeapCreatePtr>(
        ::GetProcAddress(module_, "asan_HeapCreate"));
    ASSERT_TRUE(heap_create_ != nullptr);
    heap_destroy_ = reinterpret_cast<HeapDestroyPtr>(
        ::GetProcAddress(module_, "asan_HeapDestroy"));
    ASSERT_TRUE(heap_destroy_ != nullptr);
    heap_alloc_ = reinterpret_cast<HeapAllocPtr>(
        ::GetProcAddress(module_, "asan_HeapAlloc"));
    ASSERT_TRUE(heap_alloc_ != nullptr);
    heap_free_ = reinterpret_cast<HeapFreePtr>(
        ::GetProcAddress(module_, "asan_HeapFree"));
    ASSERT_TRUE(heap_free_ != nullptr);
  }

  void UnloadDll() {
    if (module_ != NULL) {
      ASSERT_TRUE(::FreeLibrary(module_));
      module_ = nullptr;
      heap_create_ = nullptr;
      heap_destroy_ = nullptr;
      heap_alloc_ = nullptr;
      heap_free_ = nullptr;
    }
  }

  void ExpectedRecordsSeenTest(bool emit_stack_traces) {
    std::unique_ptr<base::Environment> env(base::Environment::Create());
    DCHECK_NE(static_cast<base::Environment*>(nullptr), env.get());
    if (emit_stack_traces) {
      env->SetVar(kParametersEnvVar,
                  "--stack-trace-tracking=emit --serialize-timestamps");
    } else {
      env->SetVar(kParametersEnvVar, "--stack-trace-tracking=none");
    }

    ASSERT_NO_FATAL_FAILURE(StartService());
    ASSERT_NO_FATAL_FAILURE(LoadDll());

    DWORD process_id = ::GetCurrentProcessId();
    DWORD thread_id = ::GetCurrentThreadId();

    // Make some calls to the instrumented heap API.
    HANDLE heap = (*heap_create_)(0, 0, 0);
    ASSERT_TRUE(heap != nullptr);
    void* alloc = (*heap_alloc_)(heap, 0, 1024);
    ASSERT_TRUE(alloc != nullptr);
    (*heap_free_)(heap, 0, alloc);
    // Deliberately keep around the value of |alloc| for checking expectation,
    // even though the memory it points to is no longer valid.
    (*heap_destroy_)(heap);
    // Ditto for the value of |heap|.

    ASSERT_NO_FATAL_FAILURE(UnloadDll());
    ASSERT_NO_FATAL_FAILURE(StopService());

    env->UnSetVar(kParametersEnvVar);

    EXPECT_CALL(handler_, OnProcessStarted(_, process_id, _));
    EXPECT_CALL(handler_, OnProcessAttach(_, process_id, _, _))
        .Times(testing::AnyNumber());
    EXPECT_CALL(handler_, OnProcessHeap(_, process_id, _))
        .Times(testing::AnyNumber());

    EXPECT_CALL(handler_,
                OnFunctionNameTableEntry(_, process_id, _)).Times(4);
    EXPECT_CALL(handler_,
                OnDetailedFunctionCall(_, process_id, thread_id, _)).Times(4);

    if (emit_stack_traces) {
      EXPECT_CALL(handler_,
                  OnStackTrace(_, process_id, _)).Times(4);
    }

    EXPECT_CALL(handler_, OnProcessEnded(_, process_id));

    // Replay the log.
    ASSERT_NO_FATAL_FAILURE(ReplayLogs());
  }

 protected:
  // The directory where trace file output will be written.
  base::ScopedTempDir temp_dir_;

  // The handler to which the trace file parser will delegate events.
  StrictMockParseEventHandler handler_;

  // Functions exported from the memory profiler client dll.
  HeapCreatePtr heap_create_;
  HeapDestroyPtr heap_destroy_;
  HeapAllocPtr heap_alloc_;
  HeapFreePtr heap_free_;

  // Our call trace service process instance.
  testing::CallTraceService service_;

 private:
  HMODULE module_;
};

}  // namespace

TEST_F(MemoryProfilerTest, NoServerNoCrash) {
  ASSERT_NO_FATAL_FAILURE(LoadDll());
  ASSERT_NO_FATAL_FAILURE(UnloadDll());
}

TEST_F(MemoryProfilerTest, ExpectedRecordsSeenTestNoStackTraces) {
  ASSERT_NO_FATAL_FAILURE(ExpectedRecordsSeenTest(false));
}

TEST_F(MemoryProfilerTest, ExpectedRecordsSeenTestWithStackTraces) {
  ASSERT_NO_FATAL_FAILURE(ExpectedRecordsSeenTest(true));
}

}  // namespace memprof
}  // namespace agent
