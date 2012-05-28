// Copyright 2012 Google Inc.
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
// Profiler unittests.
#include "syzygy/agent/profiler/profiler.h"

#include <intrin.h>
#include <psapi.h>

#include "base/environment.h"
#include "base/file_util.h"
#include "base/scoped_temp_dir.h"
#include "base/stringprintf.h"
#include "base/utf_string_conversions.h"
#include "base/threading/platform_thread.h"
#include "base/threading/thread.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/agent/common/process_utils.h"
#include "syzygy/trace/parse/parser.h"
#include "syzygy/trace/service/service.h"
#include "syzygy/trace/service/service_rpc_impl.h"
#include "syzygy/trace/service/trace_file_writer_factory.h"

namespace agent {
namespace profiler {

namespace {

using agent::common::GetProcessModules;
using agent::common::ModuleVector;
using file_util::FileEnumerator;
using testing::_;
using testing::Return;
using testing::StrictMock;
using trace::service::RpcServiceInstanceManager;
using trace::service::TraceFileWriterFactory;
using trace::service::Service;
using trace::parser::Parser;
using trace::parser::ParseEventHandler;

// The information on how to set the thread name comes from
// a MSDN article: http://msdn2.microsoft.com/en-us/library/xcb2z8hs.aspx
const DWORD kVCThreadNameException = 0x406D1388;

typedef struct tagTHREADNAME_INFO {
  DWORD dwType;  // Must be 0x1000.
  LPCSTR szName;  // Pointer to name (in user addr space).
  DWORD dwThreadID;  // Thread ID (-1=caller thread).
  DWORD dwFlags;  // Reserved for future use, must be zero.
} THREADNAME_INFO;

// This function has try handling, so it is separated out of its caller.
void SetNameInternal(const char* name) {
  THREADNAME_INFO info;
  info.dwType = 0x1000;
  info.szName = name;
  info.dwThreadID = -1;
  info.dwFlags = 0;

  __try {
    RaiseException(kVCThreadNameException, 0, sizeof(info)/sizeof(DWORD),
                   reinterpret_cast<DWORD_PTR*>(&info));
  } __except(EXCEPTION_CONTINUE_EXECUTION) {
  }
}

// Return address location resolution function.
typedef uintptr_t (__cdecl *ResolveReturnAddressLocationFunc)(
    uintptr_t pc_location);

MATCHER_P(ModuleAtAddress, module, "") {
  return arg->module_base_addr == module;
}

class MockParseEventHandler : public ParseEventHandler {
 public:
  MOCK_METHOD3(OnProcessStarted, void (base::Time time,
                                       DWORD process_id,
                                       const TraceSystemInfo* data));
  MOCK_METHOD2(OnProcessEnded, void (base::Time time, DWORD process_id));
  MOCK_METHOD4(OnFunctionEntry, void (base::Time time,
                                      DWORD process_id,
                                      DWORD thread_id,
                                      const TraceEnterExitEventData* data));
  MOCK_METHOD4(OnFunctionExit, void (base::Time time,
                                     DWORD process_id,
                                     DWORD thread_id,
                                     const TraceEnterExitEventData* data));
  MOCK_METHOD4(OnBatchFunctionEntry, void (base::Time time,
                                           DWORD process_id,
                                           DWORD thread_id,
                                           const TraceBatchEnterData* data));
  MOCK_METHOD4(OnProcessAttach, void (base::Time time,
                                      DWORD process_id,
                                      DWORD thread_id,
                                      const TraceModuleData* data));
  MOCK_METHOD4(OnProcessDetach, void (base::Time time,
                                      DWORD process_id,
                                      DWORD thread_id,
                                      const TraceModuleData* data));
  MOCK_METHOD4(OnThreadAttach, void (base::Time time,
                                     DWORD process_id,
                                     DWORD thread_id,
                                     const TraceModuleData* data));
  MOCK_METHOD4(OnThreadDetach, void (base::Time time,
                                     DWORD process_id,
                                     DWORD thread_id,
                                     const TraceModuleData* data));
  MOCK_METHOD5(OnInvocationBatch, void (base::Time time,
                                        DWORD process_id,
                                        DWORD thread_id,
                                        size_t num_batches,
                                        const TraceBatchInvocationInfo* data));
  MOCK_METHOD4(OnThreadName, void (base::Time time,
                                   DWORD process_id,
                                   DWORD thread_id,
                                   const base::StringPiece& thread_name));
};

// TODO(rogerm): Create a base fixture (perhaps templatized) to factor out
//     the common bits of testing various clients with the call trace service.
class ProfilerTest : public testing::Test {
 public:
  ProfilerTest()
      : consumer_thread_("profiler-test-consumer-thread"),
        consumer_thread_has_started_(
            consumer_thread_.StartWithOptions(
                base::Thread::Options(MessageLoop::TYPE_IO, 0))),
        trace_file_writer_factory_(consumer_thread_.message_loop()),
        call_trace_service_(&trace_file_writer_factory_),
        rpc_service_instance_manager_(&call_trace_service_),
        module_(NULL),
        resolution_func_(NULL) {
  }

  virtual void SetUp() OVERRIDE {
    testing::Test::SetUp();

    ASSERT_TRUE(consumer_thread_has_started_);

    // Create a temporary directory for the call trace files.
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    ASSERT_TRUE(
        trace_file_writer_factory_.SetTraceFileDirectory(temp_dir_.path()));

    // We give the service instance a "unique" id so that it does not interfere
    // with any other instances or tests that might be concurrently active.
    std::string instance_id(base::StringPrintf("%d", ::GetCurrentProcessId()));
    call_trace_service_.set_instance_id(::UTF8ToWide(instance_id));

    // The instance id needs to be in the environment to be picked up by the
    // client library.
    scoped_ptr<base::Environment> env(base::Environment::Create());
    ASSERT_FALSE(env.get() == NULL);
    ASSERT_TRUE(env->SetVar(::kSyzygyRpcInstanceIdEnvVar, instance_id));
  }

  virtual void TearDown() OVERRIDE {
    UnloadDll();

    // Stop the call trace service.
    EXPECT_TRUE(call_trace_service_.Stop());
    EXPECT_FALSE(call_trace_service_.is_running());
  }

  void ReplayLogs() {
    // Stop the service if it's running.
    ASSERT_TRUE(call_trace_service_.Stop());
    ASSERT_FALSE(call_trace_service_.is_running());

    Parser parser;
    ASSERT_TRUE(parser.Init(&handler_));

    // Queue up the trace file(s) we engendered.
    file_util::FileEnumerator enumerator(temp_dir_.path(),
                                         false,
                                         FileEnumerator::FILES);
    size_t num_files = 0;
    while (true) {
      FilePath trace_file = enumerator.Next();
      if (trace_file.empty())
        break;
      ASSERT_TRUE(parser.OpenTraceFile(trace_file));
      ++num_files;
    }
    EXPECT_GT(num_files, 0U);
    ASSERT_TRUE(parser.Consume());
  }

  // TODO(siggi): These are shareable with the other instrumentation DLL tests.
  //    Move them to a shared fixture superclass.
  void LoadDll() {
    ASSERT_TRUE(module_ == NULL);
    const wchar_t* call_trace_dll = L"profile_client.dll";
    ASSERT_EQ(NULL, ::GetModuleHandle(call_trace_dll));
    module_ = ::LoadLibrary(call_trace_dll);
    ASSERT_TRUE(module_ != NULL);
    _indirect_penter_dllmain_ =
        ::GetProcAddress(module_, "_indirect_penter_dllmain");
    _indirect_penter_ = ::GetProcAddress(module_, "_indirect_penter");

    ASSERT_TRUE(_indirect_penter_dllmain_ != NULL);
    ASSERT_TRUE(_indirect_penter_ != NULL);

    resolution_func_ = reinterpret_cast<ResolveReturnAddressLocationFunc>(
        ::GetProcAddress(module_, "ResolveReturnAddressLocation"));
    ASSERT_TRUE(resolution_func_ != NULL);
  }

  void UnloadDll() {
    if (module_ != NULL) {
      ASSERT_TRUE(::FreeLibrary(module_));
      module_ = NULL;
      _indirect_penter_ = NULL;
      _indirect_penter_dllmain_ = NULL;
    }
  }

  static BOOL WINAPI IndirectDllMain(HMODULE module,
                                     DWORD reason,
                                     LPVOID reserved);
  static BOOL WINAPI DllMainThunk(HMODULE module,
                                  DWORD reason,
                                  LPVOID reserved);

  static int IndirectFunctionA(int param1, const void* param2);
  static int FunctionAThunk(int param1, const void* param2);
  static int TestResolutionFuncThunk(ResolveReturnAddressLocationFunc resolver);
  static int TestResolutionFuncNestedThunk(
      ResolveReturnAddressLocationFunc resolver);

 protected:
  // The thread on which the trace file writer will consumer buffers and a
  // helper variable whose initialization we use as a trigger to start the
  // thread (ensuring it's message_loop is created). These declarations MUST
  // remain in this order and preceed that of trace_file_writer_factory_;
  base::Thread consumer_thread_;
  bool consumer_thread_has_started_;

  // The call trace service related objects. These declarations MUST be in
  // this order.
  TraceFileWriterFactory trace_file_writer_factory_;
  Service call_trace_service_;
  RpcServiceInstanceManager rpc_service_instance_manager_;

  // The directory where trace file output will be written.
  ScopedTempDir temp_dir_;

  // The handler to which the trace file parser will delegate events.
  StrictMock<MockParseEventHandler> handler_;

  // The address resolution function exported from the profiler dll.
  ResolveReturnAddressLocationFunc resolution_func_;

 private:
  HMODULE module_;
  static FARPROC _indirect_penter_;
  static FARPROC _indirect_penter_dllmain_;
};

FARPROC ProfilerTest::_indirect_penter_ = NULL;
FARPROC ProfilerTest::_indirect_penter_dllmain_ = NULL;

BOOL WINAPI ProfilerTest::IndirectDllMain(HMODULE module,
                                          DWORD reason,
                                          LPVOID reserved) {
  return TRUE;
}

BOOL __declspec(naked) WINAPI ProfilerTest::DllMainThunk(HMODULE module,
                                                         DWORD reason,
                                                         LPVOID reserved) {
  __asm {
    push IndirectDllMain
    jmp _indirect_penter_dllmain_
  }
}

int ProfilerTest::IndirectFunctionA(int param1,
                                    const void* param2) {
  return param1 + reinterpret_cast<int>(param2);
}

int __declspec(naked) ProfilerTest::FunctionAThunk(int param1,
                                                   const void* param2) {
  __asm {
    push IndirectFunctionA
    jmp _indirect_penter_
  }
}

void TestResolutionFunc(ResolveReturnAddressLocationFunc resolver) {
  uintptr_t pc_location =
      reinterpret_cast<uintptr_t>(_AddressOfReturnAddress());
  ASSERT_NE(pc_location, resolver(pc_location));

  // Make sure we unwind thunk chains.
  pc_location = resolver(pc_location);
  ASSERT_EQ(pc_location, resolver(pc_location));
}

int __declspec(naked) ProfilerTest::TestResolutionFuncThunk(
    ResolveReturnAddressLocationFunc resolver) {
  __asm {
    push TestResolutionFunc
    jmp _indirect_penter_
  }
}

int __declspec(naked) ProfilerTest::TestResolutionFuncNestedThunk(
    ResolveReturnAddressLocationFunc resolver) {
  // This will make like tail call elimination and create nested thunks.
  __asm {
    push TestResolutionFuncThunk
    jmp _indirect_penter_
  }
}

}  // namespace

TEST_F(ProfilerTest, NoServerNoCrash) {
  ASSERT_NO_FATAL_FAILURE(LoadDll());

  EXPECT_TRUE(DllMainThunk(NULL, DLL_PROCESS_ATTACH, NULL));
}

TEST_F(ProfilerTest, ResolveReturnAddressLocation) {
  // Spin up the RPC service.
  ASSERT_TRUE(call_trace_service_.Start(true));

  ASSERT_NO_FATAL_FAILURE(LoadDll());

  // Test the return address resolution function.
  ASSERT_NO_FATAL_FAILURE(TestResolutionFuncThunk(resolution_func_));

  // And with a nested thunk.
  ASSERT_NO_FATAL_FAILURE(TestResolutionFuncNestedThunk(resolution_func_));
}

TEST_F(ProfilerTest, RecordsAllModulesAndFunctions) {
  // Spin up the RPC service.
  ASSERT_TRUE(call_trace_service_.Start(true));

  // Get our own module handle.
  HMODULE self_module = ::GetModuleHandle(NULL);

  ASSERT_NO_FATAL_FAILURE(LoadDll());
  // TODO(rogerm): This generates spurious error logs at higher log levels
  //     because the module paths are different when depending on who infers
  //     them (one is drive letter based and the other is device based).
  EXPECT_TRUE(DllMainThunk(self_module, DLL_PROCESS_ATTACH, NULL));

  // Get the module list prior to unloading the profile DLL.
  ModuleVector modules;
  GetProcessModules(&modules);

  ASSERT_NO_FATAL_FAILURE(UnloadDll());

  // Set up expectations for what should be in the trace.
  EXPECT_CALL(handler_, OnProcessStarted(_, ::GetCurrentProcessId(), _));
  for (size_t i = 0; i < modules.size(); ++i) {
    EXPECT_CALL(handler_, OnProcessAttach(_,
                                          ::GetCurrentProcessId(),
                                          ::GetCurrentThreadId(),
                                          ModuleAtAddress(modules[i])));
  }

  // TODO(siggi): Match harder here.
  EXPECT_CALL(handler_, OnInvocationBatch(_,
                                          ::GetCurrentProcessId(),
                                          ::GetCurrentThreadId(),
                                          1,
                                          _));
  EXPECT_CALL(handler_, OnProcessEnded(_, ::GetCurrentProcessId()));

  // Replay the log.
  ASSERT_NO_FATAL_FAILURE(ReplayLogs());
}

namespace {

// We invoke the thunks through these intermediate functions to make sure
// we can generate two or more identical invocation records, e.g. same
// call site, same callee. We turn off inlining to make sure the functions
// aren't assimilated into the callsite by the compiler or linker, thus
// defeating our intent.
#pragma auto_inline(off)
void InvokeDllMainThunk(HMODULE module) {
  EXPECT_TRUE(ProfilerTest::DllMainThunk(module, DLL_PROCESS_ATTACH, NULL));
}

void InvokeFunctionAThunk() {
  const int kParam1 = 0xFAB;
  const void* kParam2 = &kParam1;
  const int kExpected = kParam1 + reinterpret_cast<int>(kParam2);
  EXPECT_EQ(kExpected, ProfilerTest::FunctionAThunk(kParam1, kParam2));
}
#pragma auto_inline(on)

}  // namespace

TEST_F(ProfilerTest, RecordsOneEntryPerModuleAndFunction) {
  // Spin up the RPC service.
  ASSERT_TRUE(call_trace_service_.Start(true));

  // Get our own module handle.
  HMODULE self_module = ::GetModuleHandle(NULL);

  ASSERT_NO_FATAL_FAILURE(LoadDll());

  // Record the module load twice.
  EXPECT_NO_FATAL_FAILURE(InvokeDllMainThunk(self_module));
  EXPECT_NO_FATAL_FAILURE(InvokeDllMainThunk(self_module));

  // And invoke Function A twice.
  ASSERT_NO_FATAL_FAILURE(InvokeFunctionAThunk());
  ASSERT_NO_FATAL_FAILURE(InvokeFunctionAThunk());

  // Get the module list prior to unloading the profile DLL.
  ModuleVector modules;
  GetProcessModules(&modules);

  ASSERT_NO_FATAL_FAILURE(UnloadDll());

  EXPECT_CALL(handler_, OnProcessStarted(_, ::GetCurrentProcessId(), _));

  // We should only have one event per module,
  // despite the double DllMain invocation.
  for (size_t i = 0; i < modules.size(); ++i) {
    EXPECT_CALL(handler_, OnProcessAttach(_,
                                          ::GetCurrentProcessId(),
                                          ::GetCurrentThreadId(),
                                          ModuleAtAddress(modules[i])));
  }

  // TODO(siggi): Match harder here.
  // We should only have two distinct invocation records,
  // despite calling each function twice.
  EXPECT_CALL(handler_, OnInvocationBatch(_,
                                          ::GetCurrentProcessId(),
                                          ::GetCurrentThreadId(),
                                          2,
                                          _));
  EXPECT_CALL(handler_, OnProcessEnded(_, ::GetCurrentProcessId()));

  // Replay the log.
  ASSERT_NO_FATAL_FAILURE(ReplayLogs());
}

TEST_F(ProfilerTest, RecordsThreadName) {
  // Spin up the RPC service.
  ASSERT_TRUE(call_trace_service_.Start(true));

  ASSERT_NO_FATAL_FAILURE(LoadDll());

  // And invoke a function to get things initialized.
  ASSERT_NO_FATAL_FAILURE(InvokeFunctionAThunk());

  // Beware that this test will fail under debugging, as the
  // debugger by default swallows the exception.
  static const char kThreadName[] = "Profiler Test Thread";
  SetNameInternal(kThreadName);

  ASSERT_NO_FATAL_FAILURE(UnloadDll());

  EXPECT_CALL(handler_, OnProcessStarted(_, ::GetCurrentProcessId(), _));
  EXPECT_CALL(handler_, OnProcessAttach(_,
                                        ::GetCurrentProcessId(),
                                        ::GetCurrentThreadId(),
                                        _))
      .Times(testing::AnyNumber());
  EXPECT_CALL(handler_, OnInvocationBatch(_,
                                          ::GetCurrentProcessId(),
                                          ::GetCurrentThreadId(),
                                          _ ,_));
  EXPECT_CALL(handler_, OnThreadName(_,
                                     ::GetCurrentProcessId(),
                                     ::GetCurrentThreadId(),
                                     base::StringPiece(kThreadName)));
  EXPECT_CALL(handler_, OnProcessEnded(_, ::GetCurrentProcessId()));

  // Replay the log.
  ASSERT_NO_FATAL_FAILURE(ReplayLogs());
}

}  // namespace profiler
}  // namespace agent
