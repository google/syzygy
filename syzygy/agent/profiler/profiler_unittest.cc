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
//
// Profiler unittests.
#include "syzygy/agent/profiler/profiler.h"

#include <intrin.h>
#include <psapi.h>

#include "base/bind.h"
#include "base/file_util.h"
#include "base/scoped_native_library.h"
#include "base/files/file_enumerator.h"
#include "base/files/scoped_temp_dir.h"
#include "base/message_loop/message_loop.h"
#include "base/threading/platform_thread.h"
#include "base/threading/thread.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/agent/common/process_utils.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/unittest_util.h"
#include "syzygy/trace/common/unittest_util.h"
#include "syzygy/trace/parse/parser.h"
#include "syzygy/trace/parse/unittest_util.h"
#include "syzygy/trace/protocol/call_trace_defs.h"
#include "syzygy/trace/service/service.h"
#include "syzygy/trace/service/service_rpc_impl.h"

extern "C" {

typedef void (__cdecl *AddDynamicSymbolFunc)(
    const void* address, size_t length, const char* name, size_t name_len);
typedef void (__cdecl *MoveDynamicSymbolFunc)(
    const void* old_address, const void* new_address);
typedef void (__cdecl *OnDynamicFunctionEntryFunc)(
    uintptr_t function, uintptr_t return_addr_location);

// We register a TLS callback to test TLS thread notifications.
extern PIMAGE_TLS_CALLBACK profiler_test_tls_callback_entry;
void WINAPI ProfilerTestTlsCallback(PVOID h, DWORD reason, PVOID reserved);

// Force the linker to include the TLS entry.
#pragma comment(linker, "/INCLUDE:__tls_used")
#pragma comment(linker, "/INCLUDE:_profiler_test_tls_callback_entry")

#pragma data_seg(push, old_seg)
// Use a typical possible name in the .CRT$XL? list of segments.
#pragma data_seg(".CRT$XLB")
PIMAGE_TLS_CALLBACK profiler_test_tls_callback_entry =
    &ProfilerTestTlsCallback;
#pragma data_seg(pop, old_seg)

PIMAGE_TLS_CALLBACK tls_action = NULL;

void WINAPI ProfilerTestTlsCallback(PVOID h, DWORD reason, PVOID reserved) {
  if (tls_action)
    tls_action(h, reason, reserved);
}

}  // extern "C"

namespace agent {
namespace profiler {

namespace {

using agent::common::GetProcessModules;
using agent::common::ModuleVector;
using testing::_;
using testing::AllOf;
using testing::Return;
using testing::StrictMockParseEventHandler;
using trace::service::RpcServiceInstanceManager;
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

MATCHER_P2(InvocationInfoHasCallerSymbol, symbol_id, symbol_len, "") {
  for (size_t i = 0; i < 1; ++i) {
    const InvocationInfo& invocation = arg->invocations[i];
    // Test that we have the symbol as caller.
    if (invocation.flags & kCallerIsSymbol &&
        invocation.caller_symbol_id == symbol_id) {
      // We found the desired symbol, now check that caller offset
      // is in bounds of the symbol length, but larger than 0, as we know
      // the return address will be to a location after a call instruction,
      // which has to be some amount of distance into the caller.
      if (invocation.caller_offset >= symbol_len ||
          invocation.caller_offset == 0) {
        return false;
      }

      return true;
    }
  }

  return false;
}

MATCHER_P(InvocationInfoHasFunctionSymbol, symbol_id, "") {
  for (size_t i = 0; i < 1; ++i) {
    const InvocationInfo& invocation = arg->invocations[i];
    // Test that we have the symbol as caller.
    if ((invocation.flags & kFunctionIsSymbol) == kFunctionIsSymbol &&
        invocation.function_symbol_id == symbol_id) {
      return true;
    }
  }

  return false;
}

// This needs to be declared at file scope for the benefit of __asm code.
enum CallerAction {
  CALL_THROUGH,
  CALL_V8_ENTRY_HOOK,
  RETURN_LENGTH,
  RETURN_ADDR
};

// TODO(rogerm): Create a base fixture (perhaps templatized) to factor out
//     the common bits of testing various clients with the call trace service.
class ProfilerTest : public testing::Test {
 public:
  ProfilerTest()
      : module_(NULL),
        resolution_func_(NULL),
        add_symbol_func_(NULL),
        move_symbol_func_(NULL),
        on_v8_function_entry_(NULL) {
  }

  virtual void SetUp() OVERRIDE {
    testing::Test::SetUp();

    // Create a temporary directory for the call trace files.
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());

    service_.SetEnvironment();
  }

  virtual void TearDown() OVERRIDE {
    tls_action = NULL;

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

  // TODO(siggi): These are shareable with the other instrumentation DLL tests.
  //    Move them to a shared fixture superclass.
  void LoadDll() {
    ASSERT_TRUE(module_ == NULL);
    static const wchar_t kCallTraceDll[] = L"profile_client.dll";
    ASSERT_EQ(NULL, ::GetModuleHandle(kCallTraceDll));
    module_ = ::LoadLibrary(kCallTraceDll);
    ASSERT_TRUE(module_ != NULL);
    _indirect_penter_dllmain_ =
        ::GetProcAddress(module_, "_indirect_penter_dllmain");
    _indirect_penter_ = ::GetProcAddress(module_, "_indirect_penter");

    ASSERT_TRUE(_indirect_penter_dllmain_ != NULL);
    ASSERT_TRUE(_indirect_penter_ != NULL);

    resolution_func_ = reinterpret_cast<ResolveReturnAddressLocationFunc>(
        ::GetProcAddress(module_, "ResolveReturnAddressLocation"));
    ASSERT_TRUE(resolution_func_ != NULL);

    add_symbol_func_ = reinterpret_cast<AddDynamicSymbolFunc>(
        ::GetProcAddress(module_, "AddDynamicSymbol"));
    ASSERT_TRUE(add_symbol_func_ != NULL);

    move_symbol_func_ = reinterpret_cast<MoveDynamicSymbolFunc>(
        ::GetProcAddress(module_, "MoveDynamicSymbol"));
    ASSERT_TRUE(add_symbol_func_ != NULL);

    on_v8_function_entry_ = reinterpret_cast<OnDynamicFunctionEntryFunc>(
        ::GetProcAddress(module_, "OnDynamicFunctionEntry"));
    ASSERT_TRUE(on_v8_function_entry_ != NULL);
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
  // This function has a curious construct to work around incremental linking.
  // It can be called in three modes, to:
  // 1. Call through to DllMainThunk.
  // 2. Call the supplied v8 entry hook.
  // 3. Return it's own length.
  // 4. Return it's own address.
  // The last is necessary because &DllMainCaller will return the address of
  // a trampoline in incremental builds, whereas we need the address of the
  // function's implementation for the test.
  static intptr_t WINAPI DllMainCaller(CallerAction action,
                                       OnDynamicFunctionEntryFunc hook);

  static int IndirectFunctionA(int param1, const void* param2);
  static int FunctionAThunk(int param1, const void* param2);
  static int TestResolutionFuncThunk(ResolveReturnAddressLocationFunc resolver);
  static int TestResolutionFuncNestedThunk(
      ResolveReturnAddressLocationFunc resolver);

 protected:
  // The directory where trace file output will be written.
  base::ScopedTempDir temp_dir_;

  // The handler to which the trace file parser will delegate events.
  StrictMockParseEventHandler handler_;

  // Functions exported from the profiler dll.
  ResolveReturnAddressLocationFunc resolution_func_;
  AddDynamicSymbolFunc add_symbol_func_;
  MoveDynamicSymbolFunc move_symbol_func_;
  OnDynamicFunctionEntryFunc on_v8_function_entry_;

  // Our call trace service process instance.
  testing::CallTraceService service_;

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

intptr_t __declspec(naked) WINAPI ProfilerTest::DllMainCaller(
    CallerAction action, OnDynamicFunctionEntryFunc hook) {
  __asm {
   start:
    mov eax, dword ptr[esp + 4]  // get action
    cmp eax, CALL_THROUGH
    je call_through

    cmp eax, CALL_V8_ENTRY_HOOK
    je call_v8_entry_hook

    cmp eax, RETURN_LENGTH
    je return_length

    cmp eax, RETURN_ADDR
    je return_addr

    xor eax, eax
    ret 8

   return_length:
    // You'd think this could be phrased as:
    // mov eax, OFFSET end - OFFSET start
    // but alas it appears that this assembler is single-pass, and so does not
    // support arithmetic on labels.
    mov eax, OFFSET end
    sub eax, OFFSET start
    ret 8

   return_addr:
    mov eax, OFFSET start
    ret 8

   call_through:
    xor eax, eax
    push eax
    push eax
    push eax
    call DllMainThunk
    ret 8

  call_v8_entry_hook:
    push esp
    // Push the start label rather than the address of the function,
    // as the latter resolves to a thunk under incremental linking.
    push OFFSET start
    call [esp + 0x10]
    add esp, 8
    ret 8

   end:
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
  ASSERT_NO_FATAL_FAILURE(StartService());

  ASSERT_NO_FATAL_FAILURE(LoadDll());

  // Test the return address resolution function.
  ASSERT_NO_FATAL_FAILURE(TestResolutionFuncThunk(resolution_func_));

  // And with a nested thunk.
  ASSERT_NO_FATAL_FAILURE(TestResolutionFuncNestedThunk(resolution_func_));
}

TEST_F(ProfilerTest, RecordsAllModulesAndFunctions) {
  // Spin up the RPC service.
  ASSERT_NO_FATAL_FAILURE(StartService());

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
  ASSERT_NO_FATAL_FAILURE(StartService());

  // Get our own module handle.
  HMODULE self_module = ::GetModuleHandle(NULL);

  // Make sure the test DLL isn't already loaded.
  ASSERT_EQ(NULL, ::GetModuleHandle(testing::kTestDllName));

  ASSERT_NO_FATAL_FAILURE(LoadDll());

  // Record the module load twice.
  EXPECT_NO_FATAL_FAILURE(InvokeDllMainThunk(self_module));
  EXPECT_NO_FATAL_FAILURE(InvokeDllMainThunk(self_module));

  // And invoke Function A twice.
  ASSERT_NO_FATAL_FAILURE(InvokeFunctionAThunk());
  ASSERT_NO_FATAL_FAILURE(InvokeFunctionAThunk());

  // Load this module late to verify it's included in the module list.
  base::ScopedNativeLibrary test_dll(::LoadLibrary(testing::kTestDllName));
  ASSERT_TRUE(test_dll.is_valid());

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
  if (::IsDebuggerPresent()) {
    LOG(WARNING) << "This test fails under debugging.";
    return;
  }

  // Spin up the RPC service.
  ASSERT_NO_FATAL_FAILURE(StartService());

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
                                          _, _));
  EXPECT_CALL(handler_, OnThreadName(_,
                                     ::GetCurrentProcessId(),
                                     ::GetCurrentThreadId(),
                                     base::StringPiece(kThreadName)));
  EXPECT_CALL(handler_, OnProcessEnded(_, ::GetCurrentProcessId()));

  // Replay the log.
  ASSERT_NO_FATAL_FAILURE(ReplayLogs());
}

TEST_F(ProfilerTest, RecordsUsedSymbols) {
  // Spin up the RPC service.
  ASSERT_NO_FATAL_FAILURE(StartService());

  ASSERT_NO_FATAL_FAILURE(LoadDll());

  // Add a dynamic symbol for the DllMain and a hypothetical bogus function.
  base::StringPiece dll_main_caller_name("DllMainCaller");
  const uint8* dll_main_addr =
      reinterpret_cast<const uint8*>(DllMainCaller(RETURN_ADDR, NULL));
  size_t dll_main_len = DllMainCaller(RETURN_LENGTH, NULL);
  add_symbol_func_(dll_main_addr, dll_main_len,
                   dll_main_caller_name.data(), dll_main_caller_name.length());

  // Place bogus function immediately after the real DllMainCaller.
  base::StringPiece func_bogus_name("BogusFunction");
  add_symbol_func_(dll_main_addr + dll_main_len, dll_main_len,
                   func_bogus_name.data(), func_bogus_name.length());

  // And place uncalled function immediately after the real DllMainCaller.
  base::StringPiece func_uncalled_name("UncalledFunction");
  add_symbol_func_(dll_main_addr + dll_main_len * 2, dll_main_len,
                   func_uncalled_name.data(), func_uncalled_name.length());

  // Call through a "dynamic symbol" to the instrumented function.
  ASSERT_NO_FATAL_FAILURE(DllMainCaller(CALL_THROUGH, NULL));

  // Now make as if BogusFunction moves to replace DllMainCaller's location.
  move_symbol_func_(dll_main_addr + dll_main_len, dll_main_addr);

  // Call through a "dynamic symbol" to the instrumented function again.
  // This should result in a second dynamic symbol and entry in the trace file.
  ASSERT_NO_FATAL_FAILURE(DllMainCaller(CALL_THROUGH, NULL));

  ASSERT_NO_FATAL_FAILURE(UnloadDll());

  EXPECT_CALL(handler_, OnProcessStarted(_, ::GetCurrentProcessId(), _));
  EXPECT_CALL(handler_, OnProcessAttach(_,
                                        ::GetCurrentProcessId(),
                                        ::GetCurrentThreadId(),
                                        _))
      .Times(testing::AnyNumber());

  // Expect two invocation records batches with dynamic symbols.
  // TODO(siggi): Fixme: it's inefficient to alternate symbols and invocation
  //     batches. Easiest fix is to pre-allocate invocation record in batches.
  EXPECT_CALL(handler_,
      OnInvocationBatch(
          _, ::GetCurrentProcessId(), ::GetCurrentThreadId(),
          1U, InvocationInfoHasCallerSymbol(1U, dll_main_len)));
  EXPECT_CALL(handler_,
      OnInvocationBatch(
          _, ::GetCurrentProcessId(), ::GetCurrentThreadId(),
          1U, InvocationInfoHasCallerSymbol(2U, dll_main_len)));

  EXPECT_CALL(handler_, OnProcessEnded(_, ::GetCurrentProcessId()));

  // The DllMain and the Bogus functions should both make an appearance,
  // and nothing else.
  EXPECT_CALL(handler_,
      OnDynamicSymbol(::GetCurrentProcessId(), 1, dll_main_caller_name));
  EXPECT_CALL(handler_,
      OnDynamicSymbol(::GetCurrentProcessId(), _, func_bogus_name));

  // Replay the log.
  ASSERT_NO_FATAL_FAILURE(ReplayLogs());
}

TEST_F(ProfilerTest, OnDynamicFunctionEntry) {
  ASSERT_NO_FATAL_FAILURE(StartService());
  ASSERT_NO_FATAL_FAILURE(LoadDll());

  // Add a dynamic symbol for the DllMain and a hypothetical bogus function.
  base::StringPiece dll_main_caller_name("DllMainCaller");
  const uint8* dll_main_addr =
      reinterpret_cast<const uint8*>(DllMainCaller(RETURN_ADDR, NULL));
  size_t dll_main_len = DllMainCaller(RETURN_LENGTH, NULL);
  add_symbol_func_(dll_main_addr, dll_main_len,
                   dll_main_caller_name.data(), dll_main_caller_name.length());

  // Call the V8 entry hook.
  DllMainCaller(CALL_V8_ENTRY_HOOK, on_v8_function_entry_);

  ASSERT_NO_FATAL_FAILURE(UnloadDll());

  EXPECT_CALL(handler_, OnProcessStarted(_, ::GetCurrentProcessId(), _));
  EXPECT_CALL(handler_, OnProcessAttach(_,
                                        ::GetCurrentProcessId(),
                                        ::GetCurrentThreadId(),
                                        _))
      .Times(testing::AnyNumber());

  // Expect two invocation records batches with dynamic symbols.
  EXPECT_CALL(handler_,
      OnInvocationBatch(
          _, ::GetCurrentProcessId(), ::GetCurrentThreadId(),
          1U, InvocationInfoHasFunctionSymbol(1U)));

  EXPECT_CALL(handler_, OnProcessEnded(_, ::GetCurrentProcessId()));

  // The DllMain and the Bogus functions should both make an appearance,
  // and nothing else.
  EXPECT_CALL(handler_,
      OnDynamicSymbol(::GetCurrentProcessId(), 1, dll_main_caller_name));

  // Replay the log.
  ASSERT_NO_FATAL_FAILURE(ReplayLogs());
}

namespace {

void WINAPI TlsAction(PVOID h, DWORD reason, PVOID reserved) {
  // We sometimes get stray threads winding up inside a unittest, and those
  // will generate a TLS callback. If we pass these through, flakiness will
  // result, so we pass only through calls on from base::Thread, which
  // we identify by the presence of a message loop.
  if (base::MessageLoop::current() != NULL)
    InvokeFunctionAThunk();
}

}  // namespace

TEST_F(ProfilerTest, ReleasesBufferOnThreadExit) {
  // Spin up the RPC service.
  ASSERT_NO_FATAL_FAILURE(StartService());

  ASSERT_NO_FATAL_FAILURE(LoadDll());

  tls_action = TlsAction;

  // Spinning 400 * 8 threads should exhaust the address
  // space if we're leaking a buffer for each thread.
  for (size_t i = 0; i < 400; ++i) {
    base::Thread thread1("one");
    base::Thread thread2("two");
    base::Thread thread3("three");
    base::Thread thread4("four");
    base::Thread thread5("five");
    base::Thread thread6("six");
    base::Thread thread7("seven");
    base::Thread thread8("eight");

    base::Thread* threads[8] = { &thread1, &thread2, &thread3, &thread4,
                                 &thread5, &thread6, &thread7, &thread8};

    // Start all the threads, and make them do some work.
    for (size_t j = 0; j < arraysize(threads); ++j) {
      base::Thread* thread = threads[j];
      thread->Start();
      thread->message_loop()->PostTask(
          FROM_HERE, base::Bind(InvokeFunctionAThunk));
    }

    // This will implicitly wind down all the threads.
  }

  ASSERT_NO_FATAL_FAILURE(UnloadDll());
}

TEST_F(ProfilerTest, EntryHookPerformance) {
  ASSERT_NO_FATAL_FAILURE(LoadDll());

  // We grab the lowest value of 10 invocations to minimize scheduling
  // artifacts and such.
  uint64 min_cycles = kuint64max;
  for (size_t i = 0; i < 10; ++i) {
    // Invoke on the entry hook a hundred thousand times, and measure the
    // wall-clock time from start to finish.
    uint64 start_cycles = __rdtsc();
    for (size_t j = 0; j < 100000; ++j) {
      InvokeFunctionAThunk();
    }
    uint64 end_cycles = __rdtsc();

    if (min_cycles > (end_cycles - start_cycles))
      min_cycles = end_cycles - start_cycles;
  }

  printf("100K entry hook invocations in [%llu] cycles.\n", min_cycles);
}

}  // namespace profiler
}  // namespace agent
