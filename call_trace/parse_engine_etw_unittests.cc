// Copyright 2011 Google Inc.
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
#include <map>
#include "base/file_path.h"
#include "base/file_util.h"
#include "base/logging.h"
#include "base/threading/simple_thread.h"
#include "base/win/event_trace_consumer.h"
#include "base/win/event_trace_controller.h"
#include "base/win/scoped_handle.h"
#include "base/win/windows_version.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/call_trace/parser.h"

// TODO(rogerm): There is a log of duplicate code in common between this
//     file and "parse_engine_rpc_unittests.cc". This common bits should
//     be extracted from the other file and this file should be updated
//     to use the tests and structure found in the other file (to test
//     dll entrypoints, module events, etc).

using call_trace::parser::Parser;
using call_trace::parser::ParseEventHandler;

namespace {

enum CallEntryType {
  kCallEntry,
  kCallExit,
};

struct Call {
  base::Time entry;
  DWORD thread_id;
  FuncAddr address;
  CallEntryType type;
};

bool operator<(const Call& a, const Call& b) {
  if (a.entry < b.entry)
    return true;
  if (a.entry > b.entry)
    return false;

  if (a.thread_id < b.thread_id)
    return true;
  if (a.thread_id > b.thread_id)
    return false;

  if (a.address < b.address)
    return true;
  if (a.address > b.address)
    return false;

  return a.type < b.type;
}

typedef std::multiset<FuncAddr> CalledAddresses;
typedef std::multiset<Call> Calls;

class TestParseEventHandler : public ParseEventHandler {
 public:
  TestParseEventHandler() : process_id_(::GetCurrentProcessId()) {
  }

  ~TestParseEventHandler() {
  }

  virtual void OnProcessStarted(base::Time time, DWORD process_id) {
  }

  virtual void OnProcessEnded(base::Time time, DWORD process_id) {
  }

  virtual void OnFunctionEntry(base::Time time,
                               DWORD process_id,
                               DWORD thread_id,
                               const TraceEnterExitEventData* data) {
    entered_addresses_.insert(data->function);
    Call call = { time, thread_id, data->function, kCallEntry };
    calls_.insert(call);
  }

  virtual void OnFunctionExit(base::Time time,
                             DWORD process_id,
                             DWORD thread_id,
                             const TraceEnterExitEventData* data) {
    exited_addresses_.insert(data->function);
    Call call = { time, thread_id, data->function, kCallExit };
    calls_.insert(call);
  }

  virtual void OnBatchFunctionEntry(base::Time time,
                                    DWORD process_id,
                                    DWORD thread_id,
                                    const TraceBatchEnterData* data) {
    for (size_t i = 0; i < data->num_calls; ++i) {
      entered_addresses_.insert(data->calls[i].function);
      Call call = {
          time - base::TimeDelta::FromMilliseconds(data->calls[i].ticks_ago),
          thread_id,
          data->calls[i].function,
          kCallEntry };
      calls_.insert(call);
    }
  }

  virtual void OnProcessAttach(base::Time time,
                               DWORD process_id,
                               DWORD thread_id,
                               const TraceModuleData* data) {
    ADD_FAILURE() << "Unexpected event for ETW call trace parser!";
  }

  virtual void OnProcessDetach(base::Time time,
                               DWORD process_id,
                               DWORD thread_id,
                               const TraceModuleData* data) {
    ADD_FAILURE() << "Unexpected event for ETW call trace parser!";
  }

  virtual void OnThreadAttach(base::Time time,
                              DWORD process_id,
                              DWORD thread_id,
                              const TraceModuleData* data) {
    ADD_FAILURE() << "Unexpected event for ETW call trace parser!";
  }

  virtual void OnThreadDetach(base::Time time,
                              DWORD process_id,
                              DWORD thread_id,
                              const TraceModuleData* data) {
    ADD_FAILURE() << "Unexpected event for ETW call trace parser!";
  }


  void GetEnteredAddresses(CalledAddresses* entered_addresses) {
    ASSERT_TRUE(entered_addresses != NULL);
    entered_addresses_.swap(*entered_addresses);
  }

  void GetExitedAddresses(CalledAddresses* exited_addresses) {
    ASSERT_TRUE(exited_addresses != NULL);
    exited_addresses_.swap(*exited_addresses);
  }

  void GetCalls(Calls* calls) {
    ASSERT_TRUE(calls != NULL);
    calls_.swap(*calls);
  }

 private:
  DWORD process_id_;
  CalledAddresses entered_addresses_;
  CalledAddresses exited_addresses_;
  Calls calls_;
};

const wchar_t* const kTestSessionName = L"TestLogSession";

// We run events through a file session to assert that
// the content comes through.
class ParseEngineEtwTest: public testing::Test {
 public:
  ParseEngineEtwTest() : module_(NULL), wait_til_disabled_(NULL),
      wait_til_enabled_(NULL), is_private_session_(false) {
  }

  virtual void SetUp() {
    base::win::EtwTraceProperties properties;
    base::win::EtwTraceController::Stop(kTestSessionName, &properties);

    // The call trace DLL should not be already loaded.
    ASSERT_EQ(NULL, ::GetModuleHandle(L"call_trace.dll"));

    // Construct a temp file name.
    ASSERT_TRUE(file_util::CreateTemporaryFile(&temp_file_));

    // Set up a file session.
    HRESULT hr = controller_.StartFileSession(kTestSessionName,
                                             temp_file_.value().c_str());
    if (hr == E_ACCESSDENIED &&
        base::win::GetVersion() >= base::win::VERSION_VISTA) {
      // Try a private session if we're running on Vista or better.
      base::win::EtwTraceProperties prop;
      prop.SetLoggerFileName(temp_file_.value().c_str());
      EVENT_TRACE_PROPERTIES& p = *prop.get();
      p.Wnode.ClientContext = 1;  // QPC timer accuracy.
      p.LogFileMode = EVENT_TRACE_FILE_MODE_SEQUENTIAL |
                      EVENT_TRACE_PRIVATE_LOGGER_MODE |
                      EVENT_TRACE_PRIVATE_IN_PROC;  // Private, sequential log.

      p.MaximumFileSize = 100;  // 100M file size.
      p.FlushTimer = 30;  // 30 seconds flush lag.

      hr = controller_.Start(kTestSessionName, &prop);

      is_private_session_ = true;
    } else {
      is_private_session_ = false;
    }

    ASSERT_HRESULT_SUCCEEDED(hr);
  }

  virtual void TearDown() {
    base::win::EtwTraceProperties properties;
    base::win::EtwTraceController::Stop(kTestSessionName, &properties);
    UnloadCallTraceDll();
    EXPECT_TRUE(file_util::Delete(temp_file_, false));
  }

  void ConsumeEventsFromTempSession() {
    // Now consume the event(s).
    TestParseEventHandler consumer;
    Parser parser;
    ASSERT_TRUE(parser.Init(&consumer));
    ASSERT_TRUE(parser.OpenTraceFile(temp_file_));
    ASSERT_TRUE(parser.Consume());

    // And nab the result.
    entered_addresses_.clear();
    exited_addresses_.clear();
    calls_.clear();
    consumer.GetEnteredAddresses(&entered_addresses_);
    consumer.GetExitedAddresses(&exited_addresses_);
    consumer.GetCalls(&calls_);
  }

  void LoadAndEnableCallTraceDll(ULONG flags) {
    // For a private ETW session, a provider must be
    // registered before it's enabled.
    if (is_private_session_) {
      ASSERT_NO_FATAL_FAILURE(LoadCallTraceDll());
    }

    ASSERT_HRESULT_SUCCEEDED(
        controller_.EnableProvider(kCallTraceProvider,
                                   CALL_TRACE_LEVEL,
                                   flags));

    if (!is_private_session_) {
      ASSERT_NO_FATAL_FAILURE(LoadCallTraceDll());
    }
  }

  void LoadCallTraceDll() {
    ASSERT_EQ(NULL, ::GetModuleHandle(L"call_trace.dll"));
    module_ = ::LoadLibrary(L"call_trace.dll");
    ASSERT_TRUE(module_ != NULL);
    _indirect_penter_ = GetProcAddress(module_, "_indirect_penter");
    _penter_ = GetProcAddress(module_, "_penter");
    wait_til_enabled_ = reinterpret_cast<WaitFuncType>(
        GetProcAddress(module_, "wait_til_enabled"));
    wait_til_disabled_ = reinterpret_cast<WaitFuncType>(
        GetProcAddress(module_, "wait_til_disabled"));

    ASSERT_TRUE(_indirect_penter_ != NULL);
    ASSERT_TRUE(wait_til_enabled_ != NULL);
    ASSERT_TRUE(wait_til_disabled_ != NULL);
  }

  void UnloadCallTraceDll() {
    if (module_) {
      ASSERT_TRUE(::FreeLibrary(module_));
      module_ = NULL;
      _indirect_penter_ = NULL;
      _penter_ = NULL;

      wait_til_disabled_ = NULL;
      wait_til_enabled_ = NULL;
    }
  }

  friend void IndirectThunkA();
  friend void IndirectThunkB();

 protected:
  typedef bool (*WaitFuncType)(void);
  WaitFuncType wait_til_enabled_;
  WaitFuncType wait_til_disabled_;

  base::win::EtwTraceController controller_;
  CalledAddresses entered_addresses_;
  CalledAddresses exited_addresses_;
  Calls calls_;

  // True iff controller_ has started a private file session.
  bool is_private_session_;

  FilePath temp_file_;
  HMODULE module_;
  static FARPROC _indirect_penter_;
  static FARPROC _penter_;
};

FARPROC ParseEngineEtwTest::_indirect_penter_ = 0;
FARPROC ParseEngineEtwTest::_penter_ = 0;

TEST(CallTraceDllLoadUnloadTest, ProcessAttach) {
  HMODULE module = ::LoadLibrary(L"call_trace.dll");
  ASSERT_TRUE(module != NULL);
  ASSERT_TRUE(::FreeLibrary(module));
}

void IndirectFunctionA() {
  rand();
}

void __declspec(naked) IndirectThunkA() {
  __asm {
    push IndirectFunctionA
    jmp ParseEngineEtwTest::_indirect_penter_
  }
}

void IndirectFunctionB() {
  clock();
}

void __declspec(naked) IndirectThunkB() {
  __asm {
    push IndirectFunctionB
    jmp ParseEngineEtwTest::_indirect_penter_
  }
}

class IndirectFunctionThread : public base::DelegateSimpleThread::Delegate {
 public:
  IndirectFunctionThread(int invocation_count, void (*f)(void), DWORD delay = 0)
      : invocation_count_(invocation_count), f_(f), delay_(delay) {
    exit_event_.Set(::CreateEvent(NULL, TRUE, FALSE, NULL));
    CHECK(exit_event_);
    done_event_.Set(::CreateEvent(NULL, TRUE, FALSE, NULL));
    CHECK(done_event_);
  }

  virtual void Run() {
    for (int i = 0; i < invocation_count_; ++i) {
      f_();
      if (i + 1 < invocation_count_ && delay_) {
        ::Sleep(delay_);
      }
    }
    ::SetEvent(done_event_);
    ASSERT_EQ(WAIT_OBJECT_0, ::WaitForSingleObject(exit_event_, INFINITE));
  }

  void Exit() {
    ::SetEvent(exit_event_);
  }

  void Wait() {
    ASSERT_EQ(WAIT_OBJECT_0, ::WaitForSingleObject(done_event_, INFINITE));
  }

 private:
  int invocation_count_;
  void (*f_)(void);
  DWORD delay_;
  base::win::ScopedHandle exit_event_;
  base::win::ScopedHandle done_event_;
};

}  // namespace

TEST_F(ParseEngineEtwTest, SingleThread) {
  ASSERT_NO_FATAL_FAILURE(LoadAndEnableCallTraceDll(TRACE_FLAG_BATCH_ENTER));

  ASSERT_TRUE(wait_til_enabled_());

  IndirectThunkA();
  IndirectThunkA();
  IndirectThunkA();

  UnloadCallTraceDll();

  ASSERT_HRESULT_SUCCEEDED(controller_.Flush(NULL));
  ASSERT_NO_FATAL_FAILURE(ConsumeEventsFromTempSession());

  ASSERT_EQ(3, entered_addresses_.size());
  ASSERT_EQ(3, entered_addresses_.count(IndirectFunctionA));
}

TEST_F(ParseEngineEtwTest, MultiThreadWithDetach) {
  ASSERT_NO_FATAL_FAILURE(LoadAndEnableCallTraceDll(TRACE_FLAG_BATCH_ENTER));

  ASSERT_TRUE(wait_til_enabled_());

  IndirectFunctionThread runner_a(2, IndirectThunkA);

  base::DelegateSimpleThread thread(&runner_a, "thread a");

  thread.Start();
  runner_a.Exit();
  thread.Join();

  UnloadCallTraceDll();

  ASSERT_HRESULT_SUCCEEDED(controller_.Flush(NULL));
  ASSERT_NO_FATAL_FAILURE(ConsumeEventsFromTempSession());

  ASSERT_EQ(2, entered_addresses_.size());
  ASSERT_EQ(2, entered_addresses_.count(IndirectFunctionA));
}

TEST_F(ParseEngineEtwTest, MultiThreadWithoutDetach) {
  ASSERT_NO_FATAL_FAILURE(LoadAndEnableCallTraceDll(TRACE_FLAG_BATCH_ENTER));

  ASSERT_TRUE(wait_til_enabled_());

  IndirectFunctionThread runner_a(2, IndirectThunkA);

  base::DelegateSimpleThread thread(&runner_a, "thread a");

  thread.Start();
  runner_a.Wait();

  UnloadCallTraceDll();

  runner_a.Exit();
  thread.Join();

  ASSERT_HRESULT_SUCCEEDED(controller_.Flush(NULL));
  ASSERT_NO_FATAL_FAILURE(ConsumeEventsFromTempSession());

  ASSERT_EQ(2, entered_addresses_.size());
  ASSERT_EQ(2, entered_addresses_.count(IndirectFunctionA));
}

TEST_F(ParseEngineEtwTest, TicksAgo) {
  ASSERT_NO_FATAL_FAILURE(LoadAndEnableCallTraceDll(TRACE_FLAG_BATCH_ENTER));

  ASSERT_TRUE(wait_til_enabled_());

  IndirectFunctionThread runners[] = {
      IndirectFunctionThread(1, IndirectThunkA, 10),
      IndirectFunctionThread(2, IndirectThunkB, 10),
      IndirectFunctionThread(3, IndirectThunkA, 10),
      IndirectFunctionThread(4, IndirectThunkB, 10),
      IndirectFunctionThread(5, IndirectThunkA, 10),
      IndirectFunctionThread(6, IndirectThunkB, 10) };

  base::DelegateSimpleThread threads[] = {
      base::DelegateSimpleThread(&runners[0], "thread 0"),
      base::DelegateSimpleThread(&runners[1], "thread 1"),
      base::DelegateSimpleThread(&runners[2], "thread 2"),
      base::DelegateSimpleThread(&runners[3], "thread 3"),
      base::DelegateSimpleThread(&runners[4], "thread 4"),
      base::DelegateSimpleThread(&runners[5], "thread 5")};

  for (size_t i = 0; i < sizeof(threads) / sizeof(threads[0]); ++i) {
    threads[i].Start();
    runners[i].Wait();
    ::Sleep(20);
    if (i == 1 || i == 3) {
      runners[i].Exit();
      threads[i].Join();
    }
  }

  runners[2].Exit();
  runners[4].Exit();
  threads[2].Join();
  threads[4].Join();

  UnloadCallTraceDll();

  runners[0].Exit();
  runners[5].Exit();
  threads[0].Join();
  threads[5].Join();

  ASSERT_HRESULT_SUCCEEDED(controller_.Flush(NULL));
  ASSERT_NO_FATAL_FAILURE(ConsumeEventsFromTempSession());

  ASSERT_EQ(21, entered_addresses_.size());
  ASSERT_LE(9U, entered_addresses_.count(IndirectFunctionA));
  ASSERT_LE(12U, entered_addresses_.count(IndirectFunctionB));

  std::vector<FuncAddr> call_sequence(calls_.size());
  for (Calls::iterator it = calls_.begin(); it != calls_.end(); ++it)
    call_sequence.push_back(it->address);

  std::vector<FuncAddr> expected_call_sequence(21);
  expected_call_sequence.insert(
      expected_call_sequence.end(), 1, IndirectFunctionA);
  expected_call_sequence.insert(
      expected_call_sequence.end(), 2, IndirectFunctionB);
  expected_call_sequence.insert(
      expected_call_sequence.end(), 3, IndirectFunctionA);
  expected_call_sequence.insert(
      expected_call_sequence.end(), 4, IndirectFunctionB);
  expected_call_sequence.insert(
      expected_call_sequence.end(), 5, IndirectFunctionA);
  expected_call_sequence.insert(
      expected_call_sequence.end(), 6, IndirectFunctionB);

  ASSERT_THAT(call_sequence, testing::ContainerEq(expected_call_sequence));
}

TEST_F(ParseEngineEtwTest, MultiThreadWithStopCallTrace) {
  ASSERT_NO_FATAL_FAILURE(LoadAndEnableCallTraceDll(TRACE_FLAG_BATCH_ENTER));

  ASSERT_TRUE(wait_til_enabled_());

  IndirectFunctionThread runner_a(2, IndirectThunkA);
  IndirectFunctionThread runner_b(77, IndirectThunkB);

  base::DelegateSimpleThread thread_a(&runner_a, "thread a");
  base::DelegateSimpleThread thread_b(&runner_b, "thread b");

  thread_a.Start();
  thread_b.Start();
  runner_a.Wait();
  runner_b.Wait();

  // Disable the provider and wait for it to notice,
  // then make sure we got all the events we expected.
  ASSERT_HRESULT_SUCCEEDED(controller_.DisableProvider(kCallTraceProvider));
  ASSERT_TRUE(wait_til_disabled_());

  ASSERT_HRESULT_SUCCEEDED(controller_.Stop(NULL));
  ASSERT_NO_FATAL_FAILURE(ConsumeEventsFromTempSession());

  UnloadCallTraceDll();
  runner_a.Exit();
  runner_b.Exit();
  thread_a.Join();
  thread_b.Join();

  ASSERT_EQ(2, entered_addresses_.count(IndirectFunctionA));
  ASSERT_EQ(77, entered_addresses_.count(IndirectFunctionB));
}

namespace {

void __declspec(naked) RecursiveFunction(int depth) {
  __asm {
    call ParseEngineEtwTest::_penter_

    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi
  }

  if (depth > 0)
    RecursiveFunction(depth - 1);

  __asm {
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret
  }
}

void __declspec(naked) TailRecursiveFunction(int depth) {
  __asm {
    call ParseEngineEtwTest::_penter_

    // Test depth for zero and exit if so.
    mov eax, DWORD PTR[esp + 4]
    test eax, eax
    jz done

    // Subtract one and "recurse".
    dec eax
    mov DWORD PTR[esp + 4], eax
    jmp TailRecursiveFunction

  done:
    ret
  }
}

}  // namespace

TEST_F(ParseEngineEtwTest, EnterExitRecursive) {
  ASSERT_NO_FATAL_FAILURE(
      LoadAndEnableCallTraceDll(TRACE_FLAG_ENTER | TRACE_FLAG_EXIT));

  // Call the recursive function.
  RecursiveFunction(10);

  // Disable the provider and wait for it to notice,
  // then make sure we got all the events we expected.
  ASSERT_HRESULT_SUCCEEDED(controller_.DisableProvider(kCallTraceProvider));
  ASSERT_TRUE(wait_til_disabled_());

  ASSERT_HRESULT_SUCCEEDED(controller_.Stop(NULL));

  ASSERT_NO_FATAL_FAILURE(ConsumeEventsFromTempSession());

  EXPECT_EQ(11, entered_addresses_.size());
  EXPECT_EQ(11, exited_addresses_.size());
}

TEST_F(ParseEngineEtwTest, EnterExitTailRecursive) {
  ASSERT_NO_FATAL_FAILURE(
      LoadAndEnableCallTraceDll(TRACE_FLAG_ENTER | TRACE_FLAG_EXIT));

  // Call the tail recursive function.
  TailRecursiveFunction(5);

  // Disable the provider and wait for it to notice,
  // then make sure we got all the events we expected.
  ASSERT_HRESULT_SUCCEEDED(controller_.DisableProvider(kCallTraceProvider));
  ASSERT_TRUE(wait_til_disabled_());

  ASSERT_HRESULT_SUCCEEDED(controller_.Stop(NULL));
  ASSERT_NO_FATAL_FAILURE(ConsumeEventsFromTempSession());

  EXPECT_EQ(6, entered_addresses_.size());
  EXPECT_EQ(6, exited_addresses_.size());
}

namespace {

// Count the number of entries/exits.
int bottom_entry = 0;
int bottom_exit = 0;

// The danger with exceptions is in the shadow stack maintained by the
// call trace DLL. On exception, some of the entries on the shadow stack
// may become orphaned, which can cause the call trace DLL to pop the wrong
// entry, and return to the wrong function.
__declspec(naked) void ExceptionTestBottom(int depth, int throw_depth) {
  __asm {
    call ParseEngineEtwTest::_penter_

    push ebp
    mov ebp, esp
    sub esp, __LOCAL_SIZE
    push ebx
    push esi
    push edi
  }

  ++bottom_entry;

  if (depth > 0)
    ExceptionTestBottom(depth - 1, throw_depth);

  ++bottom_exit;

  // When we throw, some of the shadow stack entries are orphaned.
  if (depth == throw_depth)
    ::RaiseException(0xBADF00D, 0, 0, NULL);

  __asm {
    pop edi
    pop esi
    pop ebx
    mov esp, ebp
    pop ebp
    ret
  }
}

bool ExceptionTestRecurseRaiseAndReturn() {
  __try {
    ExceptionTestBottom(10, 4);
  } __except(EXCEPTION_EXECUTE_HANDLER) {
    return GetExceptionCode() == 0xBADF00D;
  }

  return false;
}

// Count the number of entries/exits.
int top_entry = 0;
int top_exit = 0;

__declspec(naked) void RecurseAndCall(int depth, bool (*func)()) {
  __asm {
    call ParseEngineEtwTest::_penter_

    push ebp
    mov ebp, esp
    sub esp, __LOCAL_SIZE
    push ebx
    push esi
    push edi
  }

  ++top_entry;

  if (depth == 0) {
    EXPECT_TRUE(func());
  } else {
    RecurseAndCall(depth - 1, func);
  }

  ++top_exit;

  __asm {
    pop edi
    pop esi
    pop ebx
    mov esp, ebp
    pop ebp
    ret
  }
}

void ExceptionTestReturnAfterException(int depth) {
  RecurseAndCall(depth, ExceptionTestRecurseRaiseAndReturn);
}

}  // namespace

// Return immediately after taking an exception (which leaves orphaned
// entries on the shadow stack).
TEST_F(ParseEngineEtwTest, EnterExitReturnAfterException) {
  top_entry = 0;
  top_exit = 0;
  bottom_entry = 0;
  bottom_exit = 0;

  ASSERT_NO_FATAL_FAILURE(
      LoadAndEnableCallTraceDll(TRACE_FLAG_ENTER | TRACE_FLAG_EXIT));

  ExceptionTestReturnAfterException(10);

  // Disable the provider and wait for it to notice,
  // then make sure we got all the events we expected.
  ASSERT_HRESULT_SUCCEEDED(controller_.DisableProvider(kCallTraceProvider));
  ASSERT_TRUE(wait_til_disabled_());

  ASSERT_HRESULT_SUCCEEDED(controller_.Stop(NULL));

  EXPECT_EQ(11, top_entry);
  EXPECT_EQ(11, top_exit);

  EXPECT_EQ(11, bottom_entry);
  EXPECT_EQ(5, bottom_exit);
}

namespace {

bool ExceptionTestRecurseRaiseAndCall() {
  __try {
    ExceptionTestBottom(10, 4);
  } __except(EXCEPTION_EXECUTE_HANDLER) {
    RecursiveFunction(10);
    return true;
  }

  return false;
}

void ExceptionTestCallAfterException(int depth) {
  RecurseAndCall(depth, ExceptionTestRecurseRaiseAndCall);
}

}  // namespace

// Call immediately after taking an exception (which leaves orphaned
// entries on the shadow stack).
TEST_F(ParseEngineEtwTest, EnterExitCallAfterException) {
  top_entry = 0;
  top_exit = 0;
  bottom_entry = 0;
  bottom_exit = 0;

  ASSERT_NO_FATAL_FAILURE(
      LoadAndEnableCallTraceDll(TRACE_FLAG_ENTER | TRACE_FLAG_EXIT));

  ExceptionTestCallAfterException(10);

  // Disable the provider and wait for it to notice,
  // then make sure we got all the events we expected.
  ASSERT_HRESULT_SUCCEEDED(controller_.DisableProvider(kCallTraceProvider));
  ASSERT_TRUE(wait_til_disabled_());

  ASSERT_HRESULT_SUCCEEDED(controller_.Stop(NULL));

  EXPECT_EQ(11, top_entry);
  EXPECT_EQ(11, top_exit);

  EXPECT_EQ(11, bottom_entry);
  EXPECT_EQ(5, bottom_exit);
}

namespace {

void __declspec(naked) TailRecurseAndCall(int depth, bool (*func)()) {
  __asm {
    call ParseEngineEtwTest::_penter_

    // Test depth for zero and exit if so.
    mov eax, DWORD PTR[esp + 4]
    test eax, eax
    jz done

    // Subtract one and "recurse".
    dec eax
    mov DWORD PTR[esp + 4], eax
    jmp TailRecurseAndCall

  done:
    mov eax, DWORD PTR[esp + 8]
    call eax
    ret
  }
}

void ExceptionTestCallAfterTailRecurseException(int depth) {
  TailRecurseAndCall(depth, ExceptionTestRecurseRaiseAndCall);
}

}  // namespace

TEST_F(ParseEngineEtwTest, EnterExitCallAfterTailRecurseException) {
  top_entry = 0;
  top_exit = 0;
  bottom_entry = 0;
  bottom_exit = 0;

  ASSERT_NO_FATAL_FAILURE(
      LoadAndEnableCallTraceDll(TRACE_FLAG_ENTER | TRACE_FLAG_EXIT));

  ExceptionTestCallAfterTailRecurseException(10);

  // Disable the provider and wait for it to notice,
  // then make sure we got all the events we expected.
  ASSERT_HRESULT_SUCCEEDED(controller_.DisableProvider(kCallTraceProvider));
  ASSERT_TRUE(wait_til_disabled_());

  ASSERT_HRESULT_SUCCEEDED(controller_.Stop(NULL));

  EXPECT_EQ(11, bottom_entry);
  EXPECT_EQ(5, bottom_exit);

  ASSERT_NO_FATAL_FAILURE(ConsumeEventsFromTempSession());

  // Verify that the tail call exits were recorded.
  EXPECT_EQ(33, entered_addresses_.size());
  EXPECT_EQ(26, exited_addresses_.size());
}
