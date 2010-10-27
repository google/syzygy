// Copyright 2010 Google Inc.
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
#include "base/event_trace_consumer_win.h"
#include "base/event_trace_controller_win.h"
#include "base/file_path.h"
#include "base/file_util.h"
#include "base/logging.h"
#include "base/scoped_handle.h"
#include "base/simple_thread.h"
#include "base/win/windows_version.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "sawbuck/call_trace/call_trace_parser.h"
#include <map>
#include <windows.h>

namespace {

typedef std::pair<base::Time, FuncAddr> Call;
typedef std::multiset<FuncAddr> CalledAddresses;
typedef std::multiset<Call> Calls;

class TestCallTraceConsumer
    : public EtwTraceConsumerBase<TestCallTraceConsumer>,
      public CallTraceEvents {
 public:
  TestCallTraceConsumer() : process_id_(::GetCurrentProcessId()) {
    CHECK(consumer_ == NULL);
    consumer_ = this;
    call_trace_parser_.set_call_trace_event_sink(this);
  }

  ~TestCallTraceConsumer() {
    consumer_ = NULL;
  }

  void OnEvent(PEVENT_TRACE event) {
    DWORD process_id = event->Header.ProcessId;

    if (process_id_ != process_id) {
      return;
    }

    call_trace_parser_.ProcessOneEvent(event);
  }

  // CallTraceEvents implementation.
  static VOID WINAPI ProcessEvent(PEVENT_TRACE event) {
    consumer_->OnEvent(event);
  }

  virtual void OnTraceEntry(base::Time time,
                            DWORD process_id,
                            DWORD thread_id,
                            const TraceEnterExitEventData* data) {
    NOTREACHED();
  }

  virtual void OnTraceExit(base::Time time,
                          DWORD process_id,
                          DWORD thread_id,
                          const TraceEnterExitEventData* data) {
    NOTREACHED();
  }

  virtual void OnTraceBatchEnter(base::Time time,
                                 DWORD process_id,
                                 DWORD thread_id,
                                 const TraceBatchEnterData* data) {
    for (size_t i = 0; i < data->num_calls; ++i) {
      called_addresses_.insert(data->calls[i].function);
      calls_.insert(Call(
          time - base::TimeDelta::FromMilliseconds(data->calls[i].ticks_ago),
          data->calls[i].function));
    }
  }

  void GetCalledAddresses(CalledAddresses* called_addresses) {
    ASSERT_TRUE(called_addresses != NULL);
    called_addresses_.swap(*called_addresses);
  }
  void GetCalls(Calls* calls) {
    ASSERT_TRUE(calls != NULL);
    calls_.swap(*calls);
  }

 private:
  CallTraceParser call_trace_parser_;
  static TestCallTraceConsumer *consumer_;
  DWORD process_id_;
  CalledAddresses called_addresses_;
  Calls calls_;
};

TestCallTraceConsumer *TestCallTraceConsumer::consumer_ = NULL;
const wchar_t* const kTestSessionName = L"TestLogSession";

// We run events through a file session to assert that
// the content comes through.
class CallTraceDllTest: public testing::Test {
 public:
   CallTraceDllTest()
       : module_(NULL),
         wait_til_disabled_(NULL),
         wait_til_enabled_(NULL),
         is_private_session_(false) {
  }

  virtual void SetUp() {
    EtwTraceProperties properties;
    EtwTraceController::Stop(kTestSessionName, &properties);
    // Construct a temp file name.
    ASSERT_TRUE(file_util::CreateTemporaryFile(&temp_file_));
    ASSERT_EQ(NULL, ::GetModuleHandle(L"CallTrace.dll"));

    // Set up a file session.
    HRESULT hr = controller_.StartFileSession(kTestSessionName,
                                             temp_file_.value().c_str());
    if (hr == E_ACCESSDENIED &&
        base::win::GetVersion() >= base::win::VERSION_VISTA) {
      // Try a private session if we're running on Vista or better.
      EtwTraceProperties prop;
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
    EXPECT_TRUE(file_util::Delete(temp_file_, false));
    EtwTraceProperties properties;
    EtwTraceController::Stop(kTestSessionName, &properties);
    UnloadCallTraceDll();
  }

  HRESULT ConsumeEventsFromTempSession() {
    // Now consume the event(s).
    TestCallTraceConsumer consumer_;
    HRESULT hr = consumer_.OpenFileSession(temp_file_.value().c_str());
    if (SUCCEEDED(hr))
      hr = consumer_.Consume();
    consumer_.Close();
    // And nab the result.
    called_addresses_.clear();
    calls_.clear();
    consumer_.GetCalledAddresses(&called_addresses_);
    consumer_.GetCalls(&calls_);
    return hr;
  }

  void LoadAndEnableCallTraceDll() {
    // For a private ETW session, a provider must be
    // registered before it's enabled.
    if (is_private_session_) {
      ASSERT_NO_FATAL_FAILURE(LoadCallTraceDll());
    }

    ASSERT_HRESULT_SUCCEEDED(
        controller_.EnableProvider(kCallTraceProvider,
                                  CALL_TRACE_LEVEL,
                                  TRACE_FLAG_BATCH_ENTER));

    if (!is_private_session_) {
      ASSERT_NO_FATAL_FAILURE(LoadCallTraceDll());
    }
  }

  void LoadCallTraceDll() {
    ASSERT_EQ(NULL, ::GetModuleHandle(L"CallTrace.dll"));
    module_ = ::LoadLibrary(L"CallTrace.dll");
    ASSERT_TRUE(module_ != NULL);
    _indirect_penter_ = GetProcAddress(module_, "_indirect_penter");
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
      wait_til_disabled_ = NULL;
      wait_til_enabled_ = NULL;
    }
  }

  friend void thunkA();
  friend void thunkB();

 protected:
  typedef bool (*WaitFuncType)(void);
  WaitFuncType wait_til_enabled_;
  WaitFuncType wait_til_disabled_;

  EtwTraceController controller_;
  CalledAddresses called_addresses_;
  Calls calls_;

  // True iff controller_ has started a private file session.
  bool is_private_session_;

  FilePath temp_file_;
  HMODULE module_;
  static FARPROC _indirect_penter_;
};

FARPROC CallTraceDllTest::_indirect_penter_ = 0;

TEST(CallTraceDllLoadUnloadTest, ProcessAttach) {
  HMODULE module = ::LoadLibrary(L"CallTrace.dll");
  ASSERT_TRUE(module != NULL);
  ASSERT_TRUE(::FreeLibrary(module));
}

void functionA() {
  rand();
}

void __declspec(naked) thunkA() {
  __asm {
    push functionA
    jmp CallTraceDllTest::_indirect_penter_
  }
}

void functionB() {
  clock();
}

void __declspec(naked) thunkB() {
  __asm {
    push functionB
    jmp CallTraceDllTest::_indirect_penter_
  }
}

class FunctionThread : public base::DelegateSimpleThread::Delegate {
 public:
  FunctionThread(int invocation_count, void (*f)(void), DWORD delay = 0)
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
  ScopedHandle exit_event_;
  ScopedHandle done_event_;
};

}  // namespace

TEST_F(CallTraceDllTest, SingleThread) {
  ASSERT_NO_FATAL_FAILURE(LoadAndEnableCallTraceDll());

  ASSERT_TRUE(wait_til_enabled_());

  thunkA();
  thunkA();
  thunkA();

  UnloadCallTraceDll();

  ASSERT_HRESULT_SUCCEEDED(controller_.Flush(NULL));
  ASSERT_HRESULT_SUCCEEDED(ConsumeEventsFromTempSession());

  ASSERT_EQ(3, called_addresses_.size());
  ASSERT_EQ(3, called_addresses_.count(functionA));
}

TEST_F(CallTraceDllTest, MultiThreadWithDetach) {
  ASSERT_NO_FATAL_FAILURE(LoadAndEnableCallTraceDll());

  ASSERT_TRUE(wait_til_enabled_());

  FunctionThread runner_a(2, thunkA);

  base::DelegateSimpleThread thread(&runner_a, "thread a");

  thread.Start();
  runner_a.Exit();
  thread.Join();

  UnloadCallTraceDll();

  ASSERT_HRESULT_SUCCEEDED(controller_.Flush(NULL));
  ASSERT_HRESULT_SUCCEEDED(ConsumeEventsFromTempSession());

  ASSERT_EQ(2, called_addresses_.size());
  ASSERT_EQ(2, called_addresses_.count(functionA));
}

TEST_F(CallTraceDllTest, MultiThreadWithoutDetach) {
  ASSERT_NO_FATAL_FAILURE(LoadAndEnableCallTraceDll());

  ASSERT_TRUE(wait_til_enabled_());

  FunctionThread runner_a(2, thunkA);

  base::DelegateSimpleThread thread(&runner_a, "thread a");

  thread.Start();
  runner_a.Wait();

  UnloadCallTraceDll();

  runner_a.Exit();
  thread.Join();

  ASSERT_HRESULT_SUCCEEDED(controller_.Flush(NULL));
  ASSERT_HRESULT_SUCCEEDED(ConsumeEventsFromTempSession());

  ASSERT_EQ(2, called_addresses_.size());
  ASSERT_EQ(2, called_addresses_.count(functionA));
}

TEST_F(CallTraceDllTest, TicksAgo) {
  ASSERT_NO_FATAL_FAILURE(LoadAndEnableCallTraceDll());

  ASSERT_TRUE(wait_til_enabled_());

  FunctionThread runners[] = {
      FunctionThread(1, thunkA, 10),
      FunctionThread(2, thunkB, 10),
      FunctionThread(3, thunkA, 10),
      FunctionThread(4, thunkB, 10),
      FunctionThread(5, thunkA, 10),
      FunctionThread(6, thunkB, 10) };

  base::DelegateSimpleThread threads[] = {
      base::DelegateSimpleThread(&runners[0], "thread 0"),
      base::DelegateSimpleThread(&runners[1], "thread 1"),
      base::DelegateSimpleThread(&runners[2], "thread 2"),
      base::DelegateSimpleThread(&runners[3], "thread 3"),
      base::DelegateSimpleThread(&runners[4], "thread 4"),
      base::DelegateSimpleThread(&runners[5], "thread 5")};

  for ( size_t i = 0; i < sizeof(threads) / sizeof(threads[0]); ++i ){
    threads[i].Start();
    runners[i].Wait();
    ::Sleep(20);
    if ( i == 1 || i == 3 ){
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
  ASSERT_HRESULT_SUCCEEDED(ConsumeEventsFromTempSession());

  ASSERT_EQ(21, called_addresses_.size());
  ASSERT_LE(9U, called_addresses_.count(functionA));
  ASSERT_LE(12U, called_addresses_.count(functionB));

  std::vector<FuncAddr> call_sequence(calls_.size());
  for (Calls::iterator it = calls_.begin(); it != calls_.end(); ++it)
    call_sequence.push_back(it->second);

  std::vector<FuncAddr> expected_call_sequence(21);
  expected_call_sequence.insert(expected_call_sequence.end(), 1, functionA);
  expected_call_sequence.insert(expected_call_sequence.end(), 2, functionB);
  expected_call_sequence.insert(expected_call_sequence.end(), 3, functionA);
  expected_call_sequence.insert(expected_call_sequence.end(), 4, functionB);
  expected_call_sequence.insert(expected_call_sequence.end(), 5, functionA);
  expected_call_sequence.insert(expected_call_sequence.end(), 6, functionB);

  ASSERT_THAT(call_sequence, testing::ContainerEq(expected_call_sequence));
}

TEST_F(CallTraceDllTest, MultiThreadWithStopCallTrace) {
  ASSERT_NO_FATAL_FAILURE(LoadAndEnableCallTraceDll());

  ASSERT_TRUE(wait_til_enabled_());

  FunctionThread runner_a(2, thunkA);
  FunctionThread runner_b(77, thunkB);

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
  ASSERT_HRESULT_SUCCEEDED(ConsumeEventsFromTempSession());

  UnloadCallTraceDll();
  runner_a.Exit();
  runner_b.Exit();
  thread_a.Join();
  thread_b.Join();

  ASSERT_EQ(2, called_addresses_.count(functionA));
  ASSERT_EQ(77, called_addresses_.count(functionB));
}
