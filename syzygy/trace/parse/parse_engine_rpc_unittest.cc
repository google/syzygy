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

#include "syzygy/trace/parse/parse_engine_rpc.h"

#include <windows.h>

#include <list>
#include <map>

#include "base/environment.h"
#include "base/file_util.h"
#include "base/lazy_instance.h"
#include "base/logging.h"
#include "base/stringprintf.h"
#include "base/utf_string_conversions.h"
#include "base/files/file_path.h"
#include "base/memory/scoped_vector.h"
#include "base/threading/simple_thread.h"
#include "base/win/event_trace_consumer.h"
#include "base/win/event_trace_controller.h"
#include "base/win/scoped_handle.h"
#include "base/win/windows_version.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/pe/unittest_util.h"
#include "syzygy/trace/common/unittest_util.h"
#include "syzygy/trace/parse/parser.h"
#include "syzygy/trace/service/process_info.h"

namespace trace {
namespace service {
namespace {

using ::trace::parser::Parser;
using ::trace::parser::ParseEventHandlerImpl;

static const uint32 kConstantInThisModule = 0;

enum CallEntryType {
  kCallEntry,
  kCallExit,
};

struct Call {
  base::Time entry;
  size_t relative_order;
  DWORD thread_id;
  FuncAddr address;
  CallEntryType type;
};

struct ModuleEvent {
  base::Time entry;
  DWORD thread_id;
  TraceModuleData data;
  DWORD type;
};

bool operator<(const Call& a, const Call& b) {
  if (a.entry < b.entry)
    return true;
  if (a.entry > b.entry)
    return false;

  if (a.relative_order < b.relative_order)
    return true;
  if (a.relative_order > b.relative_order)
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
typedef std::vector<Call> RawCalls;
typedef RawCalls::iterator RawCallsIter;
typedef std::multiset<Call> OrderedCalls;
typedef OrderedCalls::iterator OrderedCallsIter;
typedef std::list<ModuleEvent> ModuleEvents;

class TestParseEventHandler : public ParseEventHandlerImpl {
 public:
  TestParseEventHandler(): process_id_(::GetCurrentProcessId()), event_id_(0) {
  }

  ~TestParseEventHandler() {
  }

  virtual void OnFunctionEntry(base::Time time,
                               DWORD process_id,
                               DWORD thread_id,
                               const TraceEnterExitEventData* data) {
    entered_addresses_.insert(data->function);
    Call call = { time, event_id_++, thread_id, data->function, kCallEntry };
    raw_calls_.push_back(call);
    ordered_calls_.insert(call);
  }

  virtual void OnFunctionExit(base::Time time,
                              DWORD process_id,
                              DWORD thread_id,
                              const TraceEnterExitEventData* data) {
    exited_addresses_.insert(data->function);
    Call call = { time, event_id_++, thread_id, data->function, kCallExit };
    raw_calls_.push_back(call);
    ordered_calls_.insert(call);
  }

  virtual void OnBatchFunctionEntry(base::Time time,
                                    DWORD process_id,
                                    DWORD thread_id,
                                    const TraceBatchEnterData* data) {
    for (size_t i = 0; i < data->num_calls; ++i) {
      entered_addresses_.insert(data->calls[i].function);
      Call call = { time, event_id_++, thread_id, data->calls[i].function,
                    kCallEntry };
      raw_calls_.push_back(call);
      ordered_calls_.insert(call);
    }
  }

  virtual void OnProcessAttach(base::Time time,
                               DWORD process_id,
                               DWORD thread_id,
                               const TraceModuleData* data) {
    ModuleEvent event = { time, thread_id, *data, DLL_PROCESS_ATTACH };
    module_events_.push_back(event);
  }

  virtual void OnProcessDetach(base::Time time,
                               DWORD process_id,
                               DWORD thread_id,
                               const TraceModuleData* data) {
    ModuleEvent event = { time, thread_id, *data, DLL_PROCESS_DETACH };
    module_events_.push_back(event);
  }

  virtual void OnThreadAttach(base::Time time,
                              DWORD process_id,
                              DWORD thread_id,
                              const TraceModuleData* data) {
    ModuleEvent event = { time, thread_id, *data, DLL_THREAD_ATTACH };
    module_events_.push_back(event);
  }

  virtual void OnThreadDetach(base::Time time,
                              DWORD process_id,
                              DWORD thread_id,
                              const TraceModuleData* data) {
    ModuleEvent event = { time, thread_id, *data, DLL_THREAD_DETACH };
    module_events_.push_back(event);
  }

  virtual void OnInvocationBatch(base::Time time,
                                 DWORD process_id,
                                 DWORD thread_id,
                                 size_t num_invocations,
                                 const TraceBatchInvocationInfo* data) {
    ADD_FAILURE() << "Unexpected event.";
  }

  virtual void OnThreadName(base::Time time,
                            DWORD process_id,
                            DWORD thread_id,
                            const base::StringPiece& thread_name) {
    ADD_FAILURE() << "Unexpected event.";
  }

  virtual void OnIndexedFrequency(
      base::Time time,
      DWORD process_id,
      DWORD thread_id,
      const TraceIndexedFrequencyData* data) {
    ADD_FAILURE() << "Unexpected event.";
  }

  void GetEnteredAddresses(CalledAddresses* entered_addresses) {
    ASSERT_TRUE(entered_addresses != NULL);
    entered_addresses_.swap(*entered_addresses);
  }

  void GetExitedAddresses(CalledAddresses* exited_addresses) {
    ASSERT_TRUE(exited_addresses != NULL);
    exited_addresses_.swap(*exited_addresses);
  }

  void GetRawCalls(RawCalls* calls) {
    ASSERT_TRUE(calls != NULL);
    raw_calls_.swap(*calls);
  }

  void GetOrderedCalls(OrderedCalls* calls) {
    ASSERT_TRUE(calls != NULL);
    ordered_calls_.swap(*calls);
  }

  void GetModuleEvents(ModuleEvents* module_events) {
    ASSERT_TRUE(module_events != NULL);
    module_events_.swap(*module_events);
  }

 private:
  DWORD process_id_;
  DWORD event_id_;  // Used to conserve relative ordering of calls.
  ModuleEvents module_events_;
  CalledAddresses entered_addresses_;
  CalledAddresses exited_addresses_;
  RawCalls raw_calls_;
  OrderedCalls ordered_calls_;
};

const wchar_t* const kTestSessionName = L"TestLogSession";

typedef BOOL (WINAPI *DllMainFunc)(HMODULE module,
                                   DWORD reason,
                                   LPVOID reserved);

extern const DllMainFunc IndirectThunkDllMain;

// We run events through a file session to assert that
// the content comes through.
class ParseEngineRpcTest: public testing::PELibUnitTest {
 public:
  typedef testing::PELibUnitTest Super;

  ParseEngineRpcTest() : module_(NULL) {
  }

  bool FindTraceFile(base::FilePath* trace_file_path) {
    DCHECK(trace_file_path != NULL);
    file_util::FileEnumerator enumerator(temp_dir_, false,
                                         file_util::FileEnumerator::FILES,
                                         L"trace-*.bin");
    *trace_file_path = enumerator.Next();
    return !trace_file_path->empty() && enumerator.Next().empty();
  }

  virtual void SetUp() {
    Super::SetUp();

    // Create a temporary directory for the call trace files.
    ASSERT_NO_FATAL_FAILURE(CreateTemporaryDir(&temp_dir_));

    ASSERT_NO_FATAL_FAILURE(service_.SetEnvironment());

    // The call trace DLL should not be already loaded.
    ASSERT_EQ(NULL, ::GetModuleHandle(L"call_trace_client.dll"));
  }

  virtual void TearDown() {
    UnloadCallTraceDll();
    StopCallTraceService();
    Super::TearDown();
  }

  void StartCallTraceService() {
    service_.Start(temp_dir_);
  }

  void StopCallTraceService() {
    service_.Stop();
  }

  void ConsumeEventsFromTempSession() {
    // Stop the call trace service to ensure all buffers have been flushed.
    ASSERT_NO_FATAL_FAILURE(StopCallTraceService());

    // Parse the call trace log.
    TestParseEventHandler consumer;
    Parser parser;
    ASSERT_TRUE(parser.Init(&consumer));
    base::FilePath trace_file_path;
    ASSERT_TRUE(FindTraceFile(&trace_file_path));
    ASSERT_TRUE(parser.OpenTraceFile(trace_file_path));
    ASSERT_TRUE(parser.Consume());

    // Get the information for this process.
    uint32 pid = ::GetCurrentProcessId();
    trace::service::ProcessInfo process_info;
    ASSERT_TRUE(process_info.Initialize(pid));

    // Look up this process in the process map.
    trace::parser::AbsoluteAddress64 addr =
        reinterpret_cast<uint32>(&kConstantInThisModule);
    const trace::parser::ModuleInformation* module_info =
        parser.GetModuleInformation(pid, addr);

    // An entry should exist for this process, and it should match our
    // process info.
    ASSERT_TRUE(module_info != NULL);
    ASSERT_EQ(process_info.executable_path,
              base::FilePath(module_info->path));
    ASSERT_EQ(process_info.exe_base_address, module_info->base_address.value());
    ASSERT_EQ(process_info.exe_image_size, module_info->module_size);
    ASSERT_EQ(process_info.exe_checksum, module_info->module_checksum);
    ASSERT_EQ(process_info.exe_time_date_stamp,
              module_info->module_time_date_stamp);

    // And extract the results.
    entered_addresses_.clear();
    exited_addresses_.clear();
    raw_calls_.clear();
    ordered_calls_.clear();
    consumer.GetModuleEvents(&module_events_);
    consumer.GetEnteredAddresses(&entered_addresses_);
    consumer.GetExitedAddresses(&exited_addresses_);
    consumer.GetRawCalls(&raw_calls_);
    consumer.GetOrderedCalls(&ordered_calls_);
  }

  void LoadCallTraceDll() {
    ASSERT_TRUE(module_ == NULL);
    const wchar_t* call_trace_dll = L"call_trace_client.dll";
    ASSERT_EQ(NULL, ::GetModuleHandle(call_trace_dll));
    module_ = ::LoadLibrary(call_trace_dll);
    ASSERT_TRUE(module_ != NULL);
    _indirect_penter_dllmain_ =
        GetProcAddress(module_, "_indirect_penter_dllmain");
    _indirect_penter_ = GetProcAddress(module_, "_indirect_penter");

    ASSERT_TRUE(_indirect_penter_dllmain_ != NULL);
    ASSERT_TRUE(_indirect_penter_ != NULL);
  }

  void UnloadCallTraceDll() {
    if (module_ != NULL) {
      ASSERT_TRUE(::FreeLibrary(module_));
      module_ = NULL;
      _indirect_penter_ = NULL;
      _indirect_penter_dllmain_ = NULL;
    }
  }

  friend void IndirectThunkDllMainImpl();
  friend void IndirectThunkA();
  friend void IndirectThunkB();

 protected:
  // Our call trace service instance.
  testing::CallTraceService service_;

  // The directory where trace file output will be written.
  base::FilePath temp_dir_;

  // @name Book-keeping for the tests.
  // @{
  CalledAddresses entered_addresses_;
  CalledAddresses exited_addresses_;
  RawCalls raw_calls_;
  OrderedCalls ordered_calls_;
  ModuleEvents module_events_;
  // @}

  HMODULE module_;
  static FARPROC _indirect_penter_;
  static FARPROC _indirect_penter_dllmain_;
};

FARPROC ParseEngineRpcTest::_indirect_penter_dllmain_ = 0;
FARPROC ParseEngineRpcTest::_indirect_penter_ = 0;

static BOOL WINAPI IndirectDllMain(HMODULE module,
                                   DWORD reason,
                                   LPVOID reserved) {
  return TRUE;
}

void __declspec(naked) IndirectThunkDllMainImpl() {
  __asm {
    push IndirectDllMain
    jmp ParseEngineRpcTest::_indirect_penter_dllmain_
  }
}

const DllMainFunc IndirectThunkDllMain =
    reinterpret_cast<const DllMainFunc>(&IndirectThunkDllMainImpl);

void IndirectFunctionA() {
  rand();
}

void __declspec(naked) IndirectThunkA() {
  __asm {
    push IndirectFunctionA
    jmp ParseEngineRpcTest::_indirect_penter_
  }
}

void IndirectFunctionB() {
  clock();
}

void __declspec(naked) IndirectThunkB() {
  __asm {
    push IndirectFunctionB
    jmp ParseEngineRpcTest::_indirect_penter_
  }
}

class IndirectFunctionThread : public base::DelegateSimpleThread::Delegate {
 public:
  IndirectFunctionThread(int invocation_count, void (*f)(void), HMODULE module,
                         DWORD delay = 0)
      : invocation_count_(invocation_count), f_(f), module_(module),
        delay_(delay), thread_detach_(true) {
    exit_event_.Set(::CreateEvent(NULL, TRUE, FALSE, NULL));
    CHECK(exit_event_);
    done_event_.Set(::CreateEvent(NULL, TRUE, FALSE, NULL));
    CHECK(done_event_);
  }

  void set_thread_detach(bool value) {
    thread_detach_ = value;
  }

  virtual void Run() {
    IndirectThunkDllMain(module_, DLL_THREAD_ATTACH, NULL);
    if (delay_ != 0) {
      ::Sleep(delay_);
    }
    for (int i = 0; i < invocation_count_; ++i) {
      f_();
      if (delay_ != 0) {
        ::Sleep(delay_);
      }
    }
    ::SetEvent(done_event_);
    ASSERT_EQ(WAIT_OBJECT_0, ::WaitForSingleObject(exit_event_, INFINITE));
    if (thread_detach_)
      IndirectThunkDllMain(module_, DLL_THREAD_DETACH, NULL);
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
  HMODULE module_;
  bool thread_detach_;
};

// IndirectFunctionThreads aren't copy constructible due to
// base::win::ScopedHandle member variables. Thus we have to jump
// through hoops to copy-initialize arrays of them.
typedef ScopedVector<IndirectFunctionThread> IndirectFunctionThreads;

}  // namespace

TEST_F(ParseEngineRpcTest, LoadUnload) {
  ASSERT_NO_FATAL_FAILURE(LoadCallTraceDll());
  ASSERT_NO_FATAL_FAILURE(UnloadCallTraceDll());

  base::FilePath trace_file_path;
  ASSERT_FALSE(FindTraceFile(&trace_file_path));
  ASSERT_TRUE(trace_file_path.empty());
}

TEST_F(ParseEngineRpcTest, NoServiceInstance) {
  ASSERT_NO_FATAL_FAILURE(LoadCallTraceDll());

  IndirectThunkDllMain(module_, DLL_PROCESS_ATTACH, this);
  IndirectThunkA();
  IndirectThunkA();
  IndirectThunkA();
  IndirectThunkDllMain(module_, DLL_PROCESS_DETACH, this);

  ASSERT_NO_FATAL_FAILURE(UnloadCallTraceDll());

  base::FilePath trace_file_path;
  ASSERT_FALSE(FindTraceFile(&trace_file_path));
  ASSERT_TRUE(trace_file_path.empty());
}

TEST_F(ParseEngineRpcTest, NoSessionCreated) {
  ASSERT_NO_FATAL_FAILURE(StartCallTraceService());

  ASSERT_NO_FATAL_FAILURE(LoadCallTraceDll());

  ASSERT_NO_FATAL_FAILURE(UnloadCallTraceDll());

  base::FilePath trace_file_path;
  ASSERT_FALSE(FindTraceFile(&trace_file_path));
  ASSERT_TRUE(trace_file_path.empty());
}

TEST_F(ParseEngineRpcTest, SingleThread) {
  ASSERT_NO_FATAL_FAILURE(StartCallTraceService());

  ASSERT_NO_FATAL_FAILURE(LoadCallTraceDll());

  IndirectThunkDllMain(module_, DLL_PROCESS_ATTACH, this);
  IndirectThunkA();
  IndirectThunkA();
  IndirectThunkA();
  IndirectThunkDllMain(module_, DLL_PROCESS_DETACH, this);

  ASSERT_NO_FATAL_FAILURE(UnloadCallTraceDll());

  ASSERT_NO_FATAL_FAILURE(ConsumeEventsFromTempSession());

  ASSERT_EQ(5, entered_addresses_.size());
  ASSERT_EQ(3, entered_addresses_.count(IndirectFunctionA));
  ASSERT_EQ(2, entered_addresses_.count(IndirectDllMain));
}

TEST_F(ParseEngineRpcTest, MultiThreadWithDetach) {
  ASSERT_NO_FATAL_FAILURE(StartCallTraceService());

  ASSERT_NO_FATAL_FAILURE(LoadCallTraceDll());

  IndirectThunkDllMain(module_, DLL_PROCESS_ATTACH, this);
  IndirectFunctionThread runner_a(2, IndirectThunkA, module_);

  base::DelegateSimpleThread thread(&runner_a, "thread a");

  thread.Start();
  runner_a.Exit();
  thread.Join();

  IndirectThunkDllMain(module_, DLL_PROCESS_DETACH, this);

  ASSERT_NO_FATAL_FAILURE(UnloadCallTraceDll());

  ASSERT_NO_FATAL_FAILURE(ConsumeEventsFromTempSession());

  ASSERT_EQ(6, entered_addresses_.size());
  ASSERT_EQ(4, entered_addresses_.count(IndirectDllMain));
  ASSERT_EQ(2, entered_addresses_.count(IndirectFunctionA));
}

TEST_F(ParseEngineRpcTest, MultiThreadWithoutDetach) {
  ASSERT_NO_FATAL_FAILURE(StartCallTraceService());

  ASSERT_NO_FATAL_FAILURE(LoadCallTraceDll());

  IndirectFunctionThread runner_a(2, IndirectThunkA, module_);
  runner_a.set_thread_detach(false);
  base::DelegateSimpleThread thread(&runner_a, "thread a");

  thread.Start();
  runner_a.Wait();

  ASSERT_NO_FATAL_FAILURE(UnloadCallTraceDll());

  runner_a.Exit();
  thread.Join();

  ASSERT_NO_FATAL_FAILURE(ConsumeEventsFromTempSession());

  ASSERT_EQ(3, entered_addresses_.size());
  ASSERT_EQ(2, entered_addresses_.count(IndirectFunctionA));
  ASSERT_EQ(1, entered_addresses_.count(IndirectDllMain));
}

TEST_F(ParseEngineRpcTest, RawCallSequence) {
  ASSERT_NO_FATAL_FAILURE(StartCallTraceService());

  ASSERT_NO_FATAL_FAILURE(LoadCallTraceDll());

  IndirectFunctionThreads runners;
  runners.push_back(
      new IndirectFunctionThread(1, IndirectThunkA, module_, 10));
  runners.push_back(
      new IndirectFunctionThread(2, IndirectThunkB, module_, 10));
  runners.push_back(
      new IndirectFunctionThread(3, IndirectThunkA, module_, 10));
  runners.push_back(
      new IndirectFunctionThread(4, IndirectThunkB, module_, 10));
  runners.push_back(
      new IndirectFunctionThread(5, IndirectThunkA, module_, 10));
  runners.push_back(
      new IndirectFunctionThread(6, IndirectThunkB, module_, 10));

  runners[0]->set_thread_detach(false);
  runners[5]->set_thread_detach(false);

  base::DelegateSimpleThread threads[] = {
      base::DelegateSimpleThread(runners[0], "thread 0"),
      base::DelegateSimpleThread(runners[1], "thread 1"),
      base::DelegateSimpleThread(runners[2], "thread 2"),
      base::DelegateSimpleThread(runners[3], "thread 3"),
      base::DelegateSimpleThread(runners[4], "thread 4"),
      base::DelegateSimpleThread(runners[5], "thread 5")};

  std::vector<FuncAddr> expected_call_sequence;
  for (size_t i = 0; i < arraysize(threads); ++i) {
    // Thread i makes calls IndirectDllMain here and makes all of its calls to
    // IndirectFunctionA/B, but nothing gets committed yet.
    threads[i].Start();
    runners[i]->Wait();
    ::Sleep(20);

    if (i == 1 || i == 3) {
      // Threads i==1 and i==3 detach here. This commits their i+1 calls to
      // IndirectFunctionB sandwiched between their 2 call to IndirectDllMain.
      runners[i]->Exit();
      threads[i].Join();
      expected_call_sequence.push_back(IndirectDllMain);
      expected_call_sequence.insert(
          expected_call_sequence.end(), i + 1, IndirectFunctionB);
      expected_call_sequence.push_back(IndirectDllMain);
    }
  }

  // Threads 2 detaches here, which commits it's 3 calls to IndirectFunctionA
  // and sandwiched between its 2 calls to IndirectDllMain.
  runners[2]->Exit();
  threads[2].Join();
  expected_call_sequence.push_back(IndirectDllMain);
  expected_call_sequence.insert(
      expected_call_sequence.end(), 3, IndirectFunctionA);
  expected_call_sequence.push_back(IndirectDllMain);

  // Threads 4 detaches here, which commits it's 5 calls to IndirectFunctionA
  // and it's 1 call to IndirectDllMain.
  runners[4]->Exit();
  threads[4].Join();
  expected_call_sequence.push_back(IndirectDllMain);
  expected_call_sequence.insert(
      expected_call_sequence.end(), 5, IndirectFunctionA);
  expected_call_sequence.push_back(IndirectDllMain);

  // Unloading the test dll commits all outstanding events already written
  // to the shared memory trace log buffers.
  UnloadCallTraceDll();

  // Threads 0 does not detach. We get its 1 call to IndirectFunctionA
  // prefaced by its initial call IndirectDllMain. No trailing call to
  // IndirectDllMain is recorded.
  runners[0]->Exit();
  threads[0].Join();
  expected_call_sequence.push_back(IndirectDllMain);
  expected_call_sequence.insert(
      expected_call_sequence.end(), 1, IndirectFunctionA);

  // Threads 5 does not detach. We get its 6 calls to IndirectFunctionB
  // prefaced by its initial call IndirectDllMain. No trailing call to
  // IndirectDllMain is recorded.
  runners[5]->Exit();
  threads[5].Join();
  expected_call_sequence.push_back(IndirectDllMain);
  expected_call_sequence.insert(
      expected_call_sequence.end(), 6, IndirectFunctionB);

  ASSERT_NO_FATAL_FAILURE(ConsumeEventsFromTempSession());

  ASSERT_EQ(31, entered_addresses_.size());
  ASSERT_EQ(9, entered_addresses_.count(IndirectFunctionA));
  ASSERT_EQ(12, entered_addresses_.count(IndirectFunctionB));
  ASSERT_EQ(10, entered_addresses_.count(IndirectDllMain));

  std::vector<FuncAddr> call_sequence;
  for (RawCallsIter it = raw_calls_.begin(); it != raw_calls_.end(); ++it)
    call_sequence.push_back(it->address);

  ASSERT_THAT(call_sequence, testing::ContainerEq(expected_call_sequence));
}

TEST_F(ParseEngineRpcTest, OrderedCallSequence) {
  ASSERT_NO_FATAL_FAILURE(StartCallTraceService());

  ASSERT_NO_FATAL_FAILURE(LoadCallTraceDll());

  DWORD delay = 30;  // milliseconds
  IndirectFunctionThreads runners;
  runners.push_back(
      new IndirectFunctionThread(1, IndirectThunkA, module_, delay));
  runners.push_back(
      new IndirectFunctionThread(2, IndirectThunkB, module_, delay));
  runners.push_back(
      new IndirectFunctionThread(3, IndirectThunkA, module_, delay));
  runners.push_back(
      new IndirectFunctionThread(4, IndirectThunkB, module_, delay));
  runners.push_back(
      new IndirectFunctionThread(5, IndirectThunkA, module_, delay));
  runners.push_back(
      new IndirectFunctionThread(6, IndirectThunkB, module_, delay));

  runners[0]->set_thread_detach(false);
  runners[5]->set_thread_detach(false);

  base::DelegateSimpleThread threads[] = {
      base::DelegateSimpleThread(runners[0], "thread 0"),
      base::DelegateSimpleThread(runners[1], "thread 1"),
      base::DelegateSimpleThread(runners[2], "thread 2"),
      base::DelegateSimpleThread(runners[3], "thread 3"),
      base::DelegateSimpleThread(runners[4], "thread 4"),
      base::DelegateSimpleThread(runners[5], "thread 5")};

  std::vector<FuncAddr> expected_call_sequence;
  for (size_t i = 0; i < arraysize(threads); ++i) {
    // Thread i calls IndirectDllMain and makes i + 1 calls to its indirect
    // function.
    threads[i].Start();
    runners[i]->Wait();
    expected_call_sequence.push_back(IndirectDllMain);
    expected_call_sequence.insert(
        expected_call_sequence.end(),
        i + 1,
        (i & 1) == 0 ? IndirectFunctionA : IndirectFunctionB);

    // Cleanly shutdown all threads except for 2 of them.
    if (i != 0 && i != 5) {
      runners[i]->Exit();
      threads[i].Join();
      expected_call_sequence.push_back(IndirectDllMain);
    }
  }

  // We can't say anything about the relative order of events across threads
  // because of the batch nature of the events. Thus, we don't attempt to create
  // staggered thread terminations.

  // Unloading the test dll commits all outstanding events already written
  // to the shared memory trace log buffers.
  UnloadCallTraceDll();

  // Threads 0 does not detach, so we don't see a closing IndirectDllMain call.
  runners[0]->Exit();
  threads[0].Join();

  // Threads 5 does not detach either.
  runners[5]->Exit();
  threads[5].Join();

  ASSERT_NO_FATAL_FAILURE(ConsumeEventsFromTempSession());

  ASSERT_EQ(31, entered_addresses_.size());
  ASSERT_EQ(9, entered_addresses_.count(IndirectFunctionA));
  ASSERT_EQ(12, entered_addresses_.count(IndirectFunctionB));
  ASSERT_EQ(10, entered_addresses_.count(IndirectDllMain));

  std::vector<FuncAddr> call_sequence;
  OrderedCallsIter it = ordered_calls_.begin();
  for (; it != ordered_calls_.end(); ++it) {
    call_sequence.push_back(it->address);
  }

  ASSERT_THAT(call_sequence, testing::ContainerEq(expected_call_sequence));
}

TEST_F(ParseEngineRpcTest, MultiThreadWithStopCallTrace) {
  ASSERT_NO_FATAL_FAILURE(StartCallTraceService());

  ASSERT_NO_FATAL_FAILURE(LoadCallTraceDll());

  IndirectFunctionThread runner_a(2, IndirectThunkA, module_);
  IndirectFunctionThread runner_b(77, IndirectThunkB, module_);

  runner_a.set_thread_detach(false);
  runner_b.set_thread_detach(false);

  base::DelegateSimpleThread thread_a(&runner_a, "thread a");
  base::DelegateSimpleThread thread_b(&runner_b, "thread b");

  thread_a.Start();
  thread_b.Start();
  runner_a.Wait();
  runner_b.Wait();

  ASSERT_NO_FATAL_FAILURE(UnloadCallTraceDll());
  runner_a.Exit();
  runner_b.Exit();
  thread_a.Join();
  thread_b.Join();

  ASSERT_NO_FATAL_FAILURE(ConsumeEventsFromTempSession());

  ASSERT_EQ(2, entered_addresses_.count(IndirectDllMain));
  ASSERT_EQ(2, entered_addresses_.count(IndirectFunctionA));
  ASSERT_EQ(77, entered_addresses_.count(IndirectFunctionB));
}

}  // namespace service
}  // namespace trace
