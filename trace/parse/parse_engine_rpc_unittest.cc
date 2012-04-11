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

#include <windows.h>

#include <list>
#include <map>

#include "base/environment.h"
#include "base/file_path.h"
#include "base/file_util.h"
#include "base/lazy_instance.h"
#include "base/logging.h"
#include "base/stringprintf.h"
#include "base/utf_string_conversions.h"
#include "base/threading/simple_thread.h"
#include "base/win/event_trace_consumer.h"
#include "base/win/event_trace_controller.h"
#include "base/win/scoped_handle.h"
#include "base/win/windows_version.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/pe/unittest_util.h"
#include "syzygy/trace/parse/parser.h"
#include "syzygy/trace/service/service.h"

using trace::parser::Parser;
using trace::parser::ParseEventHandler;
using trace::service::Service;

namespace {

static const uint32 kConstantInThisModule = 0;

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

class TestParseEventHandler : public ParseEventHandler {
 public:
  TestParseEventHandler(): process_id_(::GetCurrentProcessId()) {
  }

  ~TestParseEventHandler() {
  }

  virtual void OnProcessStarted(base::Time time,
                                DWORD process_id,
                                const TraceSystemInfo* data) {
  }

  virtual void OnProcessEnded(base::Time time, DWORD process_id) {
  }

  virtual void OnFunctionEntry(base::Time time,
                               DWORD process_id,
                               DWORD thread_id,
                               const TraceEnterExitEventData* data) {
    entered_addresses_.insert(data->function);
    Call call = { time, thread_id, data->function, kCallEntry };
    raw_calls_.push_back(call);
    ordered_calls_.insert(call);
  }

  virtual void OnFunctionExit(base::Time time,
                              DWORD process_id,
                              DWORD thread_id,
                              const TraceEnterExitEventData* data) {
    exited_addresses_.insert(data->function);
    Call call = { time, thread_id, data->function, kCallExit };
    raw_calls_.push_back(call);
    ordered_calls_.insert(call);
  }

  virtual void OnBatchFunctionEntry(base::Time time,
                                    DWORD process_id,
                                    DWORD thread_id,
                                    const TraceBatchEnterData* data) {
    for (size_t i = 0; i < data->num_calls; ++i) {
      entered_addresses_.insert(data->calls[i].function);
      uint64 timestamp = static_cast<uint64>(data->calls[i].tick_count);
      Call call = {
          base::Time::FromFileTime(bit_cast<FILETIME>(timestamp)),
          thread_id,
          data->calls[i].function,
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

  ParseEngineRpcTest()
      : cts_(Service::Instance()),
        env_(base::Environment::Create()),
        instance_id_(base::StringPrintf("%d", ::GetCurrentProcessId())),
        module_(NULL) {
  }

  bool FindTraceFile(FilePath* trace_file_path) {
    DCHECK(trace_file_path != NULL);
    file_util::FileEnumerator enumerator(temp_dir_, false,
                                         file_util::FileEnumerator::FILES,
                                         L"trace-*.bin");
    *trace_file_path = enumerator.Next();
    return !trace_file_path->empty() && enumerator.Next().empty();
  }

  virtual void SetUp() {
    Super::SetUp();

    // The call trace DLL should not be already loaded.
    ASSERT_EQ(NULL, ::GetModuleHandle(L"call_trace_client.dll"));
    ASSERT_FALSE(env_.get() == NULL);
    ASSERT_FALSE(instance_id_.empty());

    // Create a temporary directory
    CreateTemporaryDir(&temp_dir_);

    cts_.set_trace_directory(temp_dir_);
    cts_.set_instance_id(UTF8ToWide(instance_id_));
    env_->SetVar(::kSyzygyRpcInstanceIdEnvVar, instance_id_);
  }

  virtual void TearDown() {
    UnloadCallTraceDll();
    StopCallTraceService();
    Super::TearDown();
    temp_dir_.clear();
  }

  void StartCallTraceService(uint32 flags) {
    // Start the call trace service in the temporary directory.
    cts_.set_flags(flags);
    ASSERT_TRUE(cts_.Start(true));
  }

  void StopCallTraceService() {
    if (cts_.is_running()) {
      ASSERT_TRUE(cts_.Stop());
      ASSERT_FALSE(cts_.is_running());
    }
  }

  void ConsumeEventsFromTempSession() {
    // Stop the call trace service to ensure all buffers have been flushed.
    ASSERT_NO_FATAL_FAILURE(StopCallTraceService());

    // Parse the call trace log.
    TestParseEventHandler consumer;
    Parser parser;
    ASSERT_TRUE(parser.Init(&consumer));
    FilePath trace_file_path;
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
              FilePath(module_info->image_file_name));
    ASSERT_EQ(process_info.exe_base_address, module_info->base_address);
    ASSERT_EQ(process_info.exe_image_size, module_info->module_size);
    ASSERT_EQ(process_info.exe_checksum, module_info->image_checksum);
    ASSERT_EQ(process_info.exe_time_date_stamp,
              module_info->time_date_stamp);

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
  Service& cts_;
  scoped_ptr<base::Environment> env_;
  std::string instance_id_;
  CalledAddresses entered_addresses_;
  CalledAddresses exited_addresses_;
  RawCalls raw_calls_;
  OrderedCalls ordered_calls_;
  ModuleEvents module_events_;

  FilePath temp_dir_;
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

}  // namespace

TEST_F(ParseEngineRpcTest, LoadUnload) {
  ASSERT_NO_FATAL_FAILURE(LoadCallTraceDll());
  ASSERT_NO_FATAL_FAILURE(UnloadCallTraceDll());

  FilePath trace_file_path;
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

  FilePath trace_file_path;
  ASSERT_FALSE(FindTraceFile(&trace_file_path));
  ASSERT_TRUE(trace_file_path.empty());
}


TEST_F(ParseEngineRpcTest, NoSessionCreated) {
  ASSERT_NO_FATAL_FAILURE(StartCallTraceService(TRACE_FLAG_BATCH_ENTER));

  ASSERT_NO_FATAL_FAILURE(LoadCallTraceDll());

  ASSERT_NO_FATAL_FAILURE(UnloadCallTraceDll());

  FilePath trace_file_path;
  ASSERT_FALSE(FindTraceFile(&trace_file_path));
  ASSERT_TRUE(trace_file_path.empty());
}

TEST_F(ParseEngineRpcTest, SingleThread) {
  ASSERT_NO_FATAL_FAILURE(StartCallTraceService(TRACE_FLAG_BATCH_ENTER));

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
  ASSERT_NO_FATAL_FAILURE(StartCallTraceService(TRACE_FLAG_BATCH_ENTER));

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
  ASSERT_NO_FATAL_FAILURE(StartCallTraceService(TRACE_FLAG_BATCH_ENTER));

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
  ASSERT_NO_FATAL_FAILURE(StartCallTraceService(TRACE_FLAG_BATCH_ENTER));

  ASSERT_NO_FATAL_FAILURE(LoadCallTraceDll());

  IndirectFunctionThread runners[] = {
      IndirectFunctionThread(1, IndirectThunkA, module_, 10),
      IndirectFunctionThread(2, IndirectThunkB, module_, 10),
      IndirectFunctionThread(3, IndirectThunkA, module_, 10),
      IndirectFunctionThread(4, IndirectThunkB, module_, 10),
      IndirectFunctionThread(5, IndirectThunkA, module_, 10),
      IndirectFunctionThread(6, IndirectThunkB, module_, 10) };

  runners[0].set_thread_detach(false);
  runners[5].set_thread_detach(false);

  base::DelegateSimpleThread threads[] = {
      base::DelegateSimpleThread(&runners[0], "thread 0"),
      base::DelegateSimpleThread(&runners[1], "thread 1"),
      base::DelegateSimpleThread(&runners[2], "thread 2"),
      base::DelegateSimpleThread(&runners[3], "thread 3"),
      base::DelegateSimpleThread(&runners[4], "thread 4"),
      base::DelegateSimpleThread(&runners[5], "thread 5")};

  std::vector<FuncAddr> expected_call_sequence;
  for (size_t i = 0; i < arraysize(threads); ++i) {
    // Thread i makes calls IndirectDllMain here and makes all of its calls to
    // IndirectFunctionA/B, but nothing gets committed yet.
    threads[i].Start();
    runners[i].Wait();
    ::Sleep(20);

    if (i == 1 || i == 3) {
      // Threads i==1 and i==3 detach here. This commits their i+1 calls to
      // IndirectFunctionB sandwiched between their 2 call to IndirectDllMain.
      runners[i].Exit();
      threads[i].Join();
      expected_call_sequence.push_back(IndirectDllMain);
      expected_call_sequence.insert(
          expected_call_sequence.end(), i + 1, IndirectFunctionB);
      expected_call_sequence.push_back(IndirectDllMain);
    }
  }

  // Threads 2 detaches here, which commits it's 3 calls to IndirectFunctionA
  // and sandwiched between its 2 calls to IndirectDllMain.
  runners[2].Exit();
  threads[2].Join();
  expected_call_sequence.push_back(IndirectDllMain);
  expected_call_sequence.insert(
      expected_call_sequence.end(), 3, IndirectFunctionA);
  expected_call_sequence.push_back(IndirectDllMain);

  // Threads 4 detaches here, which commits it's 5 calls to IndirectFunctionA
  // and it's 1 call to IndirectDllMain.
  runners[4].Exit();
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
  runners[0].Exit();
  threads[0].Join();
  expected_call_sequence.push_back(IndirectDllMain);
  expected_call_sequence.insert(
      expected_call_sequence.end(), 1, IndirectFunctionA);

  // Threads 5 does not detach. We get its 6 calls to IndirectFunctionB
  // prefaced by its initial call IndirectDllMain. No trailing call to
  // IndirectDllMain is recorded.
  runners[5].Exit();
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
  ASSERT_NO_FATAL_FAILURE(StartCallTraceService(TRACE_FLAG_BATCH_ENTER));

  ASSERT_NO_FATAL_FAILURE(LoadCallTraceDll());

  DWORD delay = 30;  // milliseconds
  IndirectFunctionThread runners[] = {
      IndirectFunctionThread(1, IndirectThunkA, module_, delay),
      IndirectFunctionThread(2, IndirectThunkB, module_, delay),
      IndirectFunctionThread(3, IndirectThunkA, module_, delay),
      IndirectFunctionThread(4, IndirectThunkB, module_, delay),
      IndirectFunctionThread(5, IndirectThunkA, module_, delay),
      IndirectFunctionThread(6, IndirectThunkB, module_, delay) };

  runners[0].set_thread_detach(false);
  runners[5].set_thread_detach(false);

  base::DelegateSimpleThread threads[] = {
      base::DelegateSimpleThread(&runners[0], "thread 0"),
      base::DelegateSimpleThread(&runners[1], "thread 1"),
      base::DelegateSimpleThread(&runners[2], "thread 2"),
      base::DelegateSimpleThread(&runners[3], "thread 3"),
      base::DelegateSimpleThread(&runners[4], "thread 4"),
      base::DelegateSimpleThread(&runners[5], "thread 5")};

  std::vector<FuncAddr> expected_call_sequence;
  for (size_t i = 0; i < arraysize(threads); ++i) {
    // Thread i calls IndirectDllMain makes i+1 calls to its indirect function.
    threads[i].Start();
    runners[i].Wait();
    expected_call_sequence.push_back(IndirectDllMain);
    expected_call_sequence.insert(
        expected_call_sequence.end(),
        i + 1,
        (i & 1) == 0 ? IndirectFunctionA : IndirectFunctionB);

    if (i == 1 || i == 3) {
      // Threads i==1 and i==3 call IndirectDllMain here (on detach).
      runners[i].Exit();
      threads[i].Join();
      expected_call_sequence.push_back(IndirectDllMain);
    }
  }

  // Threads 2 detaches here, calling IndirectDllMain.
  runners[2].Exit();
  threads[2].Join();
  expected_call_sequence.push_back(IndirectDllMain);

  // Threads 4 detaches here, calling IndirectDllMain.
  runners[4].Exit();
  threads[4].Join();
  expected_call_sequence.push_back(IndirectDllMain);

  // Unloading the test dll commits all outstanding events already written
  // to the shared memory trace log buffers.
  UnloadCallTraceDll();

  // Threads 0 does not detach.
  runners[0].Exit();
  threads[0].Join();

  // Threads 5 does not detach.
  runners[5].Exit();
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
  ASSERT_NO_FATAL_FAILURE(StartCallTraceService(TRACE_FLAG_BATCH_ENTER));

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

namespace {

typedef void (*VoidFuncTakingInt)(int);

void RecursiveFunction(int depth);

void __declspec(naked) IndirectThunkRecursiveFunctionImpl() {
  __asm {
    push RecursiveFunction
    jmp ParseEngineRpcTest::_indirect_penter_
  }
}

VoidFuncTakingInt IndirectThunkRecursiveFunction =
    reinterpret_cast<VoidFuncTakingInt>(
        IndirectThunkRecursiveFunctionImpl);

void RecursiveFunction(int depth) {
  if (depth > 0)
    IndirectThunkRecursiveFunction(depth - 1);
}

void TailRecursiveFunction(int depth);

void __declspec(naked) IndirectThunkTailRecursiveFunctionImpl() {
  __asm {
    push TailRecursiveFunction
    jmp ParseEngineRpcTest::_indirect_penter_
  }
}

VoidFuncTakingInt IndirectThunkTailRecursiveFunction =
    reinterpret_cast<VoidFuncTakingInt>(
        IndirectThunkTailRecursiveFunctionImpl);

void __declspec(naked) TailRecursiveFunction(int depth) {
  __asm {
    // Test depth for zero and exit if so.
    mov eax, DWORD PTR[esp + 4]
    test eax, eax
    jz done

    // Subtract one and "recurse".
    dec eax
    mov DWORD PTR[esp + 4], eax
    jmp IndirectThunkTailRecursiveFunction

  done:
    ret
  }
}

}  // namespace

TEST_F(ParseEngineRpcTest, EnterExitRecursive) {
  ASSERT_NO_FATAL_FAILURE(
      StartCallTraceService(TRACE_FLAG_ENTER | TRACE_FLAG_EXIT));

  ASSERT_NO_FATAL_FAILURE(LoadCallTraceDll());

  // Call the recursive function.
  IndirectThunkRecursiveFunction(10);

  ASSERT_NO_FATAL_FAILURE(UnloadCallTraceDll());
  ASSERT_NO_FATAL_FAILURE(ConsumeEventsFromTempSession());

  EXPECT_EQ(11, entered_addresses_.size());
  EXPECT_EQ(11, exited_addresses_.size());
}

TEST_F(ParseEngineRpcTest, EnterExitTailRecursive) {
  ASSERT_NO_FATAL_FAILURE(
      StartCallTraceService(TRACE_FLAG_ENTER | TRACE_FLAG_EXIT));

  ASSERT_NO_FATAL_FAILURE(LoadCallTraceDll());

  // Call the tail recursive function.
  IndirectThunkTailRecursiveFunction(5);

  ASSERT_NO_FATAL_FAILURE(UnloadCallTraceDll());
  ASSERT_NO_FATAL_FAILURE(ConsumeEventsFromTempSession());

  EXPECT_EQ(6, entered_addresses_.size());
  EXPECT_EQ(6, exited_addresses_.size());
}

namespace {

// Count the number of entries/exits.
int bottom_entry = 0;
int bottom_exit = 0;

typedef void (*VoidFuncTakingIntInt)(int, int);

void ExceptionTestBottom(int depth, int throw_depth);

void __declspec(naked) IndirectThunkExceptionTestBottomImpl() {
  __asm {
    push ExceptionTestBottom
    jmp ParseEngineRpcTest::_indirect_penter_
  }
}

VoidFuncTakingIntInt IndirectThunkExceptionTestBottom =
    reinterpret_cast<VoidFuncTakingIntInt>(
        IndirectThunkExceptionTestBottomImpl);

// The danger with exceptions is in the shadow stack maintained by the
// call trace DLL. On exception, some of the entries on the shadow stack
// may become orphaned, which can cause the call trace DLL to pop the wrong
// entry, and return to the wrong function.
__declspec(naked) void ExceptionTestBottom(int depth, int throw_depth) {
  __asm {
    push ebp
    mov ebp, esp
    sub esp, __LOCAL_SIZE
    push ebx
    push esi
    push edi
  }

  ++bottom_entry;

  if (depth > 0)
    IndirectThunkExceptionTestBottom(depth - 1, throw_depth);

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
    IndirectThunkExceptionTestBottom(10, 4);
  } __except(EXCEPTION_EXECUTE_HANDLER) {
    return GetExceptionCode() == 0xBADF00D;
  }

  return false;
}

// Count the number of entries/exits.
int top_entry = 0;
int top_exit = 0;

typedef void (*VoidFuncTakingIntFuncPtr)(int, bool (*func)());

void RecurseAndCall(int depth, bool (*func)());

void __declspec(naked) IndirectThunkRecurseAndCallImpl() {
  __asm {
    push RecurseAndCall
    jmp ParseEngineRpcTest::_indirect_penter_
  }
}

VoidFuncTakingIntFuncPtr IndirectThunkRecurseAndCall =
    reinterpret_cast<VoidFuncTakingIntFuncPtr>(
        IndirectThunkRecurseAndCallImpl);

__declspec(naked) void RecurseAndCall(int depth, bool (*func)()) {
  __asm {
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
    IndirectThunkRecurseAndCall(depth - 1, func);
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
  IndirectThunkRecurseAndCall(depth, ExceptionTestRecurseRaiseAndReturn);
}

}  // namespace

// Return immediately after taking an exception (which leaves orphaned
// entries on the shadow stack).
TEST_F(ParseEngineRpcTest, EnterExitReturnAfterException) {
  top_entry = 0;
  top_exit = 0;
  bottom_entry = 0;
  bottom_exit = 0;

  ASSERT_NO_FATAL_FAILURE(
      StartCallTraceService(TRACE_FLAG_ENTER | TRACE_FLAG_EXIT));

  ASSERT_NO_FATAL_FAILURE(LoadCallTraceDll());

  ExceptionTestReturnAfterException(10);

  ASSERT_NO_FATAL_FAILURE(UnloadCallTraceDll());
  ASSERT_NO_FATAL_FAILURE(ConsumeEventsFromTempSession());

  EXPECT_EQ(11, top_entry);
  EXPECT_EQ(11, top_exit);

  EXPECT_EQ(11, bottom_entry);
  EXPECT_EQ(5, bottom_exit);
}

namespace {

bool ExceptionTestRecurseRaiseAndCall() {
  __try {
    IndirectThunkExceptionTestBottom(10, 4);
  } __except(EXCEPTION_EXECUTE_HANDLER) {
    IndirectThunkRecursiveFunction(10);
    return true;
  }

  return false;
}

void ExceptionTestCallAfterException(int depth) {
  IndirectThunkRecurseAndCall(depth, ExceptionTestRecurseRaiseAndCall);
}

}  // namespace

// Call immediately after taking an exception (which leaves orphaned
// entries on the shadow stack).
TEST_F(ParseEngineRpcTest, EnterExitCallAfterException) {
  top_entry = 0;
  top_exit = 0;
  bottom_entry = 0;
  bottom_exit = 0;

  ASSERT_NO_FATAL_FAILURE(
      StartCallTraceService(TRACE_FLAG_ENTER | TRACE_FLAG_EXIT));

  ASSERT_NO_FATAL_FAILURE(LoadCallTraceDll());

  ExceptionTestCallAfterException(10);

  ASSERT_NO_FATAL_FAILURE(UnloadCallTraceDll());
  ASSERT_NO_FATAL_FAILURE(ConsumeEventsFromTempSession());

  EXPECT_EQ(11, top_entry);
  EXPECT_EQ(11, top_exit);

  EXPECT_EQ(11, bottom_entry);
  EXPECT_EQ(5, bottom_exit);
}

namespace {

void TailRecurseAndCall(int depth, bool (*func)());

void __declspec(naked) IndirectThunkTailRecurseAndCallImpl() {
  __asm {
    push TailRecurseAndCall
    jmp ParseEngineRpcTest::_indirect_penter_
  }
}

VoidFuncTakingIntFuncPtr IndirectThunkTailRecurseAndCall =
    reinterpret_cast<VoidFuncTakingIntFuncPtr>(
        IndirectThunkTailRecurseAndCallImpl);

void __declspec(naked) TailRecurseAndCall(int depth, bool (*func)()) {
  __asm {
    // Test depth for zero and exit if so.
    mov eax, DWORD PTR[esp + 4]
    test eax, eax
    jz done

    // Subtract one and "recurse".
    dec eax
    mov DWORD PTR[esp + 4], eax
    jmp IndirectThunkTailRecurseAndCall

  done:
    mov eax, DWORD PTR[esp + 8]
    call eax
    ret
  }
}

void ExceptionTestCallAfterTailRecurseException(int depth) {
  IndirectThunkTailRecurseAndCall(depth, ExceptionTestRecurseRaiseAndCall);
}

}  // namespace

TEST_F(ParseEngineRpcTest, EnterExitCallAfterTailRecurseException) {
  top_entry = 0;
  top_exit = 0;
  bottom_entry = 0;
  bottom_exit = 0;

  StartCallTraceService(TRACE_FLAG_ENTER | TRACE_FLAG_EXIT);

  ASSERT_NO_FATAL_FAILURE(LoadCallTraceDll());

  ExceptionTestCallAfterTailRecurseException(10);

  EXPECT_EQ(11, bottom_entry);
  EXPECT_EQ(5, bottom_exit);

  ASSERT_NO_FATAL_FAILURE(UnloadCallTraceDll());
  ASSERT_NO_FATAL_FAILURE(ConsumeEventsFromTempSession());

  // Verify that the tail call exits were recorded.
  EXPECT_EQ(33, entered_addresses_.size());
  EXPECT_EQ(26, exited_addresses_.size());
}
