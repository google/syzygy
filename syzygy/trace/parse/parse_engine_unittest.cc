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

#include "syzygy/trace/parse/parse_engine.h"

#include <windows.h>  // NOLINT
#include <wmistr.h>  // NOLINT
#include <evntrace.h>

#include <set>
#include <vector>

#include "base/logging.h"
#include "base/strings/string_util.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/common/indexed_frequency_data.h"
#include "syzygy/trace/parse/parser.h"

namespace {

using testing::_;
using trace::parser::Parser;
using trace::parser::ParseEngine;
using trace::parser::ParseEventHandler;
using trace::parser::ModuleInformation;

typedef std::multiset<FuncAddr> FunctionSet;
typedef std::vector<TraceModuleData> ModuleSet;

class ParseEngineUnitTest
    : public testing::Test,
      public ParseEngine,
      public ParseEventHandler {
 public:
  ParseEngineUnitTest()
      : ParseEngine("Test", true),
        basic_block_frequencies(0),
        expected_data(NULL) {
    ::memset(&event_record_, 0, sizeof(event_record_));
    set_event_handler(this);
  }

  ~ParseEngineUnitTest() {
  }

  void DispatchEventData(TraceEventType type, const void* data, size_t size) {
    ::memset(&event_record_, 0, sizeof(event_record_));
    event_record_.Header.ProcessId = kProcessId;
    event_record_.Header.ThreadId = kThreadId;
    event_record_.Header.Guid = kCallTraceEventClass;
    event_record_.Header.Class.Type = type;
    event_record_.MofData = const_cast<void*>(data);
    event_record_.MofLength = size;

    ASSERT_TRUE(DispatchEvent(&event_record_));
  }

  bool IsRecognizedTraceFile(const base::FilePath& trace_file_path) override {
    return true;
  }

  bool OpenTraceFile(const base::FilePath& trace_file_path) override {
    return true;
  }

  virtual bool ConsumeAllEvents() {
    return true;
  }

  virtual bool CloseAllTraceFiles() {
    return true;
  }

  // ParseEventHander methods.

  void OnProcessStarted(base::Time time,
                        DWORD process_id,
                        const TraceSystemInfo* data) override {
    ASSERT_EQ(process_id, kProcessId);
  }

  void OnProcessEnded(base::Time time, DWORD process_id) override {
    ASSERT_EQ(process_id, kProcessId);
  }

  void OnFunctionEntry(base::Time time,
                       DWORD process_id,
                       DWORD thread_id,
                       const TraceEnterExitEventData* data) override {
    ASSERT_EQ(process_id, kProcessId);
    ASSERT_EQ(thread_id, kThreadId);
    ASSERT_TRUE(reinterpret_cast<const void*>(data) == expected_data);
    EXPECT_TRUE(data->function != NULL);
    function_entries.insert(data->function);
  }

  void OnFunctionExit(base::Time time,
                      DWORD process_id,
                      DWORD thread_id,
                      const TraceEnterExitEventData* data) override {
    ASSERT_EQ(process_id, kProcessId);
    ASSERT_EQ(thread_id, kThreadId);
    ASSERT_TRUE(reinterpret_cast<const void*>(data) == expected_data);
    EXPECT_TRUE(data->function != NULL);
    function_exits.insert(data->function);
  }

  void OnBatchFunctionEntry(base::Time time,
                            DWORD process_id,
                            DWORD thread_id,
                            const TraceBatchEnterData* data) override {
    ASSERT_EQ(process_id, kProcessId);
    ASSERT_EQ(thread_id, kThreadId);
    ASSERT_TRUE(reinterpret_cast<const void*>(data) == expected_data);
    for (size_t i = 0; i < data->num_calls; ++i) {
      function_entries.insert(data->calls[i].function);
    }
  }

  void OnProcessAttach(base::Time time,
                       DWORD process_id,
                       DWORD thread_id,
                       const TraceModuleData* data) override {
    ASSERT_EQ(process_id, kProcessId);
    ASSERT_EQ(thread_id, kThreadId);
    ASSERT_TRUE(reinterpret_cast<const void*>(data) == expected_data);
    process_attaches.push_back(*data);
  }

  void OnProcessDetach(base::Time time,
                       DWORD process_id,
                       DWORD thread_id,
                       const TraceModuleData* data) override {
    ASSERT_EQ(process_id, kProcessId);
    ASSERT_EQ(thread_id, kThreadId);
    ASSERT_TRUE(reinterpret_cast<const void*>(data) == expected_data);
    process_detaches.push_back(*data);
  }

  void OnThreadAttach(base::Time time,
                      DWORD process_id,
                      DWORD thread_id,
                      const TraceModuleData* data) override {
    ASSERT_EQ(process_id, kProcessId);
    ASSERT_EQ(thread_id, kThreadId);
    ASSERT_TRUE(reinterpret_cast<const void*>(data) == expected_data);
    thread_attaches.push_back(*data);
  }

  // Issued for DLL_THREAD_DETACH on an instrumented module.
  void OnThreadDetach(base::Time time,
                      DWORD process_id,
                      DWORD thread_id,
                      const TraceModuleData* data) override {
    ASSERT_EQ(process_id, kProcessId);
    ASSERT_EQ(thread_id, kThreadId);
    ASSERT_TRUE(reinterpret_cast<const void*>(data) == expected_data);
    thread_detaches.push_back(*data);
  }

  void OnInvocationBatch(
      base::Time time,
      DWORD process_id,
      DWORD thread_id,
      size_t num_invocations,
      const TraceBatchInvocationInfo* data) override {
    // TODO(anyone): Test this.
  }

  void OnIndexedFrequency(
      base::Time time,
      DWORD process_id,
      DWORD thread_id,
      const TraceIndexedFrequencyData* data) override {
    ASSERT_EQ(process_id, kProcessId);
    ASSERT_EQ(thread_id, kThreadId);
    ASSERT_TRUE(reinterpret_cast<const void*>(data) == expected_data);
    ++basic_block_frequencies;
  }

  MOCK_METHOD4(OnThreadName,
      void(base::Time time, DWORD process_id, DWORD thread_id,
           const base::StringPiece& thread_name));
  MOCK_METHOD3(OnDynamicSymbol,
               void(DWORD process_id,
                    uint32_t symbol_id,
                    const base::StringPiece& symbol_name));
  MOCK_METHOD3(OnSampleData,
               void(base::Time time,
                    DWORD process_id,
                    const TraceSampleData* data));
  MOCK_METHOD3(OnFunctionNameTableEntry,
               void(base::Time time,
                    DWORD process_id,
                    const TraceFunctionNameTableEntry* data));
  MOCK_METHOD3(OnStackTrace,
               void(base::Time time,
                    DWORD process_id,
                    const TraceStackTrace* data));
  MOCK_METHOD4(OnDetailedFunctionCall,
               void(base::Time time,
                    DWORD process_id,
                    DWORD thread_id,
                    const TraceDetailedFunctionCall* data));
  MOCK_METHOD3(OnComment,
               void(base::Time time,
                    DWORD process_id,
                    const TraceComment* data));
  MOCK_METHOD3(OnProcessHeap,
               void(base::Time time,
                    DWORD process_id,
                    const TraceProcessHeap* data));

  static const DWORD kProcessId;
  static const DWORD kThreadId;
  static const ModuleInformation kExeInfo;
  static const ModuleInformation kDllInfo;
  static const TraceModuleData kModuleData;
  static const TraceIndexedFrequencyData kIndexedFrequencyData;
  static const TraceIndexedFrequencyData kShortIndexedFrequencyData;

  EVENT_TRACE event_record_;

  FunctionSet function_entries;
  FunctionSet function_exits;
  ModuleSet process_attaches;
  ModuleSet process_detaches;
  ModuleSet thread_attaches;
  ModuleSet thread_detaches;
  size_t basic_block_frequencies;

  const void* expected_data;
};

const DWORD ParseEngineUnitTest::kProcessId = 0xAAAAAAAA;

const DWORD ParseEngineUnitTest::kThreadId = 0xBBBBBBBB;

const ModuleInformation ParseEngineUnitTest::kExeInfo(
    L"file_name.exe", pe::PEFile::AbsoluteAddress(0x11111111), 0x22222222,
    0x33333333, 0x44444444);

const ModuleInformation ParseEngineUnitTest::kDllInfo(
    L"file_name.dll", pe::PEFile::AbsoluteAddress(0x55555555), 0x66666666,
    0x77777777, 0x88888888);

const TraceModuleData ParseEngineUnitTest::kModuleData = {
    reinterpret_cast<ModuleAddr>(0x99999999),
    0x11111111,
    0x22222222,
    0x33333333,
    L"module",
    L"executable" };

const TraceIndexedFrequencyData ParseEngineUnitTest::kIndexedFrequencyData = {
    reinterpret_cast<ModuleAddr>(0x11111111),
    0x22222222,
    0x33333333,
    0x44444444,
    1,
    1,
    common::IndexedFrequencyData::BASIC_BLOCK_ENTRY,
    1,
    0 };

// This indexed frequency struct does not contain enough data for its implicitly
// encoded length.
const TraceIndexedFrequencyData
    ParseEngineUnitTest::kShortIndexedFrequencyData = {
        reinterpret_cast<ModuleAddr>(0x11111111),
        0x22222222,
        0x33333333,
        0x44444444,
        10,
        1,
        common::IndexedFrequencyData::BASIC_BLOCK_ENTRY,
        4,
        0 };

// A test function to show up in the trace events.
void TestFunc1() {
  ::Sleep(100);
}

// Another test function to show up in the trace events.
void TestFunc2() {
  ::time(NULL);
}

TEST_F(ParseEngineUnitTest, ModuleInfo) {
  const ModuleInformation* module_info = NULL;

  // Insert the module information.
  ASSERT_TRUE(AddModuleInformation(kProcessId, kExeInfo));
  ASSERT_TRUE(AddModuleInformation(kProcessId, kDllInfo));
  ASSERT_EQ(1, processes_.size());
  ASSERT_EQ(2, processes_[kProcessId].size());

  // Multiple identical insertions should be ok.
  ASSERT_TRUE(AddModuleInformation(kProcessId, kDllInfo));
  ASSERT_EQ(2, processes_[kProcessId].size());

  // Intersecting but not identical insertions should fail if disallowed.
  ModuleInformation bad_dll_info(kDllInfo);
  bad_dll_info.base_address += 100;
  ASSERT_TRUE(fail_on_module_conflict_);
  ASSERT_FALSE(AddModuleInformation(kProcessId, bad_dll_info));
  ASSERT_EQ(2, processes_[kProcessId].size());

  // If conflicting module info is non-fatal, insertions should appear to
  // succeed but not actually happen.
  fail_on_module_conflict_ = false;
  ASSERT_TRUE(AddModuleInformation(kProcessId, bad_dll_info));
  ASSERT_EQ(2, processes_[kProcessId].size());
  fail_on_module_conflict_ = true;

  // Search for unknown process.
  module_info = GetModuleInformation(
      kProcessId + 1, kExeInfo.base_address.value());
  ASSERT_TRUE(module_info == NULL);

  // Search before exe start address
  const int kBeforeOffset = -1;
  module_info = GetModuleInformation(
      kProcessId, kExeInfo.base_address.value() + kBeforeOffset);
  ASSERT_TRUE(module_info == NULL);

  // Search after exe end address.
  const size_t kAfterOffset = kExeInfo.module_size;
  module_info = GetModuleInformation(
      kProcessId, kExeInfo.base_address.value() + kAfterOffset);
  ASSERT_TRUE(module_info == NULL);

  // Get exe module by start address.
  const size_t kStartOffset = 0;
  module_info = GetModuleInformation(
      kProcessId, kExeInfo.base_address.value() + kStartOffset);
  ASSERT_TRUE(module_info != NULL);
  ASSERT_TRUE(*module_info == kExeInfo);

  // Get exe module by address somewhere in the middle.
  const size_t kMiddleOffset = kExeInfo.module_size / 2;
  module_info = GetModuleInformation(
      kProcessId, kExeInfo.base_address.value() + kMiddleOffset);
  ASSERT_TRUE(module_info != NULL);
  ASSERT_TRUE(*module_info == kExeInfo);

  // Get exe module by address at the end.
  const size_t kEndOffset = kExeInfo.module_size - 1;
  module_info = GetModuleInformation(
      kProcessId, kExeInfo.base_address.value() + kEndOffset);
  ASSERT_TRUE(module_info != NULL);
  ASSERT_TRUE(*module_info == kExeInfo);

  // We only remove modules from a given process if a conflicting module is
  // loaded after the module has been marked as dirty. This is because (1) we
  // don't guarantee temporal order of all events in a process, so you
  // might parse a function event after seeing the module get unloaded
  // if the buffers are flushed in that order; and (2) because process ids may
  // be reused (but not concurrently) so we do want to drop stale module info
  // when the process has been replaced.

  // Get dll module by address somewhere in the middle, then remove it and
  // see that it's STILL found by that address.
  const size_t kDllOffset = kDllInfo.module_size / 2;
  module_info = GetModuleInformation(
      kProcessId, kDllInfo.base_address.value() + kDllOffset);
  ASSERT_TRUE(module_info != NULL);
  ASSERT_TRUE(*module_info == kDllInfo);
  ASSERT_TRUE(RemoveModuleInformation(kProcessId, kDllInfo));
  ASSERT_EQ(2, processes_[kProcessId].size());
  module_info = GetModuleInformation(
      kProcessId, kDllInfo.base_address.value() + kDllOffset);
  ASSERT_TRUE(module_info != NULL);
  ASSERT_TRUE(*module_info == kDllInfo);

  // Add conflicting module information and see that the old module is gone.
  ModuleInformation new_dll_info(kDllInfo);
  new_dll_info.base_address += 4;
  ASSERT_TRUE(AddModuleInformation(kProcessId, new_dll_info));
  ASSERT_EQ(2, processes_[kProcessId].size());
  module_info = GetModuleInformation(
      kProcessId, kDllInfo.base_address.value());
  ASSERT_TRUE(module_info == NULL);
  module_info = GetModuleInformation(
      kProcessId, new_dll_info.base_address.value());
  ASSERT_TRUE(module_info != NULL);
  ASSERT_TRUE(*module_info == new_dll_info);
}

TEST_F(ParseEngineUnitTest, UnhandledEvent) {
  EVENT_TRACE local_record = {};
  ASSERT_FALSE(DispatchEvent(&local_record));

  local_record.Header.ProcessId = kProcessId;
  local_record.Header.ThreadId = kThreadId;
  local_record.Header.Guid = kCallTraceEventClass;
  local_record.Header.Class.Type = 0xFF;  // Invalid value.
  ASSERT_TRUE(DispatchEvent(&local_record));
  ASSERT_TRUE(error_occurred());
}

TEST_F(ParseEngineUnitTest, FunctionEntryEvents) {
  TraceEnterEventData event_data = {};
  event_data.function = &TestFunc1;
  expected_data = &event_data;

  ASSERT_NO_FATAL_FAILURE(
      DispatchEventData(TRACE_ENTER_EVENT, &event_data, sizeof(event_data)));
  ASSERT_FALSE(error_occurred());
  ASSERT_NO_FATAL_FAILURE(
      DispatchEventData(TRACE_ENTER_EVENT, &event_data, sizeof(event_data)));
  ASSERT_FALSE(error_occurred());
  ASSERT_EQ(function_entries.size(), 2);
  ASSERT_EQ(function_entries.count(&TestFunc1), 2);

  // Check for short event data.
  ASSERT_NO_FATAL_FAILURE(
      DispatchEventData(TRACE_ENTER_EVENT,
                        &event_data,
                        sizeof(TraceEnterEventData) - 1));
  ASSERT_TRUE(error_occurred());
}

TEST_F(ParseEngineUnitTest, FunctionExitEvents) {
  TraceExitEventData event_data = {};
  event_data.function = &TestFunc2;
  expected_data = &event_data;

  ASSERT_NO_FATAL_FAILURE(
      DispatchEventData(TRACE_EXIT_EVENT, &event_data, sizeof(event_data)));
  ASSERT_FALSE(error_occurred());
  ASSERT_NO_FATAL_FAILURE(
      DispatchEventData(TRACE_EXIT_EVENT, &event_data, sizeof(event_data)));
  ASSERT_FALSE(error_occurred());
  ASSERT_EQ(function_exits.size(), 2);
  ASSERT_EQ(function_exits.count(&TestFunc2), 2);

  // Check for short event data.
  ASSERT_NO_FATAL_FAILURE(
     DispatchEventData(TRACE_EXIT_EVENT,
                       &event_data,
                       sizeof(TraceEnterEventData) - 1));
  ASSERT_TRUE(error_occurred());
}

TEST_F(ParseEngineUnitTest, BatchFunctionEntry) {
  uint8_t raw_data[sizeof(TraceBatchEnterData) +
                   4 * sizeof(TraceEnterEventData)] = {};
  TraceBatchEnterData& event_data =
     *reinterpret_cast<TraceBatchEnterData*>(&raw_data);
  event_data.thread_id = kThreadId;
  event_data.num_calls = 5;
  event_data.calls[0].function = &TestFunc1;
  event_data.calls[1].function = &TestFunc2;
  event_data.calls[2].function = &TestFunc1;
  event_data.calls[3].function = &TestFunc2;
  event_data.calls[4].function = NULL;
  expected_data = &raw_data;

  ASSERT_NO_FATAL_FAILURE(
      DispatchEventData(TRACE_BATCH_ENTER, &raw_data, sizeof(raw_data)));
  ASSERT_FALSE(error_occurred());
  ASSERT_NO_FATAL_FAILURE(
      DispatchEventData(TRACE_BATCH_ENTER, &raw_data, sizeof(raw_data)));
  ASSERT_FALSE(error_occurred());
  ASSERT_EQ(function_entries.size(), 8);
  ASSERT_EQ(function_entries.count(&TestFunc1), 4);
  ASSERT_EQ(function_entries.count(&TestFunc2), 4);

  // Check for short event header.
  ASSERT_NO_FATAL_FAILURE(
      DispatchEventData(TRACE_BATCH_ENTER,
                        &raw_data,
                        FIELD_OFFSET(TraceBatchEnterData, num_calls)));
  ASSERT_TRUE(error_occurred());

  // Check for short event tail (remove the empty record + one byte).
  set_error_occurred(false);
  ASSERT_NO_FATAL_FAILURE(
      DispatchEventData(TRACE_BATCH_ENTER,
                        &raw_data,
                         sizeof(raw_data) - sizeof(TraceEnterEventData) - 1));
  ASSERT_TRUE(error_occurred());
}

TEST_F(ParseEngineUnitTest, ProcessAttachIncomplete) {
  TraceModuleData incomplete(kModuleData);
  incomplete.module_base_addr = NULL;

  // No error should be reported for NULL module addr, instead the record
  // should be ignored.
  expected_data = &kModuleData;
  ASSERT_NO_FATAL_FAILURE(
      DispatchEventData(TRACE_PROCESS_ATTACH_EVENT,
                        &incomplete,
                        sizeof(incomplete)));

  ASSERT_FALSE(error_occurred());
  ASSERT_EQ(process_attaches.size(), 0);
}

TEST_F(ParseEngineUnitTest, ProcessAttach) {
  expected_data = &kModuleData;

  ASSERT_NO_FATAL_FAILURE(
      DispatchEventData(TRACE_PROCESS_ATTACH_EVENT,
                        &kModuleData,
                        sizeof(kModuleData)));
  ASSERT_FALSE(error_occurred());
  ASSERT_EQ(process_attaches.size(), 1);

  // Check for short module event.
  ASSERT_NO_FATAL_FAILURE(
      DispatchEventData(TRACE_PROCESS_ATTACH_EVENT,
                        &kModuleData,
                        sizeof(kModuleData) - 1));
  ASSERT_TRUE(error_occurred());
}

TEST_F(ParseEngineUnitTest, ProcessDetach) {
  expected_data = &kModuleData;

  ASSERT_NO_FATAL_FAILURE(
      DispatchEventData(TRACE_PROCESS_DETACH_EVENT,
                        &kModuleData,
                        sizeof(kModuleData)));
  ASSERT_FALSE(error_occurred());
  ASSERT_EQ(process_detaches.size(), 1);

  // Check for short module event.
  ASSERT_NO_FATAL_FAILURE(
      DispatchEventData(TRACE_PROCESS_DETACH_EVENT,
                        &kModuleData,
                        sizeof(kModuleData) - 1));
  ASSERT_TRUE(error_occurred());
}

TEST_F(ParseEngineUnitTest, ThreadAttach) {
  expected_data = &kModuleData;

  ASSERT_NO_FATAL_FAILURE(
      DispatchEventData(TRACE_THREAD_ATTACH_EVENT,
                        &kModuleData,
                        sizeof(kModuleData)));
  ASSERT_FALSE(error_occurred());
  ASSERT_EQ(thread_attaches.size(), 1);

  // Check for short module event.
  ASSERT_NO_FATAL_FAILURE(
      DispatchEventData(TRACE_THREAD_ATTACH_EVENT,
                        &kModuleData,
                        sizeof(kModuleData) - 1));
  ASSERT_TRUE(error_occurred());
}

TEST_F(ParseEngineUnitTest, ThreadDetach) {
  expected_data = &kModuleData;

  ASSERT_NO_FATAL_FAILURE(
      DispatchEventData(TRACE_THREAD_DETACH_EVENT,
                        &kModuleData,
                        sizeof(kModuleData)));
  ASSERT_FALSE(error_occurred());
  ASSERT_EQ(thread_detaches.size(), 1);

  // Check for short module event.
  ASSERT_NO_FATAL_FAILURE(
      DispatchEventData(TRACE_THREAD_DETACH_EVENT,
                        &kModuleData,
                        sizeof(kModuleData) - 1));
  ASSERT_TRUE(error_occurred());
}

TEST_F(ParseEngineUnitTest, IndexedFrequencyTooSmallForHeader) {
  ASSERT_NO_FATAL_FAILURE(
      DispatchEventData(TRACE_INDEXED_FREQUENCY,
                        &kIndexedFrequencyData,
                        sizeof(kIndexedFrequencyData) - 1));

  ASSERT_TRUE(error_occurred());
  ASSERT_EQ(basic_block_frequencies, 0);
}

TEST_F(ParseEngineUnitTest, IndexedFrequencyTooSmallForContents) {
  ASSERT_NO_FATAL_FAILURE(
      DispatchEventData(TRACE_INDEXED_FREQUENCY,
                        &kShortIndexedFrequencyData,
                        sizeof(kShortIndexedFrequencyData)));

  ASSERT_TRUE(error_occurred());
  ASSERT_EQ(basic_block_frequencies, 0);
}

TEST_F(ParseEngineUnitTest, IndexedFrequency) {
  expected_data = &kIndexedFrequencyData;
  ASSERT_NO_FATAL_FAILURE(
      DispatchEventData(TRACE_INDEXED_FREQUENCY,
                        &kIndexedFrequencyData,
                        sizeof(kIndexedFrequencyData)));
  ASSERT_FALSE(error_occurred());
  ASSERT_EQ(basic_block_frequencies, 1);
}

TEST_F(ParseEngineUnitTest, DynamicSymbol) {
  static const char kSymbolName[] = "aDynamicSymbol";
  const uint32_t kSymbolId = 0x17459A;
  char data[FIELD_OFFSET(TraceDynamicSymbol, symbol_name) +
            sizeof(kSymbolName)];
  TraceDynamicSymbol* symbol = reinterpret_cast<TraceDynamicSymbol*>(data);
  symbol->symbol_id = kSymbolId;
  ::memcpy(symbol->symbol_name, kSymbolName, sizeof(kSymbolName));

  // Dispatch a valid dynamic symbol record.
  EXPECT_CALL(*this,
      OnDynamicSymbol(kProcessId, kSymbolId, base::StringPiece(kSymbolName)));
  ASSERT_NO_FATAL_FAILURE(
      DispatchEventData(TRACE_DYNAMIC_SYMBOL, data, sizeof(data)));
  ASSERT_FALSE(error_occurred());

  // Dispatch a short symbol record, make sure we err out.
  ASSERT_NO_FATAL_FAILURE(
      DispatchEventData(TRACE_DYNAMIC_SYMBOL,
                        data,
                        FIELD_OFFSET(TraceDynamicSymbol, symbol_name) - 1));
  ASSERT_TRUE(error_occurred());
}

TEST_F(ParseEngineUnitTest, SampleData) {
  const uint32_t kBucketCount = 42;
  char buffer[FIELD_OFFSET(TraceSampleData, buckets) +
              kBucketCount * sizeof(uint32_t)] = {};
  TraceSampleData* data = reinterpret_cast<TraceSampleData*>(buffer);

  data->module_base_addr = reinterpret_cast<ModuleAddr>(0x01000000);
  data->module_size = 32 * 1024 * 1024;
  data->module_checksum = 0xDEADF00D;
  data->module_time_date_stamp = 0x12345678;
  data->bucket_size = 4;
  data->bucket_start = reinterpret_cast<ModuleAddr>(0x01001000);
  data->bucket_count = kBucketCount;
  data->sampling_start_time = 0x0102030405060708;
  data->sampling_end_time = 0x0203040506070809;
  data->sampling_interval = 0x10000;

  for (size_t i = 0; i < kBucketCount; ++i)
    data->buckets[i] = i;

  EXPECT_CALL(*this, OnSampleData(_, kProcessId, data));
  ASSERT_NO_FATAL_FAILURE(
      DispatchEventData(TRACE_SAMPLE_DATA, data, sizeof(buffer)));
  ASSERT_FALSE(error_occurred());

  // Dispatch a malformed record and make sure the parser errors.
  ASSERT_NO_FATAL_FAILURE(
      DispatchEventData(TRACE_SAMPLE_DATA, data, sizeof(buffer) - 1));
  ASSERT_TRUE(error_occurred());
}

TEST_F(ParseEngineUnitTest, FunctionNameTableEntry) {
  const char kDummyFunctionName[] = "DummyFunction";
  char buffer[FIELD_OFFSET(TraceFunctionNameTableEntry, name) +
      arraysize(kDummyFunctionName)] = {};
  TraceFunctionNameTableEntry* data =
      reinterpret_cast<TraceFunctionNameTableEntry*>(buffer);

  data->function_id = 37;
  data->name_length = arraysize(kDummyFunctionName);
  base::snprintf(data->name, data->name_length, kDummyFunctionName);

  EXPECT_CALL(*this, OnFunctionNameTableEntry(_, kProcessId, data));
  ASSERT_NO_FATAL_FAILURE(DispatchEventData(
      TRACE_FUNCTION_NAME_TABLE_ENTRY, data, sizeof(buffer)));
  ASSERT_FALSE(error_occurred());

  // Dispatch a malformed record and make sure the parser errors.
  ASSERT_NO_FATAL_FAILURE(DispatchEventData(
      TRACE_FUNCTION_NAME_TABLE_ENTRY, data, sizeof(buffer) - 1));
  ASSERT_TRUE(error_occurred());
}

TEST_F(ParseEngineUnitTest, StackTrace) {
  char buffer[FIELD_OFFSET(TraceStackTrace, frames) +
      sizeof(void*) * 4] = {};
  TraceStackTrace* data =
      reinterpret_cast<TraceStackTrace*>(buffer);

  data->stack_trace_id = 42;
  data->num_frames = 4;
  data->frames[0] = reinterpret_cast<void*>(0xDEADBEEF);
  data->frames[1] = reinterpret_cast<void*>(0x900DF00D);
  data->frames[2] = reinterpret_cast<void*>(0xCAFEBABE);
  data->frames[3] = reinterpret_cast<void*>(0x00031337);

  EXPECT_CALL(*this, OnStackTrace(_, kProcessId, data));
  ASSERT_NO_FATAL_FAILURE(DispatchEventData(
      TRACE_STACK_TRACE, data, sizeof(buffer)));
  ASSERT_FALSE(error_occurred());

  // Dispatch a malformed record and make sure the parser errors.
  ASSERT_NO_FATAL_FAILURE(DispatchEventData(
      TRACE_STACK_TRACE, data, sizeof(buffer) - 1));
  ASSERT_TRUE(error_occurred());
}

TEST_F(ParseEngineUnitTest, DetailedFunctionCall) {
  const uint8_t kDummyArguments[] = {
      0x02,
      0x00,
      0x00,
      0x00,  // 2 aguments
      0x04,
      0x00,
      0x00,
      0x00,  // Argument 0 length 4.
      0x01,
      0x00,
      0x00,
      0x00,  // Argument 1 length 1.
      0xDE,
      0xAD,
      0xBE,
      0xEF,  // Argument 0: 0xDEADBEEF.
      'A'    // Argument 1: 'A'
  };
  char buffer[FIELD_OFFSET(TraceDetailedFunctionCall, argument_data) +
      arraysize(kDummyArguments)] = {};
  TraceDetailedFunctionCall* data =
      reinterpret_cast<TraceDetailedFunctionCall*>(buffer);

  data->timestamp = 0x0102030405060708;
  data->function_id = 37;
  data->argument_data_size = arraysize(kDummyArguments);
  ::memcpy(data->argument_data, kDummyArguments, arraysize(kDummyArguments));

  EXPECT_CALL(*this, OnDetailedFunctionCall(_, kProcessId, kThreadId, data));
  ASSERT_NO_FATAL_FAILURE(DispatchEventData(
      TRACE_DETAILED_FUNCTION_CALL, data, sizeof(buffer)));
  ASSERT_FALSE(error_occurred());

  // Dispatch a malformed record and make sure the parser errors.
  ASSERT_NO_FATAL_FAILURE(DispatchEventData(
      TRACE_DETAILED_FUNCTION_CALL, data, sizeof(buffer) - 1));
  ASSERT_TRUE(error_occurred());
}

TEST_F(ParseEngineUnitTest, Comment) {
  const char kDummyComment[] = "This is a comment!";
  char buffer[FIELD_OFFSET(TraceComment, comment) +
      arraysize(kDummyComment)] = {};
  TraceComment* data =
      reinterpret_cast<TraceComment*>(buffer);

  data->comment_size = arraysize(kDummyComment);
  ::memcpy(data->comment, kDummyComment, arraysize(kDummyComment));

  EXPECT_CALL(*this, OnComment(_, kProcessId, data));
  ASSERT_NO_FATAL_FAILURE(DispatchEventData(
      TRACE_COMMENT, data, sizeof(buffer)));
  ASSERT_FALSE(error_occurred());

  // Dispatch a malformed record and make sure the parser errors.
  ASSERT_NO_FATAL_FAILURE(DispatchEventData(
      TRACE_COMMENT, data, sizeof(buffer) - 1));
  ASSERT_TRUE(error_occurred());
}

TEST_F(ParseEngineUnitTest, ProcessHeap) {
  TraceProcessHeap proc_heap = {0xF005BA11};

  EXPECT_CALL(*this, OnProcessHeap(_, kProcessId, &proc_heap));
  ASSERT_NO_FATAL_FAILURE(
      DispatchEventData(TRACE_PROCESS_HEAP, &proc_heap, sizeof(proc_heap)));
  ASSERT_FALSE(error_occurred());

  // Dispatch a malformed record and make sure the parser errors.
  ASSERT_NO_FATAL_FAILURE(
      DispatchEventData(TRACE_PROCESS_HEAP, &proc_heap, sizeof(proc_heap) - 1));
  ASSERT_TRUE(error_occurred());
}

}  // namespace
