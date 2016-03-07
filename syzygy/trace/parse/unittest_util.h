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
// Call trace event parsing test classes.

#ifndef SYZYGY_TRACE_PARSE_UNITTEST_UTIL_H_
#define SYZYGY_TRACE_PARSE_UNITTEST_UTIL_H_

#include "gmock/gmock.h"
#include "syzygy/trace/parse/parser.h"

namespace testing {

class MockParseEventHandler : public trace::parser::ParseEventHandler {
 public:
  MOCK_METHOD3(OnProcessStarted, void(base::Time time,
                                      DWORD process_id,
                                      const TraceSystemInfo* data));
  MOCK_METHOD2(OnProcessEnded, void(base::Time time, DWORD process_id));
  MOCK_METHOD4(OnFunctionEntry, void(base::Time time,
                                     DWORD process_id,
                                     DWORD thread_id,
                                     const TraceEnterExitEventData* data));
  MOCK_METHOD4(OnFunctionExit, void(base::Time time,
                                    DWORD process_id,
                                    DWORD thread_id,
                                    const TraceEnterExitEventData* data));
  MOCK_METHOD4(OnBatchFunctionEntry, void(base::Time time,
                                          DWORD process_id,
                                          DWORD thread_id,
                                          const TraceBatchEnterData* data));
  MOCK_METHOD4(OnProcessAttach, void(base::Time time,
                                     DWORD process_id,
                                     DWORD thread_id,
                                     const TraceModuleData* data));
  MOCK_METHOD4(OnProcessDetach, void(base::Time time,
                                     DWORD process_id,
                                     DWORD thread_id,
                                     const TraceModuleData* data));
  MOCK_METHOD4(OnThreadAttach, void(base::Time time,
                                    DWORD process_id,
                                    DWORD thread_id,
                                    const TraceModuleData* data));
  MOCK_METHOD4(OnThreadDetach, void(base::Time time,
                                    DWORD process_id,
                                    DWORD thread_id,
                                    const TraceModuleData* data));
  MOCK_METHOD5(OnInvocationBatch, void(base::Time time,
                                       DWORD process_id,
                                       DWORD thread_id,
                                       size_t num_batches,
                                       const TraceBatchInvocationInfo* data));
  MOCK_METHOD4(OnThreadName, void(base::Time time,
                                  DWORD process_id,
                                  DWORD thread_id,
                                  const base::StringPiece& thread_name));
  MOCK_METHOD4(OnIndexedFrequency,
               void(base::Time time,
                    DWORD process_id,
                    DWORD thread_id,
                    const TraceIndexedFrequencyData* data));
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
};

typedef testing::StrictMock<MockParseEventHandler> StrictMockParseEventHandler;

}  // namespace testing

#endif  // SYZYGY_TRACE_PARSE_UNITTEST_UTIL_H_
