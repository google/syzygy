// Copyright 2015 Google Inc. All Rights Reserved.
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

#include "syzygy/kasko/testing/mock_service.h"

#include <stdint.h>
#include <string>
#include <vector>

#include "base/process/process_handle.h"
#include "base/threading/platform_thread.h"
#include "gtest/gtest.h"
#include "syzygy/kasko/minidump_request.h"

namespace kasko {
namespace testing {

TEST(MockServiceTest, ParameterMapping) {
  std::vector<testing::MockService::CallRecord> call_log;
  testing::MockService mock_service(&call_log);

  std::string protobuf = "hello world";
  uint32_t kStreamType = 987;
  uint32_t kExceptionInfoAddress = 1122;
  base::PlatformThreadId kThreadId = 3;
  base::ProcessId kProcessId = 44;

  MinidumpRequest request;
  request.exception_info_address = kExceptionInfoAddress;
  request.type = MinidumpRequest::SMALL_DUMP_TYPE;
  request.crash_keys.push_back(MinidumpRequest::CrashKey(L"foo", L"bar"));
  MinidumpRequest::CustomStream custom_stream = {kStreamType, protobuf.data(),
                                                 protobuf.length()};
  request.custom_streams.push_back(custom_stream);
  MinidumpRequest::MemoryRange memory_range = {0xdeadbeef, 100};
  request.user_selected_memory_ranges.push_back(memory_range);

  mock_service.SendDiagnosticReport(kProcessId, kThreadId, request);

  ASSERT_EQ(1u, call_log.size());
  ASSERT_EQ(kExceptionInfoAddress, call_log[0].exception_info_address);
  ASSERT_EQ(kProcessId, call_log[0].client_process_id);
  ASSERT_EQ(kThreadId, call_log[0].thread_id);
  ASSERT_EQ(MinidumpRequest::SMALL_DUMP_TYPE, call_log[0].minidump_type);
  ASSERT_EQ(1u, call_log[0].user_selected_memory_ranges.size());
  ASSERT_EQ(memory_range.start(),
            call_log[0].user_selected_memory_ranges[0].start());
  ASSERT_EQ(memory_range.size(),
            call_log[0].user_selected_memory_ranges[0].size());
  ASSERT_EQ(1u, call_log[0].crash_keys.size());
  auto crash_keys_entry = call_log[0].crash_keys.find(L"foo");
  ASSERT_NE(call_log[0].crash_keys.end(), crash_keys_entry);
  ASSERT_EQ(L"bar", crash_keys_entry->second);
  ASSERT_EQ(1u, call_log[0].custom_streams.size());
  auto custom_streams_entry = call_log[0].custom_streams.find(kStreamType);
  ASSERT_NE(call_log[0].custom_streams.end(), custom_streams_entry);
  ASSERT_EQ(protobuf, custom_streams_entry->second);
}

}  // namespace testing
}  // namespace kasko
