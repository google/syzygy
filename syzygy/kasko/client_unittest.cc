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

#include "syzygy/kasko/client.h"

#include <Windows.h>  // NOLINT
#include <Rpc.h>

#include <vector>

#include "base/bind.h"
#include "base/callback.h"
#include "base/callback_helpers.h"
#include "base/process/process_handle.h"
#include "base/strings/string16.h"
#include "base/strings/string_number_conversions.h"
#include "gtest/gtest.h"
#include "syzygy/kasko/minidump_request.h"
#include "syzygy/kasko/service_bridge.h"
#include "syzygy/kasko/testing/mock_service.h"

namespace kasko {

namespace {

const base::char16* const kValidRpcProtocol = L"ncalrpc";
const base::char16* const kTestRpcEndpointPrefix = L"syzygy-kasko-test-svc";

base::string16 GetTestEndpoint() {
  return kTestRpcEndpointPrefix + base::UintToString16(::GetCurrentProcessId());
}

}  // namespace

TEST(ClientTest, BasicTest) {
  std::vector<testing::MockService::CallRecord> call_log;

  base::string16 protocol = kValidRpcProtocol;
  base::string16 endpoint = GetTestEndpoint();
  ServiceBridge instance(
      protocol, endpoint,
      std::unique_ptr<Service>(new testing::MockService(&call_log)));
  ASSERT_TRUE(instance.Run());

  base::ScopedClosureRunner stop_service_bridge(
      base::Bind(&ServiceBridge::Stop, base::Unretained(&instance)));

  std::string protobuf = "hello world";
  uint32_t kStreamType = 987;
  MinidumpRequest request;
  MinidumpRequest::CustomStream custom_stream = {kStreamType, protobuf.data(),
                                                 protobuf.length()};
  request.custom_streams.push_back(custom_stream);

  // Small dump with crash keys.
  request.type = MinidumpRequest::SMALL_DUMP_TYPE;
  request.crash_keys.push_back(MinidumpRequest::CrashKey(L"foo", L"bar"));
  request.crash_keys.push_back(MinidumpRequest::CrashKey(L"hello", L"world"));
  Client(endpoint).SendReport(request);

  // Larger dump without crash keys.
  request.type = MinidumpRequest::LARGER_DUMP_TYPE;
  request.crash_keys.clear();
  MinidumpRequest::MemoryRange memory_range = {0xdeadbeef, 100};
  request.user_selected_memory_ranges.push_back(memory_range);
  Client(endpoint).SendReport(request);

  // Full dump without protobuf.
  request.type = MinidumpRequest::FULL_DUMP_TYPE;
  request.crash_keys.clear();
  request.custom_streams.clear();
  Client(endpoint).SendReport(request);

  ASSERT_EQ(3u, call_log.size());
  ASSERT_EQ(::GetCurrentProcessId(), call_log[0].client_process_id);
  ASSERT_EQ(1u, call_log[0].custom_streams.size());
  auto custom_streams_entry = call_log[0].custom_streams.find(kStreamType);
  ASSERT_NE(call_log[0].custom_streams.end(), custom_streams_entry);
  ASSERT_EQ(protobuf, custom_streams_entry->second);
  ASSERT_EQ(2u, call_log[0].crash_keys.size());
  auto crash_keys_entry = call_log[0].crash_keys.find(L"foo");
  ASSERT_NE(call_log[0].crash_keys.end(), crash_keys_entry);
  ASSERT_EQ(L"bar", crash_keys_entry->second);
  crash_keys_entry = call_log[0].crash_keys.find(L"hello");
  ASSERT_NE(call_log[0].crash_keys.end(), crash_keys_entry);
  ASSERT_EQ(L"world", crash_keys_entry->second);
  ASSERT_EQ(0u, call_log[0].user_selected_memory_ranges.size());
  ASSERT_EQ(MinidumpRequest::SMALL_DUMP_TYPE, call_log[0].minidump_type);

  ASSERT_EQ(::GetCurrentProcessId(), call_log[1].client_process_id);
  ASSERT_EQ(0u, call_log[1].crash_keys.size());
  ASSERT_EQ(1u, call_log[1].custom_streams.size());
  custom_streams_entry = call_log[1].custom_streams.find(kStreamType);
  ASSERT_NE(call_log[1].custom_streams.end(), custom_streams_entry);
  ASSERT_EQ(protobuf, custom_streams_entry->second);
  ASSERT_EQ(1u, call_log[1].user_selected_memory_ranges.size());
  ASSERT_EQ(memory_range.start(),
            call_log[1].user_selected_memory_ranges[0].start());
  ASSERT_EQ(memory_range.size(),
            call_log[1].user_selected_memory_ranges[0].size());
  ASSERT_EQ(MinidumpRequest::LARGER_DUMP_TYPE, call_log[1].minidump_type);

  ASSERT_EQ(::GetCurrentProcessId(), call_log[2].client_process_id);
  ASSERT_EQ(0u, call_log[2].crash_keys.size());
  ASSERT_EQ(0u, call_log[2].custom_streams.size());
  ASSERT_EQ(MinidumpRequest::FULL_DUMP_TYPE, call_log[2].minidump_type);
}

}  // namespace kasko
