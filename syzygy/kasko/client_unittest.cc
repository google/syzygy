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
      scoped_ptr<Service>(new testing::MockService(&call_log)));
  ASSERT_TRUE(instance.Run());

  base::ScopedClosureRunner stop_service_bridge(
      base::Bind(&ServiceBridge::Stop, base::Unretained(&instance)));

  std::string protobuf = "hello world";

  base::char16* keys[] = {L"foo", L"hello", nullptr};
  base::char16* values[] = {L"bar", L"world", nullptr};

  // Small dump with crash keys.
  Client(endpoint).SendReport(nullptr, SMALL_DUMP_TYPE, protobuf.data(),
                              protobuf.length(), keys, values);

  // Larger dump without crash keys.
  Client(endpoint).SendReport(nullptr, LARGER_DUMP_TYPE, protobuf.data(),
                              protobuf.length(), nullptr, nullptr);

  ASSERT_EQ(2u, call_log.size());
  ASSERT_EQ(::GetCurrentProcessId(), call_log[0].client_process_id);
  ASSERT_EQ(protobuf, call_log[0].protobuf);
  ASSERT_EQ(2u, call_log[0].crash_keys.size());
  auto entry = call_log[0].crash_keys.find(L"foo");
  ASSERT_NE(call_log[0].crash_keys.end(), entry);
  ASSERT_EQ(L"bar", entry->second);
  entry = call_log[0].crash_keys.find(L"hello");
  ASSERT_NE(call_log[0].crash_keys.end(), entry);
  ASSERT_EQ(L"world", entry->second);
  ASSERT_EQ(SMALL_DUMP_TYPE, call_log[0].minidump_type);

  ASSERT_EQ(::GetCurrentProcessId(), call_log[1].client_process_id);
  ASSERT_EQ(protobuf, call_log[1].protobuf);
  ASSERT_EQ(0u, call_log[1].crash_keys.size());
  ASSERT_EQ(LARGER_DUMP_TYPE, call_log[1].minidump_type);
}

}  // namespace kasko
