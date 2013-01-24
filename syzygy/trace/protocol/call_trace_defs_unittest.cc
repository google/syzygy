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

#include "syzygy/trace/protocol/call_trace_defs.h"

#include "gtest/gtest.h"

namespace trace {

TEST(CallTraceDefsTest, GetSyzygyCallTraceRpcProtocol) {
  std::wstring protocol;
  ::GetSyzygyCallTraceRpcProtocol(&protocol);
  EXPECT_FALSE(protocol.empty());
}

TEST(CallTraceDefsTest, GetSyzygyCallTraceRpcEndpoint) {
  std::wstring base_endpoint;
  ::GetSyzygyCallTraceRpcEndpoint(L"", &base_endpoint);
  EXPECT_FALSE(base_endpoint.empty());

  std::wstring new_endpoint;
  ::GetSyzygyCallTraceRpcEndpoint(L"foo", &new_endpoint);
  EXPECT_FALSE(new_endpoint.empty());
  EXPECT_EQ(base_endpoint + L"-foo", new_endpoint);
}

TEST(CallTraceDefsTest, GetSyzygyCallTraceRpcMutexName) {
  std::wstring base_mutex_name;
  ::GetSyzygyCallTraceRpcMutexName(L"", &base_mutex_name);
  EXPECT_FALSE(base_mutex_name.empty());

  std::wstring new_mutex_name;
  ::GetSyzygyCallTraceRpcMutexName(L"bar", &new_mutex_name);
  EXPECT_FALSE(new_mutex_name.empty());
  EXPECT_EQ(base_mutex_name + L"-bar", new_mutex_name);
}

}  // namespace trace
