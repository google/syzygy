// Copyright 2014 Google Inc. All Rights Reserved.
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
// Unit tests for RPC helpers.

#include "syzygy/common/rpc/helpers.h"

#include "base/strings/string16.h"
#include "gtest/gtest.h"

namespace common {
namespace rpc {

TEST(RpcHelpersTest, AsRpcWstr) {
  base::char16 a_string[] = L"Hello world.";
  // As this helper only amounts to a reinterpret cast, the real test is that it
  // compiles.
  RPC_WSTR an_rpc_wstr = AsRpcWstr(a_string);
  EXPECT_NE(static_cast<RPC_WSTR>(nullptr), an_rpc_wstr);
}

}  // namespace rpc
}  // namespace common
