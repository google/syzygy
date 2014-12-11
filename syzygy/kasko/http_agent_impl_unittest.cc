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

#include "syzygy/kasko/http_agent_impl.h"

#include <map>
#include <string>

#include "base/strings/string_number_conversions.h"
#include "gtest/gtest.h"
#include "syzygy/kasko/upload.h"
#include "syzygy/kasko/testing/test_server.h"

namespace kasko {

TEST(HttpAgentImplTest, SimpleUpload) {
  testing::TestServer server;
  ASSERT_TRUE(server.Start());

  base::string16 url =
      L"http://localhost:" + base::UintToString16(server.port()) + L"/path";
  HttpAgentImpl agent_impl(L"test", L"0.0");
  base::string16 response_body;
  uint16_t response_code = 0;
  ASSERT_TRUE(SendHttpUpload(
      &agent_impl, url, std::map<base::string16, base::string16>(),
      "file_contents", L"file_name", &response_body, &response_code));

  EXPECT_EQ(L"file_name=file_contents\r\n", response_body);
  EXPECT_EQ(200, response_code);
}

}  // namespace kasko
