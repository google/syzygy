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

#include "syzygy/kasko/internet_unittest_helpers.h"

#include <algorithm>

#include "base/strings/utf_string_conversions.h"
#include "gtest/gtest.h"

namespace kasko {

void ExpectMultipartMimeMessageIsPlausible(
    const base::string16& boundary,
    const std::map<base::string16, base::string16>& parameters,
    const std::string& file,
    const std::string& file_part_name,
    const std::string& body) {
  std::string::const_iterator range_begin = body.begin();
  if (!parameters.empty()) {
    std::string key = base::WideToUTF8(parameters.begin()->first);
    std::string value = base::WideToUTF8(parameters.begin()->second);
    range_begin = std::search(range_begin, body.end(), key.begin(), key.end());
    EXPECT_NE(range_begin, body.end());
    range_begin =
        std::search(range_begin, body.end(), value.begin(), value.end());
    EXPECT_NE(range_begin, body.end());
  }

  range_begin =
      std::search(range_begin, body.end(), boundary.begin(), boundary.end());
  EXPECT_NE(range_begin, body.end());
  range_begin = std::search(range_begin, body.end(), file_part_name.begin(),
                            file_part_name.end());
  EXPECT_NE(range_begin, body.end());
  range_begin = std::search(range_begin, body.end(), file.begin(), file.end());
  EXPECT_NE(range_begin, body.end());
}

}  // namespace kasko
