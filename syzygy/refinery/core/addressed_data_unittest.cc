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

#include "syzygy/refinery/core/addressed_data.h"

#include "gtest/gtest.h"

namespace refinery {

TEST(AddressedDataTest, BasicTest) {
  // Create an address range.
  const Address kAddress = 80ULL;
  const char kBuffer[] = "abcdef";
  const AddressRange range(kAddress, sizeof(kBuffer));
  AddressedData data(range, reinterpret_cast<const void*>(kBuffer));

  // Retrieving from outside the range fails.
  char retrieved;
  ASSERT_FALSE(data.GetAt(kAddress - 1, &retrieved));
  ASSERT_FALSE(data.GetAt(kAddress + sizeof(kBuffer), &retrieved));

  // Retrieving the head succeeds.
  retrieved = '-';
  ASSERT_TRUE(data.GetAt(kAddress, &retrieved));
  ASSERT_EQ('a', retrieved);

  // Retrieving into the range succeeds.
  retrieved = '-';
  ASSERT_TRUE(data.GetAt(kAddress + 5, &retrieved));
  ASSERT_EQ('f', retrieved);
}

}  // namespace refinery
