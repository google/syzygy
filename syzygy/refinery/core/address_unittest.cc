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

#include "syzygy/refinery/core/address.h"

#include "gtest/gtest.h"

namespace refinery {

TEST(AddressTest, ConversionTest) {
  // An integer with its most significant bit set.
  uint32_t integer = 0xffffffff;

  // The expected address corresponding to this integer.
  Address expected_address = static_cast<Address>(integer);
  ASSERT_EQ(0xffffffffULL, expected_address);

  // The coresponding pointer with its most significant bit set (note: this is a
  // 32 bit test).
  int* ptr = reinterpret_cast<int*>(integer);

  // Validate conversion is as expected.
  ASSERT_EQ(expected_address,
            static_cast<Address>(reinterpret_cast<uintptr_t>(ptr)));
}

TEST(AddressRangeTest, IsValid) {
  // TODO(siggi): IsValid is sort of a nonsense check, as the size of the
  //     address space needs to go into it.
  //     Move this check to the ProcessState.

  // The empty range is not valid.
  AddressRange range;
  EXPECT_TRUE(range.IsEmpty());
  EXPECT_FALSE(range.IsValid());

  range = AddressRange(UINT64_MAX, 1);
  EXPECT_FALSE(range.IsValid());

  range = AddressRange(UINT64_MAX - UINT32_MAX + 1, UINT32_MAX);
  EXPECT_FALSE(range.IsValid());

  range = AddressRange(UINT64_MAX - UINT32_MAX, UINT32_MAX);
  EXPECT_TRUE(range.IsValid());

  // Empty range anywhere is not valid.
  range = AddressRange(100, 0);
  EXPECT_FALSE(range.IsValid());

  range = AddressRange(100, 1);
  EXPECT_TRUE(range.IsValid());
}

}  // namespace refinery
