// Copyright 2011 Google Inc. All Rights Reserved.
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

#include "syzygy/core/address.h"

#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"

namespace core {

TEST(AddressTest, DefaultInitialization) {
  EXPECT_EQ(0, RelativeAddress().value());
  EXPECT_EQ(0, AbsoluteAddress().value());
  EXPECT_EQ(0, FileOffsetAddress().value());
}

TEST(AddressTest, CreateInitialialized) {
  const size_t kAddress = 0xCAFEBABE;
  EXPECT_EQ(kAddress, RelativeAddress(kAddress).value());
  EXPECT_EQ(kAddress, AbsoluteAddress(kAddress).value());
  EXPECT_EQ(kAddress, FileOffsetAddress(kAddress).value());
}

TEST(AddressTest, Operators) {
  const RelativeAddress kOne(1);
  const RelativeAddress kTwo(2);
  const RelativeAddress kThree(3);

  EXPECT_TRUE(kOne < kTwo);
  EXPECT_FALSE(kOne < kOne);
  EXPECT_FALSE(kTwo < kOne);

  EXPECT_TRUE(kOne <= kOne);
  EXPECT_TRUE(kOne <= kTwo);
  EXPECT_FALSE(kTwo <= kOne);

  EXPECT_FALSE(kOne > kTwo);
  EXPECT_TRUE(kTwo > kOne);

  RelativeAddress addr(kOne);

  EXPECT_TRUE(kOne == addr);
  EXPECT_FALSE(addr == kTwo);

  EXPECT_TRUE(kOne + 1 == kTwo);
  EXPECT_TRUE(kOne == kTwo - 1);
  EXPECT_EQ(1, kTwo - kOne);

  EXPECT_EQ(1, addr.value());
  addr.set_value(2);
  EXPECT_EQ(2, addr.value());

  addr += 1;
  EXPECT_TRUE(addr == kThree);
  addr -= 1;
  EXPECT_TRUE(addr == kTwo);
}

TEST(AddressTest, AlignUp) {
  const RelativeAddress one(1);
  const RelativeAddress two(2);
  const RelativeAddress four(4);
  const RelativeAddress eight(8);
  const RelativeAddress sixteen(16);

  EXPECT_EQ(one.AlignUp(1), one);
  EXPECT_EQ(one.AlignUp(2), two);
  EXPECT_EQ(one.AlignUp(4), four);
  EXPECT_EQ(one.AlignUp(8), eight);
  EXPECT_EQ(one.AlignUp(16), sixteen);

  EXPECT_TRUE(one.AlignUp(1).IsAligned(1));
  EXPECT_TRUE(one.AlignUp(2).IsAligned(2));
  EXPECT_TRUE(one.AlignUp(4).IsAligned(4));
  EXPECT_TRUE(one.AlignUp(8).IsAligned(8));
  EXPECT_TRUE(one.AlignUp(16).IsAligned(16));
}

TEST(AddressTest, GetAlignment) {
  const uint32_t max_alignment = 0x80000000;

  const RelativeAddress zero(0);
  EXPECT_EQ(max_alignment, zero.GetAlignment());
  const RelativeAddress one(1);

  for (uint32_t i = 1; i < max_alignment; i <<= 1) {
    RelativeAddress address(i);
    EXPECT_EQ(i, address.GetAlignment());
  }

  RelativeAddress max_address(max_alignment);
  EXPECT_EQ(max_alignment, max_address.GetAlignment());
}

TEST(AddressTest, Serialization) {
  const RelativeAddress address(42);

  EXPECT_TRUE(testing::TestSerialization(address));
}

TEST(AddressTest, AddressVariant) {
  AddressVariant a0;
  EXPECT_EQ(kRelativeAddressType, a0.type());
  EXPECT_EQ(0u, a0.value());

  AddressVariant a1(kRelativeAddressType, 0);
  EXPECT_EQ(kRelativeAddressType, a1.type());
  EXPECT_EQ(0u, a1.value());

  AddressVariant a2(kAbsoluteAddressType, 0);
  EXPECT_EQ(kAbsoluteAddressType, a2.type());
  EXPECT_EQ(0u, a2.value());

  AddressVariant a3(kFileOffsetAddressType, 0);
  EXPECT_EQ(kFileOffsetAddressType, a3.type());
  EXPECT_EQ(0u, a3.value());

  AddressVariant a3_copy(a3);
  EXPECT_EQ(kFileOffsetAddressType, a3_copy.type());
  EXPECT_EQ(0u, a3_copy.value());

  EXPECT_NE(a1, a2);
  EXPECT_NE(a1, a3);
  EXPECT_NE(a2, a1);
  EXPECT_NE(a2, a3);
  EXPECT_NE(a3, a1);
  EXPECT_NE(a3, a2);

  // Comparisons.

  EXPECT_TRUE(a1 < a2);
  EXPECT_TRUE(a1 <= a3);
  EXPECT_TRUE(a3 > a2);
  EXPECT_TRUE(a3 >= a1);

  // Mutators.

  a2.set_type(kRelativeAddressType);
  EXPECT_EQ(kRelativeAddressType, a2.type());
  EXPECT_EQ(a1, a2);

  a2.set_value(0xBAAD);
  EXPECT_EQ(0xBAADu, a2.value());
  a2.set_value(0);
  EXPECT_EQ(0u, a2.value());

  // Arithmetic operations.

  a2 += 1;
  EXPECT_EQ(1u, a2.value());
  EXPECT_NE(a1, a2);

  a2 -= 1;
  EXPECT_EQ(0u, a2.value());
  EXPECT_EQ(a1, a2);

  a1 = a3;
  EXPECT_EQ(kFileOffsetAddressType, a1.type());
  EXPECT_EQ(0u, a3.value());
  EXPECT_EQ(a1, a3);

  a2 = a3 + 2;
  EXPECT_EQ(2u, a2.value());
  EXPECT_NE(a2, a3);

  a3 += 2;
  EXPECT_EQ(2u, a3.value());
  EXPECT_EQ(a2, a3);

  a3 = a3.AlignUp(4);
  EXPECT_EQ(4u, a3.value());
  a3 = a3.AlignUp(4);
  EXPECT_EQ(4u, a3.value());

  // Assignment from concrete types.

  RelativeAddress rel(47);
  AbsoluteAddress abso(82);
  FileOffsetAddress off(13);

  a1 = rel;
  EXPECT_EQ(rel.type(), a1.type());
  EXPECT_EQ(rel.value(), a1.value());

  a2 = abso;
  EXPECT_EQ(abso.type(), a2.type());
  EXPECT_EQ(abso.value(), a2.value());

  a3 = off;
  EXPECT_EQ(off.type(), a3.type());
  EXPECT_EQ(off.value(), a3.value());

  // Extraction of concrete types.

  RelativeAddress rel2;
  AbsoluteAddress abso2;
  FileOffsetAddress off2;
  EXPECT_TRUE(a1.Extract(&rel2));
  EXPECT_EQ(rel, rel2);
  EXPECT_TRUE(a2.Extract(&abso2));
  EXPECT_EQ(abso, abso2);
  EXPECT_TRUE(a3.Extract(&off2));
  EXPECT_EQ(off, off2);
  EXPECT_FALSE(a1.Extract(&abso));
  EXPECT_FALSE(a1.Extract(&off));
}

}  // namespace core
