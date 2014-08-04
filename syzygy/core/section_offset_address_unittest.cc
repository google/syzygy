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

#include "syzygy/core/section_offset_address.h"

#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"

namespace core {

namespace {

const uint32 kSectionId = 2;
const uint32 kOffset = 0xCAFEBABE;

}  // namespace

TEST(SectionOffsetAddressTest, DefaultInitialization) {
  SectionOffsetAddress address;
  EXPECT_EQ(0, address.section_id());
  EXPECT_EQ(0, address.offset());
}

TEST(SectionOffsetAddressTest, CreateInitialialized) {
  const uint32 kSectionId = 2;
  const uint32 kOffset = 0xCAFEBABE;

  SectionOffsetAddress address(kSectionId, kOffset);

  EXPECT_EQ(kSectionId, address.section_id());
  EXPECT_EQ(kOffset, address.offset());
}

TEST(SectionOffsetAddressTest, ValueComparison) {
  const SectionOffsetAddress::SectionOffset kOne(1, 0);
  const SectionOffsetAddress::SectionOffset kTwo(1, 10);
  const SectionOffsetAddress::SectionOffset kThree(2, 0);

  EXPECT_TRUE(kOne < kTwo);
  EXPECT_FALSE(kOne < kOne);
  EXPECT_FALSE(kTwo < kOne);
  EXPECT_TRUE(kTwo < kThree);
  EXPECT_FALSE(kThree < kOne);
  EXPECT_FALSE(kThree < kTwo);

  EXPECT_TRUE(kOne <= kTwo);
  EXPECT_TRUE(kOne <= kOne);
  EXPECT_FALSE(kTwo <= kOne);
  EXPECT_TRUE(kTwo <= kThree);
  EXPECT_FALSE(kThree <= kOne);
  EXPECT_FALSE(kThree <= kTwo);

  EXPECT_FALSE(kOne > kTwo);
  EXPECT_FALSE(kOne > kOne);
  EXPECT_TRUE(kTwo > kOne);
  EXPECT_FALSE(kTwo > kThree);
  EXPECT_TRUE(kThree > kOne);
  EXPECT_TRUE(kThree > kTwo);

  EXPECT_FALSE(kOne >= kTwo);
  EXPECT_TRUE(kOne >= kOne);
  EXPECT_TRUE(kTwo >= kOne);
  EXPECT_FALSE(kTwo >= kThree);
  EXPECT_TRUE(kThree >= kOne);
  EXPECT_TRUE(kThree >= kTwo);

  const SectionOffsetAddress::SectionOffset kOtherOne(1, 0);
  EXPECT_TRUE(kOne == kOtherOne);
  EXPECT_FALSE(kOne == kTwo);
  EXPECT_FALSE(kOne != kOtherOne);
  EXPECT_TRUE(kOne != kTwo);
}

TEST(SectionOffsetAddressTest, Operators) {
  const SectionOffsetAddress kOne(1, 0);
  const SectionOffsetAddress kTwo(1, 10);
  const SectionOffsetAddress kThree(2, 0);

  EXPECT_TRUE(kOne < kTwo);
  EXPECT_FALSE(kOne < kOne);
  EXPECT_FALSE(kTwo < kOne);
  EXPECT_TRUE(kTwo < kThree);
  EXPECT_FALSE(kThree < kOne);
  EXPECT_FALSE(kThree < kTwo);

  EXPECT_TRUE(kOne <= kTwo);
  EXPECT_TRUE(kOne <= kOne);
  EXPECT_FALSE(kTwo <= kOne);
  EXPECT_TRUE(kTwo <= kThree);
  EXPECT_FALSE(kThree <= kOne);
  EXPECT_FALSE(kThree <= kTwo);

  EXPECT_FALSE(kOne > kTwo);
  EXPECT_FALSE(kOne > kOne);
  EXPECT_TRUE(kTwo > kOne);
  EXPECT_FALSE(kTwo > kThree);
  EXPECT_TRUE(kThree > kOne);
  EXPECT_TRUE(kThree > kTwo);

  EXPECT_FALSE(kOne >= kTwo);
  EXPECT_TRUE(kOne >= kOne);
  EXPECT_TRUE(kTwo >= kOne);
  EXPECT_FALSE(kTwo >= kThree);
  EXPECT_TRUE(kThree >= kOne);
  EXPECT_TRUE(kThree >= kTwo);

  SectionOffsetAddress addr(kOne);
  EXPECT_TRUE(kOne == addr);
  EXPECT_FALSE(addr == kTwo);
  EXPECT_FALSE(kOne != addr);
  EXPECT_TRUE(addr != kTwo);
  EXPECT_EQ(1, addr.section_id());
  EXPECT_EQ(0, addr.offset());

  EXPECT_TRUE(kOne + 10 == kTwo);
  EXPECT_TRUE(kOne == kTwo - 10);

  addr += 10;
  EXPECT_TRUE(addr == kTwo);
  addr -= 10;
  EXPECT_TRUE(addr == kOne);

  addr = kThree;
  EXPECT_TRUE(addr == kThree);
}

TEST(SectionOffsetAddressTest, SetValue) {
  SectionOffsetAddress address(0, 0);
  address.set_value(SectionOffsetAddress::SectionOffset(kSectionId, kOffset));

  EXPECT_EQ(kSectionId, address.value().section_id);
  EXPECT_EQ(kOffset, address.value().offset);
}

TEST(SectionOffsetAddressTest, SetSectionId) {
  SectionOffsetAddress address(0, 0);
  address.set_section_id(kSectionId);
  EXPECT_EQ(kSectionId, address.value().section_id);
}

TEST(SectionOffsetAddressTest, SetOffset) {
  SectionOffsetAddress address(0, 0);
  address.set_offset(kOffset);
  EXPECT_EQ(kOffset, address.value().offset);
}

TEST(SectionOffsetAddressTest, AlignUp) {
  const SectionOffsetAddress one(0, 1);
  const SectionOffsetAddress two(0, 2);
  const SectionOffsetAddress four(0, 4);
  const SectionOffsetAddress eight(0, 8);
  const SectionOffsetAddress sixteen(0, 16);

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

TEST(SectionOffsetAddressTest, GetAlignment) {
  const uint32 max_alignment = 512;

  const SectionOffsetAddress zero(0, 0);
  EXPECT_EQ(max_alignment, zero.GetAlignment());
  const SectionOffsetAddress one(0, 1);

  for (uint32 i = 1; i <= max_alignment; i <<= 1) {
    SectionOffsetAddress address(0, i);
    EXPECT_EQ(i, address.GetAlignment());
  }

  SectionOffsetAddress big_offset(0, 1024);
  EXPECT_EQ(max_alignment, big_offset.GetAlignment());
}

TEST(SectionOffsetAddressTest, Serialization) {
  const SectionOffsetAddress address(5, 42);

  EXPECT_TRUE(testing::TestSerialization(address));
}

}  // namespace core
