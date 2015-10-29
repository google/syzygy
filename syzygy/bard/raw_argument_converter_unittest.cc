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

#include "syzygy/bard/raw_argument_converter.h"

#include "gtest/gtest.h"

namespace bard {

class RawArgumentConverterTest : public testing::Test {
 public:
  RawArgumentConverterTest() : ui8_(0u), ui16_(0u), ui32_(0u) {}

  uint8_t ui8_;
  uint16_t ui16_;
  uint32_t ui32_;
};

TEST_F(RawArgumentConverterTest, TestOneByte) {
  uint8_t value = 234;
  uint32_t size = sizeof(value);
  uint8_t* ptr = &value;

  RawArgumentConverter arg(ptr, size);

  EXPECT_TRUE(arg.RetrieveAs(&ui8_));
  EXPECT_EQ(value, ui8_);
  EXPECT_FALSE(arg.RetrieveAs(&ui16_));
  EXPECT_FALSE(arg.RetrieveAs(&ui32_));
}

TEST_F(RawArgumentConverterTest, TestTwoBytes) {
  uint16_t value = 60123;
  uint32_t size = sizeof(value);
  uint8_t* ptr = reinterpret_cast<uint8_t*>(&value);

  RawArgumentConverter arg(ptr, size);

  EXPECT_FALSE(arg.RetrieveAs(&ui8_));
  EXPECT_TRUE(arg.RetrieveAs(&ui16_));
  EXPECT_EQ(value, ui16_);
  EXPECT_FALSE(arg.RetrieveAs(&ui32_));
}

TEST_F(RawArgumentConverterTest, TestFourBytes) {
  uint32_t value = 4294912345;
  uint32_t size = sizeof(value);
  uint8_t* ptr = reinterpret_cast<uint8_t*>(&value);

  RawArgumentConverter arg(ptr, size);

  EXPECT_FALSE(arg.RetrieveAs(&ui8_));
  EXPECT_FALSE(arg.RetrieveAs(&ui16_));
  EXPECT_TRUE(arg.RetrieveAs(&ui32_));
  EXPECT_EQ(value, ui32_);
}

}  // namespace bard
