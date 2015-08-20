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

TEST(RawArgumentConverterTest, TestOneByte) {
  uint8_t value = 234;
  uint32_t size = sizeof(value);
  uint8_t* ptr = &value;

  RawArgumentConverter arg(ptr, size);

  EXPECT_EQ(value, arg.RetrieveAs<uint8_t>());
}

TEST(RawArgumentConverterTest, TestTwoBytes) {
  uint16_t value = 60123;
  uint32_t size = sizeof(value);
  uint8_t* ptr = reinterpret_cast<uint8_t*>(&value);

  RawArgumentConverter arg(ptr, size);

  EXPECT_EQ(value, arg.RetrieveAs<uint16_t>());
}

TEST(RawArgumentConverterTest, TestFourBytes) {
  uint32_t value = 4294912345;
  uint32_t size = sizeof(value);
  uint8_t* ptr = reinterpret_cast<uint8_t*>(&value);

  RawArgumentConverter arg(ptr, size);

  EXPECT_EQ(value, arg.RetrieveAs<uint32_t>());
}

}  // namespace bard
