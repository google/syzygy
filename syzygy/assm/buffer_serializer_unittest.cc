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

#include "syzygy/assm/buffer_serializer.h"

#include "gtest/gtest.h"
#include "syzygy/assm/unittest_util.h"

namespace assm {

class BufferSerializerTest : public testing::Test {
 public:
  BufferSerializerTest() {
  }

  void NopTest(size_t nop_size) {
    const size_t kOffset = 5U;
    const size_t kBufferSize = 1024U;

    // Initialize buffer.
    uint8_t buffer[kBufferSize];
    ::memset(buffer, 0, kBufferSize);

    // Assemble a NOP into the buffer.
    BufferSerializer bs(buffer, kBufferSize);
    AssemblerImpl asm_(reinterpret_cast<uint32_t>(&buffer[kOffset]), &bs);
    asm_.nop(nop_size);

    // Should not touch any bytes before offset.
    for (size_t i = 0; i < kOffset; ++i) {
      EXPECT_EQ(0U, buffer[i]);
    }

    // Should write the proper NOP.
    for (size_t i = 0; i < nop_size; ++i) {
      EXPECT_EQ(testing::kNops[nop_size][i], buffer[kOffset + i]);
    }

    // Should not touch any bytes after the NOP.
    for (size_t i = kOffset + nop_size; i < kBufferSize; ++i) {
      EXPECT_EQ(0U, buffer[i]);
    }
  }
};

TEST_F(BufferSerializerTest, Nop) {
  const size_t kMaxNopSizeToTest = 10;

  for (size_t nop_size = 0; nop_size <= kMaxNopSizeToTest; ++nop_size) {
    NopTest(nop_size);
  }
}

}  // namespace assm
