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

#include "syzygy/assm/unittest_util.h"

namespace testing {

// Definitions of various length NOP codes for 32-bit X86. We use the same
// ones that are typically used by MSVC and recommended by Intel in
// the Intel Architecture Software Developer's manual, page 4-8.

// NOP (XCHG EAX, EAX)
const uint8_t kNop1[1] = {0x90};
// 66 NOP
const uint8_t kNop2[2] = {0x66, 0x90};
// LEA REG, 0 (REG) (8-bit displacement)
const uint8_t kNop3[3] = {0x66, 0x66, 0x90};
// NOP DWORD PTR [EAX + 0] (8-bit displacement)
const uint8_t kNop4[4] = {0x0F, 0x1F, 0x40, 0x00};
// NOP DWORD PTR [EAX + EAX*1 + 0] (8-bit displacement)
const uint8_t kNop5[5] = {0x0F, 0x1F, 0x44, 0x00, 0x00};
// LEA REG, 0 (REG) (32-bit displacement)
const uint8_t kNop6[6] = {0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00};
// LEA REG, 0 (REG) (32-bit displacement)
const uint8_t kNop7[7] = {0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00};
// NOP DWORD PTR [EAX + EAX*1 + 0] (32-bit displacement)
const uint8_t kNop8[8] = {0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00};
// NOP WORD  PTR [EAX + EAX*1 + 0] (32-bit displacement)
const uint8_t kNop9[9] = {
    0x66,  // Prefix,
    0x0F,
    0x1F,
    0x84,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00  // kNop8.
};
const uint8_t kNop10[10] = {
    0x66,
    0x66,  // Prefix,
    0x0F,
    0x1F,
    0x84,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00  // kNop8.
};
const uint8_t kNop11[11] = {
    0x66,
    0x66,
    0x66,  // Prefix,
    0x0F,
    0x1F,
    0x84,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00  // kNop8.
};

// Collect all of the various NOPs in an array indexable by their length.
const uint8_t* kNops[12] = {nullptr,
                            kNop1,
                            kNop2,
                            kNop3,
                            kNop4,
                            kNop5,
                            kNop6,
                            kNop7,
                            kNop8,
                            kNop9,
                            kNop10,
                            kNop11};

}  // namespace testing
