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
//
// Declares some unittest helpers.

#ifndef SYZYGY_ASSM_UNITTEST_UTIL_H_
#define SYZYGY_ASSM_UNITTEST_UTIL_H_

#include "base/basictypes.h"

namespace testing {

// Definitions of various length NOP codes for 32-bit X86. We use the same
// ones that are typically used by MSVC and recommended by Intel in
// the Intel Architecture Software Developer's manual, page 4-8.

extern const uint8 kNop1[1];
extern const uint8 kNop2[2];
extern const uint8 kNop3[3];
extern const uint8 kNop4[4];
extern const uint8 kNop5[5];
extern const uint8 kNop6[6];
extern const uint8 kNop7[7];
extern const uint8 kNop8[8];
extern const uint8 kNop9[9];
extern const uint8 kNop10[10];
extern const uint8 kNop11[11];

// Collect all of the various NOPs in an array indexable by their length.
extern const uint8* kNops[12];

}  // namespace testing

#endif  // SYZYGY_ASSM_UNITTEST_UTIL_H_
