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
#include "syzygy/msf/msf_constants.h"

namespace msf {

const uint8_t kMsfHeaderMagicString[kMsfHeaderMagicStringSize] = {
    0x4D, 0x69, 0x63, 0x72, 0x6F,
    0x73, 0x6F, 0x66,  // "Microsof"
    0x74, 0x20, 0x43, 0x2F, 0x43,
    0x2B, 0x2B, 0x20,  // "t C/C++ "
    0x4D, 0x53, 0x46, 0x20, 0x37,
    0x2E, 0x30, 0x30,  // "MSF 7.00"
    0x0D, 0x0A, 0x1A, 0x44, 0x53,
    0x00, 0x00, 0x00  // "^^^DS^^^"
};

}  // namespace msf
