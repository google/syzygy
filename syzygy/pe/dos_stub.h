// Copyright 2012 Google Inc. All Rights Reserved.
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
// Declares a DOS stub which we inject into Syzygy transformed binaries.
// The implementation of the stub is in dos_stub.asm, which is compiled and
// converted to an array.

#ifndef SYZYGY_PE_DOS_STUB_H_
#define SYZYGY_PE_DOS_STUB_H_

#include <stdint.h>

namespace pe {

// Contains 16-bit X86 machine code DOS stub. This is to be injected between
// the DOS header and NT headers in Syzygy transformed binaries.
extern const uint8_t kDosStub[];
extern const size_t kDosStubSize;

}  // namespace pe

#endif  // SYZYGY_PE_DOS_STUB_H_
