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
// This file declares implementation classes to generate assembly code.
// The API to the assembler is intentionally very close to the API exposed
// by the V8 assembler (see src/ia32/assembler-ia32.* in V8 repository).

#ifndef SYZYGY_ASSM_ASSEMBLER_H_
#define SYZYGY_ASSM_ASSEMBLER_H_

#include "syzygy/assm/assembler_base.h"
#include "syzygy/assm/cond.h"
#include "syzygy/assm/operand_base.h"
#include "syzygy/assm/register.h"
#include "syzygy/assm/value_base.h"

namespace assm {

class AssemblerImpl : public AssemblerBase<const void*> {
 public:
  typedef AssemblerBase<const void*> Super;
  AssemblerImpl(uint32_t location, InstructionSerializer* serializer)
      : Super(location, serializer) {}

  // Expose control flow instructions as public.
  using Super::jmp;
  using Super::j;
  using Super::jecxz;
};

}  // namespace assm

#endif  // SYZYGY_ASSM_ASSEMBLER_H_
