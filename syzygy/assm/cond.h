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
//
// This file declares implementation classes to generate assembly code.
// The API to the assembler is intentionally very close to the API exposed
// by the V8 assembler (see src/ia32/assembler-ia32.* in V8 repository).

#ifndef SYZYGY_ASSM_COND_H_
#define SYZYGY_ASSM_COND_H_

#include "syzygy/assm/register.h"

namespace assm {

// The condition codes by which conditional branches are determined. This enum
// is taken from the V8 project, and has the property that the conditions are
// defined to be bit-wise ORed into the base conditional branch opcode, and
// they can be easily negated/inverted.
//
// See:
//     http://code.google.com/p/v8/source/browse/trunk/src/ia32/assembler-ia32.h
enum ConditionCode {
  // Any value < 0 is considered no_condition
  kNoCondition  = -1,

  kOverflow =  0,
  kNoOverflow =  1,
  kBelow =  2,
  kAboveEqual =  3,
  kEqual =  4,
  kNotEqual =  5,
  kBelowEqual =  6,
  kAbove =  7,
  kNegative =  8,
  kPositive =  9,
  kParityEven = 10,
  kParityOdd = 11,
  kLess = 12,
  kGreaterEqual = 13,
  kLessEqual = 14,
  kGreater = 15,

  // Aliases.
  kCarry = kBelow,
  kNotCarry = kAboveEqual,
  kZero = kEqual,
  kNotZero = kNotEqual,
  kSign = kNegative,
  kNotSign = kPositive,

  // Extents.
  kMinConditionCode = 0,
  kMaxConditionCode = 15
};

// The conditions on which a loop instruction should branch. These are modeled
// in the same manner as ConditionCode (above).
enum LoopCode {
  kLoopOnCounterAndNotZeroFlag = 0,  // LOOPNE and LOOPNZ
  kLoopOnCounterAndZeroFlag = 1,  // LOOPE and NOOPZ.
  kLoopOnCounter = 2,  // LOOP.
};

inline ConditionCode NegateConditionCode(ConditionCode cc) {
  DCHECK_GT(16, cc);
  return static_cast<ConditionCode>(cc ^ 1);
}

}  // namespace assm

#endif  // SYZYGY_ASSM_COND_H_
