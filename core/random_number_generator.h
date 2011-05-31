// Copyright 2011 Google Inc.
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

#ifndef SYZYGY_CORE_RANDOM_NUMBER_GENERATOR_H_
#define SYZYGY_CORE_RANDOM_NUMBER_GENERATOR_H_

#include "base/basictypes.h"

namespace core {

// This is a linear congruent pseudo random generator.
// See: http://en.wikipedia.org/wiki/Linear_congruential_generator.
class RandomNumberGenerator {
 public:
  explicit RandomNumberGenerator(uint32 seed);

  // Makes the random number generator callable (with the given modulus).
  uint32 operator()(uint32 n);

 private:
  uint32 seed_;
};

}  // namespace core

#endif  // SYZYGY_CORE_RANDOM_NUMBER_GENERATOR_H_
