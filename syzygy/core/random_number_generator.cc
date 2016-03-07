// Copyright 2011 Google Inc. All Rights Reserved.
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

#include "syzygy/core/random_number_generator.h"
#include "base/logging.h"

// This is a linear congruent pseudo random generator.
// See: http://en.wikipedia.org/wiki/Linear_congruential_generator.

namespace {

const int kA = 1103515245;
const int kC = 12345;

}  // namespace

namespace core {

RandomNumberGenerator::RandomNumberGenerator(uint32_t seed) : seed_(seed) {
}

uint32_t RandomNumberGenerator::operator()(uint32_t n) {
  // The generator is g(N + 1) = (g(N) * kA + kC) mod 2^32.
  // The use of unsigned 32 bit values yields the mod 2^32 for free.
  seed_ = seed_ * kA + kC;
  uint32_t ret = seed_ % n;
  DCHECK_GT(n, ret);
  return ret;
}

}  // namespace core
