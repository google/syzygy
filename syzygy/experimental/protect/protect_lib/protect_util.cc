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

#include "syzygy/protect/protect_lib/protect_util.h"
#include <algorithm>
#include <ctime>
#include <iostream>
#include <vector>

unsigned int VectGenerator::_kSum = 256;

std::vector<uint8>* VectGenerator::Generate(uint8 x, int len)
{
  unsigned int max_sum = _kSum - x;
  int rand_num;
  std::vector<uint8> *values = new std::vector<uint8>();

  if (max_sum < 0) {
    return NULL;
  }

  std::srand(unsigned(std::time(0)));

  for (int i = 0; i < len - 1; ++i) {
    rand_num = std::rand() % max_sum;
    values->push_back(rand_num);

    max_sum -= rand_num;

    if (max_sum < 0) {
      return NULL;
    }
  }

  values->push_back(max_sum);

  std::random_shuffle(values->begin(), values->end());

  return values;
}
