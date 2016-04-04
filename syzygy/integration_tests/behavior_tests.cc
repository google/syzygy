// Copyright 2013 Google Inc. All Rights Reserved.
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
#include "syzygy/integration_tests/behavior_tests.h"

namespace testing {

unsigned int ArrayComputation1() {
  // Dummy function to validate end to end instrumentation.
  const size_t kBufferLength = 1024;
  char A[kBufferLength];
  short B[kBufferLength];
  int C[kBufferLength];

  for (size_t i = 0; i < kBufferLength; ++i) {
    if (i == 0)
      A[i] = 0;
    else
      A[i] = 3*A[i-1] + 11;
  }

  for (size_t i = 0; i < kBufferLength; ++i) {
    B[i] = static_cast<short>(i);
    B[i] += A[i];
    B[i] = (B[i] << 1) ^ B[i];
  }

  for (size_t i = 0; i < kBufferLength; ++i) {
    C[i] = i;
    C[i] += A[i] + B[i];
    C[i] = ~C[i];
  }

  unsigned int sum = 0;
  for (int i = 0; i < kBufferLength; ++i) {
    sum += C[i] - (A[i] - B[i]);
  }

  return sum;
}

unsigned int ArrayComputation2() {
  // Dummy function to validate end to end instrumentation.
  const size_t kBufferLength = 1024;
  int A[kBufferLength];

  for (size_t i = 0; i < kBufferLength; ++i) {
    A[i] = i;
  }

  int *ptr1 = &A[0];
  int *ptr2 = &A[kBufferLength-1];
  int result = 0;
  while (*ptr1 <= *ptr2) {
    ptr1++;
    ptr2--;
    result++;
  }

  return result;
}

}  // namespace testing
