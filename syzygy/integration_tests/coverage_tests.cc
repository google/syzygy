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

// NOTE: Do *NOT* modify line number because this file is used for testing end
// to end coverage.

namespace testing {

// Avoid any optimization.
#pragma optimize("", off)

int always_zero = 0;
int always_one = 1;

int coverage_func1() {
  int sum = 2;
  for (int i = 0; i < 10; ++i)
    sum += 4 * i;
  return sum;
}

int coverage_func2() {
  int sum = 2;
  if (always_one) {
    for (int i = 0; i < 10; ++i)
      sum += 4 * i;
  } else {
    // This is never executed.
    always_one = 0;
  }
  return sum;
}

int coverage_func3() {
  int sum = 2;
  if (always_zero) {
    // This is never executed.
    for (int i = 0; i < 10; ++i)
      sum += 4 * i;
  } else {
    always_one = 0;
  }
  return sum;
}

}  // namespace testing
