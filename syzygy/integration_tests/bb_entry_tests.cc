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

#include "syzygy/integration_tests/bb_entry_tests.h"

// Avoiding global optimization.
#pragma optimize("g", off)

unsigned int BBEntryCallOnce() {
  return 42;
}

unsigned int BBEntryFunction1() {
  return 10;
}

unsigned int BBEntryFunction2() {
  return BBEntryFunction1() + BBEntryFunction1();
}

unsigned int BBEntryFunction3() {
  return BBEntryFunction2() + BBEntryFunction2();
}

unsigned int BBEntryCallTree() {
  return BBEntryFunction3() + 2;
}

unsigned int BBEntryFunctionRecursive(int n) {
  if (n == 1)
    return 1;
  return BBEntryFunctionRecursive(n - 1) + 1;
}

unsigned int BBEntryCallRecursive() {
  return BBEntryFunctionRecursive(42);
}
