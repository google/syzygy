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

#include "syzygy/refinery/types/test_types.h"

namespace testing {

namespace {

// This type is declared in the anonymous namespace to allow "colliding" on
// the type name from another compilation unit.
struct TestCollidingUDT {
  int first;
  int second;
};

}  // namespace

// Used to test UDTs in DiaCrawlerTests.
struct TestSimpleUDT {
  int one;
  const char two;
  short const* volatile three;
  const volatile unsigned short four;
  unsigned short five : 3;
  unsigned short six : 5;
};

struct TestRecursiveUDT {
  struct TestRecursiveUDT* prev;
  struct TestRecursiveUDT* next;
};

void AliasTypesOne() {
  // Make sure the types are used in the file.
  TestCollidingUDT colliding = {};
  Alias(&colliding);

  TestSimpleUDT simple = {0, 0, 0, 0};
  Alias(&simple);

  TestRecursiveUDT recursive = {};
  Alias(&recursive);
}

}  // namespace testing
