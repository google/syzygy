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

#include "syzygy/refinery/types/test_typenames.h"

#include "syzygy/refinery/types/alias.h"

namespace testing {

struct TestUDT {
  TestUDT() : integer(42), reference(integer) {}

  int integer;

  const int& reference;
  const volatile TestUDT* pointer;

  char array[5];
  volatile char constant_array[5];
};

enum TestEnum { ONE, TWO };

void FunctionWithNoParams() {}
struct TestFunctions {
  const char MethodWithParams(const int one, char two) { return 'a'; }
};

void AliasTypes() {
  // Make sure the types are used in the file.

  // Pull in a UDT, a basic type, a pointer, a reference and arrays.
  TestUDT simple = {};
  Alias(&simple);

  // Pull in an enum.
  TestEnum some_enum = ONE;
  Alias(&some_enum);

  // Pull in functions.
  Alias(FunctionWithNoParams);
  TestFunctions functions;
  Alias(&functions);
}

}  // namespace testing
