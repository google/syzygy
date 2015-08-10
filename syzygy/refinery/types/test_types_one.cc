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
  short const* volatile* three;
  const volatile unsigned short four;
  unsigned short five : 3;
  unsigned short six : 5;
};

struct TestRecursiveUDT {
  struct TestRecursiveUDT* prev;
  struct TestRecursiveUDT* next;
};

// The following classes are set up to test correct reading of pointer to data
// members and functions.
class A {};
class B {};

class Single : public A {};
class Multi : public A, public B {};
class Virtual : virtual public A {};
class Unknown;

typedef int (Single::*SingleFunc)();
typedef int (Multi::*MultiFunc)();
typedef int (Virtual::*VirtualFunc)();
typedef int (Unknown::*UnknownFunc)();

typedef int* Single::*SingleData;
typedef int* Multi::*MultiData;
typedef int* Virtual::*VirtualData;
typedef int* Unknown::*UnknownData;

// The member pointers sizes as a constants. This way their values appear in
// the symbol stream of the PDB file which allows us to test against them that
// we are assigning the correct sizes.
static const size_t kSingleFuncSize = sizeof(SingleFunc);
static const size_t kMultiFuncSize = sizeof(MultiFunc);
static const size_t kVirtualFuncSize = sizeof(VirtualFunc);
static const size_t kUnknownFuncSize = sizeof(UnknownFunc);

static const size_t kSingleDataSize = sizeof(SingleData);
static const size_t kMultiDataSize = sizeof(MultiData);
static const size_t kVirtualDataSize = sizeof(VirtualData);
static const size_t kUnknownDataSize = sizeof(UnknownData);

struct TestMemberPointersUDT {
  SingleData testSingleDataSize;
  MultiData testMultiDataSize;
  VirtualData testVirtualDataSize;
  UnknownData testUnknownDataSize;

  SingleFunc testSingleFuncSize;
  MultiFunc testMultiFuncSize;
  VirtualFunc testVirtualFuncSize;
  UnknownFunc testUnknownFuncSize;
};

void AliasTypesOne() {
  // Make sure the types are used in the file.
  TestCollidingUDT colliding = {};
  Alias(&colliding);

  TestSimpleUDT simple = {0, 0, 0, 0};
  Alias(&simple);

  TestRecursiveUDT recursive = {};
  Alias(&recursive);

  TestMemberPointersUDT member_data = {};
  Alias(&member_data);
}

}  // namespace testing
