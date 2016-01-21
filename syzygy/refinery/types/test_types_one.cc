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

#include <cstddef>

#include "syzygy/refinery/types/alias.h"
#include "syzygy/refinery/types/test_types.h"

namespace testing {

namespace {

// Set the important sizes.
REGISTER_SIZEOF(Pointer, void*);
REGISTER_SIZEOF(IndexingType, size_t);

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

REGISTER_SIZEOF_TYPE(TestSimpleUDT);

struct TestRecursiveUDT {
  struct TestRecursiveUDT* prev;
  struct TestRecursiveUDT* next;
};

REGISTER_SIZEOF_TYPE(TestRecursiveUDT);

// Struct to test references, constructor is needed because references cannot be
// default-initialized.
struct TestReference {
  TestReference() : value(42), reference(value) {}

  int value;
  const int& reference;
};

struct TestArrays {
  const int int_array[30];
  TestRecursiveUDT* volatile (*array_ptr)[32];
};

struct TestFunctions {
  TestFunctions() {}
  void NonOverloadedFunction() {}
  int OverloadedFunction() { return 42; }
  void OverloadedFunction(int arg) {}
};

enum UnderlyingEnum : short { first_value, second_value };

struct TestBitfields {
  TestBitfields() : const_enum_bitfield(first_value) {}
  bool bool_bitfield : 1;
  int int_bitfield : 1;
  UnderlyingEnum enum_bitfield : 1;
  const UnderlyingEnum const_enum_bitfield : 1;
};

union TestUnion {
  int signed_int;
  unsigned int unsigned_int;
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

// Sizes of the member pointers.
REGISTER_SIZEOF_TYPE(SingleFunc);
REGISTER_SIZEOF_TYPE(MultiFunc);
REGISTER_SIZEOF_TYPE(VirtualFunc);
REGISTER_SIZEOF_TYPE(UnknownFunc);

REGISTER_SIZEOF_TYPE(SingleData);
REGISTER_SIZEOF_TYPE(MultiData);
REGISTER_SIZEOF_TYPE(VirtualData);
REGISTER_SIZEOF_TYPE(UnknownData);

struct TestMemberPointersUDT {
  SingleData testSingleData;
  MultiData testMultiData;
  VirtualData testVirtualData;
  UnknownData testUnknownData;

  SingleFunc testSingleFunc;
  MultiFunc testMultiFunc;
  VirtualFunc testVirtualFunc;
  UnknownFunc testUnknownFunc;
};

REGISTER_SIZEOF_TYPE(TestMemberPointersUDT);

struct TestAllInOneUDT : public A, virtual public B {
  static int static_member;
  void NonOverloadedMethod() {}
  void OverloadedMethod() {}
  const char OverloadedMethod(int arg) { return 'a'; }
  virtual void VirtualMethod() {}

  struct NestedType {
    int inner_member;
  };

  int regular_member;
};

REGISTER_SIZEOF_TYPE(TestAllInOneUDT);
REGISTER_OFFSETOF(TestAllInOneUDT, regular_member);

class ComplicatedTypeB;
class ComplicatedTypeA;

class ComplicatedTypeA {
  void (ComplicatedTypeB::*ptr)(ComplicatedTypeA);
};

class ComplicatedTypeB {
  void Function(ComplicatedTypeA a) {}
};

struct TestNullptrType {
  nullptr_t nullptr_type;
};

TestAllInOneUDT test_global;

void AliasTypesOne() {
  // Make sure the types are used in the file.
  TestCollidingUDT colliding = {};
  Alias(&colliding);

  TestSimpleUDT simple = {0, 0, 0, 0};
  Alias(&simple);

  TestRecursiveUDT recursive = {};
  Alias(&recursive);

  TestReference references = {};
  Alias(&references);

  TestArrays arrays = {{0}};
  Alias(&arrays);

  TestFunctions functions;
  Alias(&functions);

  TestBitfields bitfields = {};
  Alias(&bitfields);

  TestMemberPointersUDT member_data = {};
  Alias(&member_data);

  TestAllInOneUDT all_in_one = {};
  Alias(&all_in_one);

  TestNullptrType nullptr_type = {};
  Alias(&nullptr_type);

  TestUnion union_type = {};
  Alias(&union_type);

  Alias(&test_global);
}

}  // namespace testing
