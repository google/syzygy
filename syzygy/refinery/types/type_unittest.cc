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

#include "syzygy/refinery/types/type.h"

#include "gtest/gtest.h"

namespace refinery {

TEST(TypesTest, BasicType) {
  // Create a BasicType and store in a supertype pointer.
  TypePtr type = new BasicType(L"foo", 10);

  ASSERT_TRUE(type.get());
  // Verify the kind and fields.
  EXPECT_EQ(Type::BasicKind, type->kind());
  EXPECT_EQ(L"foo", type->name());
  EXPECT_EQ(10U, type->size());

  // Down-cast it.
  BasicTypePtr basic_type;
  ASSERT_TRUE(type->CastTo(&basic_type));
  ASSERT_TRUE(basic_type);

  // Verify that it can't be cast to a PointerType.
  PointerTypePtr ptr;
  EXPECT_FALSE(basic_type->CastTo(&ptr));
  EXPECT_FALSE(ptr.get());
}

TEST(TypesTest, BitfieldType) {
  // Create a BasicType and store in a supertype pointer.
  TypePtr type = new BitfieldType(L"bar", 4, 3, 1);

  ASSERT_TRUE(type.get());
  // Verify the kind and fields.
  EXPECT_EQ(Type::BitfieldKind, type->kind());
  EXPECT_EQ(L"bar", type->name());
  EXPECT_EQ(4, type->size());

  // Down-cast it.
  BitfieldTypePtr bitfield_type;
  ASSERT_TRUE(type->CastTo(&bitfield_type));
  ASSERT_TRUE(bitfield_type);

  ASSERT_EQ(3, bitfield_type->bit_length());
  ASSERT_EQ(1, bitfield_type->bit_offset());
}

TEST(TypesTest, UserDefineType) {
  // Build a UDT instance.
  UserDefinedType::Fields fields;

  BasicTypePtr basic_type = new BasicType(L"int", 4);
  fields.push_back(
      UserDefinedType::Field(L"one", 0, Type::FLAG_CONST, basic_type));
  fields.push_back(
      UserDefinedType::Field(L"two", 4, Type::FLAG_VOLATILE, basic_type));
  basic_type = new BasicType(L"short", 2);
  fields.push_back(
      UserDefinedType::Field(L"three", 8, 0, basic_type));
  UserDefinedTypePtr udt =
      new UserDefinedType(L"foo", 10, fields);

  // Up-cast it.
  TypePtr type(udt);
  udt = nullptr;

  ASSERT_EQ(Type::UserDefinedKind, type->kind());
  EXPECT_EQ(L"foo", type->name());
  EXPECT_EQ(10, type->size());

  ASSERT_TRUE(type->CastTo(&udt));
  ASSERT_EQ(type.get(), udt.get());

  // Verify the fields set up above.
  ASSERT_EQ(3U, udt->fields().size());

  EXPECT_EQ(0U, udt->fields()[0].offset());
  EXPECT_TRUE(udt->fields()[0].is_const());
  EXPECT_FALSE(udt->fields()[0].is_volatile());
  EXPECT_TRUE(udt->fields()[0].type()->CastTo(&basic_type));
  EXPECT_EQ(L"int", basic_type->name());
  EXPECT_EQ(4, basic_type->size());

  EXPECT_EQ(4U, udt->fields()[1].offset());
  EXPECT_FALSE(udt->fields()[1].is_const());
  EXPECT_TRUE(udt->fields()[1].is_volatile());
  EXPECT_TRUE(udt->fields()[1].type()->CastTo(&basic_type));
  EXPECT_EQ(L"int", basic_type->name());
  EXPECT_EQ(4, basic_type->size());

  EXPECT_EQ(8U, udt->fields()[2].offset());
  EXPECT_FALSE(udt->fields()[2].is_const());
  EXPECT_FALSE(udt->fields()[2].is_volatile());
  EXPECT_TRUE(udt->fields()[2].type()->CastTo(&basic_type));
  EXPECT_EQ(L"short", basic_type->name());
  EXPECT_EQ(2, basic_type->size());
}

TEST(TypesTest, PointerType) {
  // Build a Pointer instance.
  TypePtr type =
      new PointerType(
          L"void*", 4, Type::FLAG_VOLATILE, new BasicType(L"void", 0));

  // Test the basic properties.
  ASSERT_TRUE(type);
  EXPECT_EQ(L"void*", type->name());
  EXPECT_EQ(4U, type->size());

  EXPECT_EQ(Type::PointerKind, type->kind());

  // Downcast and test its fields.
  PointerTypePtr pointer;
  ASSERT_TRUE(type->CastTo(&pointer));
  ASSERT_TRUE(pointer);
  EXPECT_FALSE(pointer->is_const());
  EXPECT_TRUE(pointer->is_volatile());
  ASSERT_TRUE(pointer->type());

  EXPECT_EQ(L"void", pointer->type()->name());
  EXPECT_EQ(0U, pointer->type()->size());
}

}  // namespace refinery
