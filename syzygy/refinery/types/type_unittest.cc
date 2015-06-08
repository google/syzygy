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
#include "syzygy/refinery/types/type_repository.h"

namespace refinery {

TEST(TypesTest, BasicType) {
  // Create a BasicType and store in a supertype pointer.
  TypePtr type = new BasicType(L"foo", 10);

  ASSERT_TRUE(type.get());
  // Verify the kind and fields.
  EXPECT_EQ(Type::BASIC_TYPE_KIND, type->kind());
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
  EXPECT_EQ(Type::BITFIELD_TYPE_KIND, type->kind());
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
  TypeRepository repo;

  const TypeId kBasicTypeId = repo.AddType(new BasicType(L"int", 4));
  fields.push_back(
      UserDefinedType::Field(L"one", 0, Type::FLAG_CONST, kBasicTypeId));
  fields.push_back(
      UserDefinedType::Field(L"two", 4, Type::FLAG_VOLATILE, kBasicTypeId));
  const TypeId kShortTypeId = repo.AddType(new BasicType(L"short", 2));
  fields.push_back(
      UserDefinedType::Field(L"three", 8, 0, kShortTypeId));
  UserDefinedTypePtr udt =
      new UserDefinedType(L"foo", 10);
  udt->Finalize(fields);

  repo.AddType(udt);

  // Up-cast it.
  TypePtr type(udt);
  udt = nullptr;

  ASSERT_EQ(Type::USER_DEFINED_TYPE_KIND, type->kind());
  EXPECT_EQ(L"foo", type->name());
  EXPECT_EQ(10, type->size());

  ASSERT_TRUE(type->CastTo(&udt));
  ASSERT_EQ(type.get(), udt.get());

  // Verify the fields set up above.
  ASSERT_EQ(3U, udt->fields().size());

  EXPECT_EQ(0U, udt->fields()[0].offset());
  EXPECT_TRUE(udt->fields()[0].is_const());
  EXPECT_FALSE(udt->fields()[0].is_volatile());
  EXPECT_EQ(kBasicTypeId, udt->fields()[0].type_id());
  BasicTypePtr basic_type;
  ASSERT_TRUE(udt->GetFieldType(0)->CastTo(&basic_type));
  EXPECT_EQ(L"int", basic_type->name());
  EXPECT_EQ(4, basic_type->size());

  EXPECT_EQ(4U, udt->fields()[1].offset());
  EXPECT_FALSE(udt->fields()[1].is_const());
  EXPECT_TRUE(udt->fields()[1].is_volatile());
  EXPECT_EQ(kBasicTypeId, udt->fields()[1].type_id());
  ASSERT_TRUE(udt->GetFieldType(1)->CastTo(&basic_type));
  EXPECT_EQ(L"int", basic_type->name());
  EXPECT_EQ(4, basic_type->size());

  EXPECT_EQ(8U, udt->fields()[2].offset());
  EXPECT_FALSE(udt->fields()[2].is_const());
  EXPECT_FALSE(udt->fields()[2].is_volatile());
  EXPECT_EQ(kShortTypeId, udt->fields()[2].type_id());
  ASSERT_TRUE(udt->GetFieldType(2)->CastTo(&basic_type));
  EXPECT_EQ(L"short", basic_type->name());
  EXPECT_EQ(2, basic_type->size());
}

TEST(TypesTest, PointerType) {
  // Build a Pointer instance.
  TypeRepository repo;
  const TypeId kPtrTypeId = repo.AddType(new BasicType(L"void", 0));
  TypePtr type = new PointerType(L"void*", 4, Type::FLAG_VOLATILE, kPtrTypeId);
  repo.AddType(type);

  // Test the basic properties.
  ASSERT_TRUE(type);
  EXPECT_EQ(L"void*", type->name());
  EXPECT_EQ(4U, type->size());

  EXPECT_EQ(Type::POINTER_TYPE_KIND, type->kind());

  // Downcast and test its fields.
  PointerTypePtr pointer;
  ASSERT_TRUE(type->CastTo(&pointer));
  ASSERT_TRUE(pointer);
  EXPECT_FALSE(pointer->is_const());
  EXPECT_TRUE(pointer->is_volatile());
  ASSERT_EQ(kPtrTypeId, pointer->content_type_id());

  ASSERT_TRUE(pointer->GetContentType());
  EXPECT_EQ(L"void", pointer->GetContentType()->name());
  EXPECT_EQ(0U, pointer->GetContentType()->size());
}

TEST(TypesTest, WildcardType) {
  // Build a wildcard instance.
  TypeRepository repo;
  TypePtr type = new WildcardType(L"Array", 4);
  repo.AddType(type);

  // Test the basic properties.
  ASSERT_TRUE(type);
  EXPECT_EQ(L"Array", type->name());
  EXPECT_EQ(4U, type->size());

  // Downcast and test its fields.
  WildcardTypePtr wildcard;
  ASSERT_TRUE(type->CastTo(&wildcard));
  ASSERT_TRUE(wildcard);
}

namespace {

TypePtr CreateUDT(const wchar_t* name,
                  size_t size,
                  const UserDefinedType::Fields& fields) {
  UserDefinedTypePtr udt = new UserDefinedType(name, size);
  udt->Finalize(fields);
  return udt;
}

}  // namespace

TEST(TypesTest, TypeHash) {
  TypeHash hash;

  // BasicType.
  {
    size_t norm = hash(new BasicType(L"basic", 4));
    EXPECT_EQ(norm, hash(new BasicType(L"basic", 4)));
    EXPECT_NE(norm, hash(new BasicType(L"fasic", 4)));
    EXPECT_NE(norm, hash(new BasicType(L"basic", 3)));
  }

  // BitfieldType.
  {
    size_t norm = hash(new BitfieldType(L"bitfield", 4, 1, 3));

    EXPECT_EQ(norm, hash(new BitfieldType(L"bitfield", 4, 1, 3)));

    EXPECT_NE(norm, hash(new BitfieldType(L"fitfield", 4, 1, 3)));
    EXPECT_NE(norm, hash(new BitfieldType(L"bitfield", 3, 1, 3)));
    EXPECT_NE(norm, hash(new BitfieldType(L"bitfield", 4, 2, 3)));
    EXPECT_NE(norm, hash(new BitfieldType(L"bitfield", 4, 1, 4)));
  }

  // UserDefinedType.
  {
    const TypeId kType = 333;

    UserDefinedType::Fields fields;
    fields.push_back(
        UserDefinedType::Field(L"one", 0, 0, kType));

    size_t norm = hash(CreateUDT(L"udt", 8, fields));
    EXPECT_EQ(norm, hash(CreateUDT(L"udt", 8, fields)));

    EXPECT_NE(norm, hash(CreateUDT(L"Udt", 8, fields)));
    EXPECT_NE(norm, hash(CreateUDT(L"udt", 12, fields)));

    UserDefinedType::Fields inequal_fields;
    // Difference in field number.
    EXPECT_NE(norm, hash(CreateUDT(L"udt", 8, inequal_fields)));

    // Difference in const only.
    inequal_fields.push_back(UserDefinedType::Field(
        L"one", 0, Type::FLAG_CONST, kType));
    EXPECT_NE(norm, hash(CreateUDT(L"udt", 8, inequal_fields)));

    // Difference in type.
    inequal_fields.clear();
    inequal_fields.push_back(
        UserDefinedType::Field(L"one", 0, 0, kType + 30));
    EXPECT_NE(norm, hash(CreateUDT(L"udt", 8, inequal_fields)));
  }

  // PointerType.
  {
    const TypeId kType = 395;
    size_t norm = hash(new PointerType(L"pointer", 4, 0, kType));

    EXPECT_EQ(norm, hash(new PointerType(L"pointer", 4, 0, kType)));

    EXPECT_NE(norm, hash(new PointerType(L"Pointer", 4, 0, kType)));
    EXPECT_NE(norm, hash(new PointerType(L"pointer", 3, 0, kType)));
    EXPECT_NE(norm, hash(new PointerType(L"pointer", 4, Type::FLAG_CONST,
                                         kType)));
    EXPECT_NE(norm, hash(new PointerType(L"pointer", 4, 0, kType - 3)));
  }

  // WildcardType.
  {
    size_t norm = hash(new WildcardType(L"Array", 4));
    EXPECT_EQ(norm, hash(new WildcardType(L"Array", 4)));
    EXPECT_NE(norm, hash(new WildcardType(L"fasic", 4)));
    EXPECT_NE(norm, hash(new WildcardType(L"Array", 3)));
  }
}

TEST(TypesTest, TypeIsEqual) {
  TypeIsEqual comp;

  {
    UserDefinedType::Fields fields;
    const TypeId kFieldType = 30945;
    fields.push_back(UserDefinedType::Field(L"one", 0, 0, kFieldType));
    fields.push_back(UserDefinedType::Field(L"two", 4, 0, kFieldType));

    const TypeId kPtrType = 1234;
    TypePtr types[] = {
      new BasicType(L"basic", 4),
      new BitfieldType(L"bitfield", 4, 1, 3),
      CreateUDT(L"udt", 8, fields),
      new PointerType(L"pointer", 4, 0, kPtrType),
      new WildcardType(L"Array", 4),
    };

    // Test all type cross-comparisons, only the diagonal should compare true.
    for (size_t i = 0; i < arraysize(types); ++i) {
      for (size_t j = 0; j < arraysize(types); ++j) {
        if (i == j)
          EXPECT_TRUE(comp(types[i], types[j]));
        else
          EXPECT_FALSE(comp(types[i], types[j]));
      }
    }

    // Create another set of equal types.
    TypePtr equal_types[] = {
      new BasicType(L"basic", 4),
      new BitfieldType(L"bitfield", 4, 1, 3),
      CreateUDT(L"udt", 8, fields),
      new PointerType(L"pointer", 4, 0, kPtrType),
      new WildcardType(L"Array", 4),
    };

    // Test all type cross-comparisons, only the diagonal should compare but
    // now on equality rather than identity.
    for (size_t i = 0; i < arraysize(types); ++i) {
      for (size_t j = 0; j < arraysize(types); ++j) {
        if (i == j)
          EXPECT_TRUE(comp(types[i], equal_types[j]));
        else
          EXPECT_FALSE(comp(types[i], equal_types[j]));
      }
    }
  }

  {
    // Test field inequality for basic types.
    TypePtr norm = new BasicType(L"one", 0);
    EXPECT_FALSE(comp(norm, new BasicType(L"two", 0)));
    EXPECT_FALSE(comp(norm, new BasicType(L"one", 4)));
  }

  {
    // Test field inequality for bit field types.
    TypePtr norm = new BitfieldType(L"one", 4, 1, 1);

    EXPECT_FALSE(comp(norm, new BitfieldType(L"two", 4, 1, 1)));
    EXPECT_FALSE(comp(norm, new BitfieldType(L"one", 2, 1, 1)));
    EXPECT_FALSE(comp(norm, new BitfieldType(L"one", 4, 2, 1)));
    EXPECT_FALSE(comp(norm, new BitfieldType(L"one", 4, 1, 2)));
  }


  {
    UserDefinedType::Fields fields;
    const TypeId kFieldType = 94014;
    fields.push_back(
        UserDefinedType::Field(L"one", 0, 0, kFieldType));

    // Test field inequality for UDTs.
    TypePtr norm = CreateUDT(L"one", 4, fields);
    EXPECT_FALSE(comp(norm, CreateUDT(L"two", 4, fields)));
    EXPECT_FALSE(comp(norm, CreateUDT(L"one", 8, fields)));

    UserDefinedType::Fields inequal_fields;

    // Test difference in field number.
    EXPECT_FALSE(comp(norm, CreateUDT(L"one", 4, inequal_fields)));

    // Difference in field constness.
    inequal_fields.push_back(
        UserDefinedType::Field(L"one", 0, Type::FLAG_CONST, kFieldType));
    EXPECT_FALSE(comp(norm, CreateUDT(L"one", 4, inequal_fields)));

    // Difference in field offset (name).
    inequal_fields.clear();
    inequal_fields.push_back(UserDefinedType::Field(L"one", 1, 0, kFieldType));
    EXPECT_FALSE(comp(norm, CreateUDT(L"one", 4, inequal_fields)));

    // Difference in field type.
    inequal_fields.clear();
    inequal_fields.push_back(
        UserDefinedType::Field(L"one", 0, 0, kFieldType + 9));
    EXPECT_FALSE(comp(norm, CreateUDT(L"one", 4, inequal_fields)));
  }

  {
    // Test field inequality for wildcard types.
    TypePtr norm = new WildcardType(L"Array", 0);
    EXPECT_FALSE(comp(norm, new WildcardType(L"Farray", 0)));
    EXPECT_FALSE(comp(norm, new WildcardType(L"Array", 4)));
  }
}

}  // namespace refinery
