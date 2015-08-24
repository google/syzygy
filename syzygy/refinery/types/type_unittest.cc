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

namespace {

class TypesTest : public testing::Test {
 protected:
  TypePtr CreateUDT(const wchar_t* name,
                    size_t size,
                    const UserDefinedType::Fields& fields) {
    UserDefinedTypePtr udt = new UserDefinedType(name, size);
    udt->Finalize(fields, UserDefinedType::Functions());
    return udt;
  }

  TypePtr CreatePointerType(const wchar_t* name,
                            size_t size,
                            PointerType::Mode ptr_mode,
                            Type::Flags flags,
                            TypeId content_type_id) {
    PointerTypePtr ptr = new PointerType(size, ptr_mode);
    ptr->Finalize(flags, content_type_id);
    ptr->SetName(name);
    return ptr;
  }

  TypeRepository repo_;
};

}  // namespace

TEST_F(TypesTest, BasicType) {
  // Create a BasicType and store in a supertype pointer.
  TypePtr type = new BasicType(L"foo", 10);

  ASSERT_TRUE(type.get());
  // Verify the kind and fields.
  EXPECT_EQ(Type::BASIC_TYPE_KIND, type->kind());
  EXPECT_EQ(L"foo", type->name());
  EXPECT_EQ(L"foo", type->decorated_name());
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

// This test will eventually be deleted with the no-decorated-name constructor.
TEST_F(TypesTest, UserDefineType) {
  // Build a UDT instance.
  UserDefinedType::Fields fields;

  const TypeId kBasicTypeId = repo_.AddType(new BasicType(L"int", 4));
  fields.push_back(
      UserDefinedType::Field(L"one", 0, Type::FLAG_CONST, 0, 0, kBasicTypeId));
  fields.push_back(UserDefinedType::Field(L"two", 4, Type::FLAG_VOLATILE, 0, 0,
                                          kBasicTypeId));
  const TypeId kShortTypeId = repo_.AddType(new BasicType(L"short", 2));
  fields.push_back(UserDefinedType::Field(L"three", 8, 0, 0, 0, kShortTypeId));
  UserDefinedTypePtr udt =
      new UserDefinedType(L"foo", 10);

  const TypeId kClassId = repo_.AddType(udt);

  // Set up a member function.
  FunctionTypePtr function = new FunctionType(FunctionType::CALL_NEAR_C);
  function->Finalize(FunctionType::ArgumentType(kNoTypeFlags, kShortTypeId),
                     FunctionType::Arguments(), kClassId);
  function->SetName(L"short (foo::)()");
  const TypeId kFunctionId = repo_.AddType(function);

  UserDefinedType::Functions functions;
  functions.push_back(
      UserDefinedType::Function(L"memberFunction", kFunctionId));

  udt->Finalize(fields, functions);

  // Up-cast it.
  TypePtr type(udt);
  udt = nullptr;

  ASSERT_EQ(Type::USER_DEFINED_TYPE_KIND, type->kind());
  EXPECT_EQ(L"foo", type->name());
  EXPECT_EQ(L"foo", type->decorated_name());
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

  EXPECT_EQ(1, udt->functions().size());
  EXPECT_EQ(L"memberFunction", udt->functions()[0].name());
  EXPECT_EQ(kFunctionId, udt->functions()[0].type_id());
  ASSERT_TRUE(udt->GetFunctionType(0)->CastTo(&function));
  EXPECT_EQ(L"short (foo::)()", function->name());
  EXPECT_EQ(function->containing_class_id(), udt->type_id());
}

// This test will eventually be deleted with the no-decorated-name constructor.
TEST_F(TypesTest, UserDefineTypeWithDecoratedName) {
  // Build a UDT instance.
  UserDefinedType::Fields fields;
  const TypeId kBasicTypeId = repo_.AddType(new BasicType(L"int", 4));
  fields.push_back(
      UserDefinedType::Field(L"one", 0, Type::FLAG_CONST, 0, 0, kBasicTypeId));
  fields.push_back(UserDefinedType::Field(L"two", 4, Type::FLAG_VOLATILE, 0, 0,
                                          kBasicTypeId));
  const TypeId kShortTypeId = repo_.AddType(new BasicType(L"short", 2));
  fields.push_back(UserDefinedType::Field(L"three", 8, 0, 0, 0, kShortTypeId));
  UserDefinedTypePtr udt = new UserDefinedType(L"foo", L"decorated_foo", 10);
  udt->Finalize(fields, UserDefinedType::Functions());

  repo_.AddType(udt);

  // Up-cast it.
  TypePtr type(udt);
  udt = nullptr;

  ASSERT_EQ(Type::USER_DEFINED_TYPE_KIND, type->kind());
  EXPECT_EQ(L"foo", type->name());
  EXPECT_EQ(L"decorated_foo", type->decorated_name());
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

TEST_F(TypesTest, PointerType) {
  // Build a Pointer instance.
  const TypeId kPtrTypeId = repo_.AddType(new BasicType(L"void", 0));
  TypePtr type = CreatePointerType(L"void*", 4, PointerType::PTR_MODE_PTR,
                                   Type::FLAG_VOLATILE, kPtrTypeId);
  repo_.AddType(type);

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
  EXPECT_EQ(PointerType::PTR_MODE_PTR, pointer->ptr_mode());
  ASSERT_EQ(kPtrTypeId, pointer->content_type_id());

  ASSERT_TRUE(pointer->GetContentType());
  EXPECT_EQ(L"void", pointer->GetContentType()->name());
  EXPECT_EQ(0U, pointer->GetContentType()->size());
}

TEST_F(TypesTest, PointerTypeWithDecoratedName) {
  // Build a Pointer instance.
  const TypeId kPtrTypeId = repo_.AddType(new BasicType(L"void", 0));
  PointerTypePtr ptr_type = new PointerType(4, PointerType::PTR_MODE_PTR);
  ptr_type->SetName(L"void*");
  ptr_type->SetDecoratedName(L"decorated_void*");
  ptr_type->Finalize(Type::FLAG_VOLATILE, kPtrTypeId);

  TypePtr type = ptr_type;
  repo_.AddType(type);

  // Test the basic properties.
  ASSERT_TRUE(type);
  EXPECT_EQ(L"void*", type->name());
  EXPECT_EQ(L"decorated_void*", type->decorated_name());
  EXPECT_EQ(4U, type->size());

  EXPECT_EQ(Type::POINTER_TYPE_KIND, type->kind());

  // Downcast and test its fields.
  PointerTypePtr pointer;
  ASSERT_TRUE(type->CastTo(&pointer));
  ASSERT_TRUE(pointer);
  EXPECT_FALSE(pointer->is_const());
  EXPECT_TRUE(pointer->is_volatile());
  EXPECT_EQ(PointerType::PTR_MODE_PTR, pointer->ptr_mode());
  ASSERT_EQ(kPtrTypeId, pointer->content_type_id());

  ASSERT_TRUE(pointer->GetContentType());
  EXPECT_EQ(L"void", pointer->GetContentType()->name());
  EXPECT_EQ(L"void", pointer->GetContentType()->decorated_name());
  EXPECT_EQ(0U, pointer->GetContentType()->size());
}

TEST_F(TypesTest, ArrayType) {
  TypePtr int_type = new BasicType(L"int32_t", 0);
  const TypeId kIntTypeId = repo_.AddType(int_type);
  PointerTypePtr ptr_type = new PointerType(4, PointerType::PTR_MODE_PTR);
  ptr_type->SetName(L"aName");
  ptr_type->SetDecoratedName(L"aDecoratedName");
  ptr_type->Finalize(Type::FLAG_VOLATILE, kIntTypeId);
  const TypeId kPtrTypeId = repo_.AddType(ptr_type);

  ArrayTypePtr array = new ArrayType(10 * ptr_type->size());
  repo_.AddType(array);
  array->Finalize(Type::FLAG_CONST, kIntTypeId, 10, kPtrTypeId);
  ASSERT_EQ(L"", array->name());
  array->SetName(L"ArrayName");
  array->SetDecoratedName(L"decorated@@ArrayName");

  ASSERT_EQ(kIntTypeId, array->index_type_id());
  ASSERT_EQ(10, array->num_elements());
  ASSERT_EQ(kPtrTypeId, array->element_type_id());
  ASSERT_EQ(int_type, array->GetIndexType());
  ASSERT_EQ(ptr_type, array->GetElementType());
  ASSERT_EQ(ptr_type, array->GetElementType());
  ASSERT_EQ(L"ArrayName", array->name());
  ASSERT_EQ(L"decorated@@ArrayName", array->decorated_name());
  ASSERT_FALSE(array->is_volatile());
}

TEST_F(TypesTest, FunctionType) {
  // Build a UDT instance.
  FunctionType::Arguments args;
  const TypeId kBasicTypeId = repo_.AddType(new BasicType(L"uint32_t", 4));
  args.push_back(FunctionType::ArgumentType(Type::FLAG_CONST, kBasicTypeId));
  args.push_back(FunctionType::ArgumentType(Type::FLAG_VOLATILE, kBasicTypeId));
  const TypeId kShortTypeId = repo_.AddType(new BasicType(L"short", 2));
  args.push_back(FunctionType::ArgumentType(kNoTypeFlags, kShortTypeId));

  const TypeId kBoolTypeId = repo_.AddType(new BasicType(L"bool", 1));
  FunctionType::ArgumentType ret_value(Type::FLAG_CONST, kBoolTypeId);

  const TypeId kClassType =
      repo_.AddType(new UserDefinedType(L"foo", L"decorated_foo", 10));

  FunctionTypePtr function = new FunctionType(FunctionType::CALL_NEAR_C);
  function->Finalize(ret_value, args, kClassType);
  function->SetName(L"FunctionName");
  function->SetDecoratedName(L"decorated@@FunctionName");

  repo_.AddType(function);

  // Up-cast it.
  TypePtr type(function);
  function = nullptr;

  ASSERT_EQ(Type::FUNCTION_TYPE_KIND, type->kind());
  EXPECT_EQ(L"FunctionName", type->name());
  EXPECT_EQ(L"decorated@@FunctionName", type->decorated_name());
  EXPECT_EQ(0, type->size());

  ASSERT_TRUE(type->CastTo(&function));
  ASSERT_EQ(type.get(), function.get());

  // Verify the arguments set up above.
  ASSERT_EQ(3U, function->argument_types().size());

  EXPECT_EQ(FunctionType::CALL_NEAR_C, function->call_convention());
  EXPECT_TRUE(function->IsMemberFunction());
  EXPECT_EQ(kClassType, function->containing_class_id());

  UserDefinedTypePtr udt;
  EXPECT_TRUE(function->GetContainingClassType()->CastTo(&udt));
  EXPECT_EQ(L"foo", udt->name());
  EXPECT_EQ(L"decorated_foo", udt->decorated_name());

  EXPECT_TRUE(function->argument_types()[0].is_const());
  EXPECT_FALSE(function->argument_types()[0].is_volatile());
  EXPECT_EQ(kBasicTypeId, function->argument_types()[0].type_id());
  BasicTypePtr basic_type;
  ASSERT_TRUE(function->GetArgumentType(0)->CastTo(&basic_type));
  EXPECT_EQ(L"uint32_t", basic_type->name());
  EXPECT_EQ(4, basic_type->size());

  EXPECT_FALSE(function->argument_types()[1].is_const());
  EXPECT_TRUE(function->argument_types()[1].is_volatile());
  EXPECT_EQ(kBasicTypeId, function->argument_types()[1].type_id());
  ASSERT_TRUE(function->GetArgumentType(1)->CastTo(&basic_type));
  EXPECT_EQ(L"uint32_t", basic_type->name());
  EXPECT_EQ(4, basic_type->size());

  EXPECT_FALSE(function->argument_types()[2].is_const());
  EXPECT_FALSE(function->argument_types()[2].is_volatile());
  EXPECT_EQ(kShortTypeId, function->argument_types()[2].type_id());
  ASSERT_TRUE(function->GetArgumentType(2)->CastTo(&basic_type));
  EXPECT_EQ(L"short", basic_type->name());
  EXPECT_EQ(2, basic_type->size());

  EXPECT_TRUE(function->return_type().is_const());
  EXPECT_FALSE(function->return_type().is_volatile());
  EXPECT_EQ(kBoolTypeId, function->return_type().type_id());
  ASSERT_TRUE(function->GetReturnType()->CastTo(&basic_type));
  EXPECT_EQ(L"bool", basic_type->name());
  EXPECT_EQ(1, basic_type->size());
}

TEST_F(TypesTest, WildcardType) {
  // Build a wildcard instance.
  TypePtr type = new WildcardType(L"Wildcard", 4);
  repo_.AddType(type);

  // Test the basic properties.
  ASSERT_TRUE(type);
  EXPECT_EQ(L"Wildcard", type->name());
  EXPECT_EQ(L"Wildcard", type->decorated_name());
  EXPECT_EQ(4U, type->size());

  // Downcast and test its fields.
  WildcardTypePtr wildcard;
  ASSERT_TRUE(type->CastTo(&wildcard));
  ASSERT_TRUE(wildcard);
}

}  // namespace refinery
