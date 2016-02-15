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

#include "base/memory/ref_counted.h"
#include "gtest/gtest.h"
#include "syzygy/refinery/types/type_repository.h"

namespace refinery {

namespace {

enum ConstQualifier {
  NOT_CONST_QUALIFIED,
  CONST_QUALIFIED
};
enum VolatileQualifier {
  NOT_VOLATILE_QUALIFIED,
  VOLATILE_QUALIFIED
};

class TypesTest : public testing::Test {
 protected:
  void SetUp() override {
    Test::SetUp();
    repo_ = new TypeRepository();
  }

  TypePtr CreatePointerType(size_t size,
                            PointerType::Mode ptr_mode,
                            Type::Flags flags,
                            TypeId content_type_id) {
    PointerTypePtr ptr = new PointerType(size, ptr_mode);
    ptr->Finalize(flags, content_type_id);
    return ptr;
  }

  void ValidateMemberField(FieldPtr field,
                           const base::string16& name,
                           ptrdiff_t offset,
                           TypeId type_id,
                           ConstQualifier const_qualifier,
                           VolatileQualifier volatile_qualifier) {
    EXPECT_EQ(offset, field->offset());
    EXPECT_EQ(type_id, field->type_id());
    MemberFieldPtr member;
    ASSERT_TRUE(field->CastTo(&member));  // implicitely validates kind.

    EXPECT_EQ(name, member->name());
    EXPECT_EQ(const_qualifier == CONST_QUALIFIED, member->is_const());
    EXPECT_EQ(volatile_qualifier == VOLATILE_QUALIFIED, member->is_volatile());
    EXPECT_EQ(0U, member->bit_pos());
    EXPECT_EQ(0U, member->bit_len());
  }

  scoped_refptr<TypeRepository> repo_;
};

}  // namespace

TEST_F(TypesTest, BasicType) {
  // Create a BasicType and store in a supertype pointer.
  TypePtr type = new BasicType(L"foo", 10);

  ASSERT_TRUE(type.get());
  // Verify the kind and fields.
  EXPECT_EQ(Type::BASIC_TYPE_KIND, type->kind());
  EXPECT_EQ(L"foo", type->GetName());
  EXPECT_EQ(L"foo", type->GetDecoratedName());
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
TEST_F(TypesTest, UserDefinedType) {
  // Build a UDT instance.
  UserDefinedType::Fields fields;

  const TypeId kBasicTypeId = repo_->AddType(new BasicType(L"int", 4));
  fields.push_back(new UserDefinedType::MemberField(
      L"one", 0, Type::FLAG_CONST, 0, 0, kBasicTypeId, repo_.get()));
  fields.push_back(new UserDefinedType::MemberField(
      L"two", 4, Type::FLAG_VOLATILE, 0, 0, kBasicTypeId, repo_.get()));
  const TypeId kShortTypeId = repo_->AddType(new BasicType(L"short", 2));
  fields.push_back(new UserDefinedType::MemberField(L"three", 8, 0, 0, 0,
                                                    kShortTypeId, repo_.get()));
  UserDefinedTypePtr udt =
      new UserDefinedType(L"foo", 10, UserDefinedType::UDT_CLASS);

  const TypeId kClassId = repo_->AddType(udt);

  // Set up a member function.
  FunctionTypePtr function = new FunctionType(FunctionType::CALL_NEAR_C);
  function->Finalize(FunctionType::ArgumentType(kNoTypeFlags, kShortTypeId),
                     FunctionType::Arguments(), kClassId);
  const TypeId kFunctionId = repo_->AddType(function);

  UserDefinedType::Functions functions;
  functions.push_back(
      UserDefinedType::Function(L"memberFunction", kFunctionId));

  udt->Finalize(&fields, &functions);

  // Up-cast it.
  TypePtr type(udt);
  udt = nullptr;

  ASSERT_EQ(Type::USER_DEFINED_TYPE_KIND, type->kind());
  EXPECT_EQ(L"foo", type->GetName());
  EXPECT_EQ(L"foo", type->GetDecoratedName());
  EXPECT_EQ(10, type->size());

  ASSERT_TRUE(type->CastTo(&udt));
  ASSERT_EQ(type.get(), udt.get());

  EXPECT_FALSE(udt->is_fwd_decl());
  EXPECT_EQ(UserDefinedType::UDT_CLASS, udt->udt_kind());

  // Verify the fields set up above.
  ASSERT_EQ(3U, udt->fields().size());

  ASSERT_NO_FATAL_FAILURE(ValidateMemberField(udt->fields()[0], L"one", 0U,
                                              kBasicTypeId, CONST_QUALIFIED,
                                              NOT_VOLATILE_QUALIFIED));
  BasicTypePtr basic_type;
  ASSERT_TRUE(udt->GetFieldType(0)->CastTo(&basic_type));
  EXPECT_EQ(L"int", basic_type->GetName());
  EXPECT_EQ(4, basic_type->size());

  ASSERT_NO_FATAL_FAILURE(ValidateMemberField(udt->fields()[1], L"two", 4U,
                                              kBasicTypeId, NOT_CONST_QUALIFIED,
                                              VOLATILE_QUALIFIED));
  ASSERT_TRUE(udt->GetFieldType(1)->CastTo(&basic_type));
  EXPECT_EQ(L"int", basic_type->GetName());
  EXPECT_EQ(4, basic_type->size());

  ASSERT_NO_FATAL_FAILURE(ValidateMemberField(udt->fields()[2], L"three", 8U,
                                              kShortTypeId, NOT_CONST_QUALIFIED,
                                              NOT_VOLATILE_QUALIFIED));
  ASSERT_TRUE(udt->GetFieldType(2)->CastTo(&basic_type));
  EXPECT_EQ(L"short", basic_type->GetName());
  EXPECT_EQ(2, basic_type->size());

  EXPECT_EQ(1, udt->functions().size());
  EXPECT_EQ(L"memberFunction", udt->functions()[0].name());
  EXPECT_EQ(kFunctionId, udt->functions()[0].type_id());
  ASSERT_TRUE(udt->GetFunctionType(0)->CastTo(&function));
  EXPECT_EQ(L"short (foo::)()", function->GetName());
  EXPECT_EQ(function->containing_class_id(), udt->type_id());
}

TEST_F(TypesTest, UserDefineTypeWithDecoratedName) {
  // Build a UDT instance.
  UserDefinedType::Fields fields;
  const TypeId kBasicTypeId = repo_->AddType(new BasicType(L"int", 4));
  fields.push_back(new UserDefinedType::MemberField(
      L"one", 0, Type::FLAG_CONST, 0, 0, kBasicTypeId, repo_.get()));
  fields.push_back(new UserDefinedType::MemberField(
      L"two", 4, Type::FLAG_VOLATILE, 0, 0, kBasicTypeId, repo_.get()));
  const TypeId kShortTypeId = repo_->AddType(new BasicType(L"short", 2));
  fields.push_back(new UserDefinedType::MemberField(L"three", 8, 0, 0, 0,
                                                    kShortTypeId, repo_.get()));
  UserDefinedTypePtr udt = new UserDefinedType(L"foo", L"decorated_foo", 10,
                                               UserDefinedType::UDT_STRUCT);
  UserDefinedType::Functions functions;
  udt->Finalize(&fields, &functions);

  repo_->AddType(udt);

  // Up-cast it.
  TypePtr type(udt);
  udt = nullptr;

  ASSERT_EQ(Type::USER_DEFINED_TYPE_KIND, type->kind());
  EXPECT_EQ(L"foo", type->GetName());
  EXPECT_EQ(L"decorated_foo", type->GetDecoratedName());
  EXPECT_EQ(10, type->size());

  ASSERT_TRUE(type->CastTo(&udt));
  ASSERT_EQ(type.get(), udt.get());

  EXPECT_FALSE(udt->is_fwd_decl());
  EXPECT_EQ(UserDefinedType::UDT_STRUCT, udt->udt_kind());

  // Verify the fields set up above.
  ASSERT_EQ(3U, udt->fields().size());

  ASSERT_NO_FATAL_FAILURE(ValidateMemberField(udt->fields()[0], L"one", 0U,
                                              kBasicTypeId, CONST_QUALIFIED,
                                              NOT_VOLATILE_QUALIFIED));
  BasicTypePtr basic_type;
  ASSERT_TRUE(udt->GetFieldType(0)->CastTo(&basic_type));
  EXPECT_EQ(L"int", basic_type->GetName());
  EXPECT_EQ(4, basic_type->size());

  ASSERT_NO_FATAL_FAILURE(ValidateMemberField(udt->fields()[1], L"two", 4U,
                                              kBasicTypeId, NOT_CONST_QUALIFIED,
                                              VOLATILE_QUALIFIED));
  ASSERT_TRUE(udt->GetFieldType(1)->CastTo(&basic_type));
  EXPECT_EQ(L"int", basic_type->GetName());
  EXPECT_EQ(4, basic_type->size());

  ASSERT_NO_FATAL_FAILURE(ValidateMemberField(udt->fields()[2], L"three", 8U,
                                              kShortTypeId, NOT_CONST_QUALIFIED,
                                              NOT_VOLATILE_QUALIFIED));
  ASSERT_TRUE(udt->GetFieldType(2)->CastTo(&basic_type));
  EXPECT_EQ(L"short", basic_type->GetName());
  EXPECT_EQ(2, basic_type->size());
}

TEST_F(TypesTest, UserDefinedTypeGetFieldsOfKind) {
  // Create a basic type.
  const TypeId kBasicTypeId = repo_->AddType(new BasicType(L"int", 4));

  // Create a UDT with a field.
  UserDefinedType::Fields fields;
  fields.push_back(new UserDefinedType::MemberField(
      L"one", 0, Type::FLAG_CONST, 0, 0, kBasicTypeId, repo_.get()));
  UserDefinedType::Functions functions;
  UserDefinedTypePtr udt = new UserDefinedType(L"foo", L"decorated_foo", 4,
                                               UserDefinedType::UDT_STRUCT);
  udt->Finalize(&fields, &functions);
  repo_->AddType(udt);

  // Retrieve fields.
  UserDefinedType::Members members;
  udt->GetFieldsOfKind(&members);
  ASSERT_EQ(1, members.size());
  ValidateMemberField(members[0], L"one", 0U, kBasicTypeId, CONST_QUALIFIED,
                      NOT_VOLATILE_QUALIFIED);

  UserDefinedType::BaseClasses base_classes;
  udt->GetFieldsOfKind(&base_classes);
  ASSERT_EQ(0, base_classes.size());
}

TEST_F(TypesTest, UserDefineTypeForwardDeclaration) {
  // Build a UDT instance.
  UserDefinedTypePtr udt = new UserDefinedType(L"fwd", L"decorated_fwd", 0,
                                               UserDefinedType::UDT_STRUCT);
  udt->SetIsForwardDeclaration();

  repo_->AddType(udt);

  // Up-cast it.
  TypePtr type(udt);
  udt = nullptr;

  ASSERT_EQ(Type::USER_DEFINED_TYPE_KIND, type->kind());
  EXPECT_EQ(L"fwd", type->GetName());
  EXPECT_EQ(L"decorated_fwd", type->GetDecoratedName());
  EXPECT_EQ(0, type->size());

  ASSERT_TRUE(type->CastTo(&udt));
  ASSERT_EQ(type.get(), udt.get());

  EXPECT_TRUE(udt->is_fwd_decl());

  EXPECT_EQ(0, udt->fields().size());
  EXPECT_EQ(0, udt->functions().size());
}

TEST(BaseClassFieldTest, BasicTest) {
  scoped_refptr<TypeRepository> repository(new TypeRepository());

  const TypeId id = 2;
  const ptrdiff_t offset = 3;

  BaseClassFieldPtr bclass_field =
      new UserDefinedType::BaseClassField(offset, id, repository.get());
  EXPECT_EQ(UserDefinedType::Field::BASE_CLASS_KIND, bclass_field->kind());
  EXPECT_EQ(id, bclass_field->type_id());
  EXPECT_EQ(offset, bclass_field->offset());

  // Validate IsEqual.
  EXPECT_TRUE(bclass_field->IsEqual(*bclass_field));
  BaseClassFieldPtr other_bclass_field =
      new UserDefinedType::BaseClassField(offset + 1, id + 1, repository.get());
  EXPECT_FALSE(bclass_field->IsEqual(*other_bclass_field));
}

TEST(VfptrFieldTest, BasicTest) {
  scoped_refptr<TypeRepository> repository(new TypeRepository());

  const TypeId id = 2;
  const ptrdiff_t offset = 3;

  VfptrFieldPtr vfptr_field =
      new UserDefinedType::VfptrField(offset, id, repository.get());
  EXPECT_EQ(UserDefinedType::Field::VFPTR_KIND, vfptr_field->kind());
  EXPECT_EQ(id, vfptr_field->type_id());
  EXPECT_EQ(offset, vfptr_field->offset());

  // Validate IsEqual.
  EXPECT_TRUE(vfptr_field->IsEqual(*vfptr_field));
  VfptrFieldPtr other_vfptr_field =
      new UserDefinedType::VfptrField(offset + 1, id + 1, repository.get());
  EXPECT_FALSE(vfptr_field->IsEqual(*other_vfptr_field));
}

TEST_F(TypesTest, PointerType) {
  // Build a Pointer instance.
  const TypeId kPtrTypeId = repo_->AddType(new BasicType(L"void", 0));
  TypePtr type = CreatePointerType(4, PointerType::PTR_MODE_PTR,
                                   Type::FLAG_VOLATILE, kPtrTypeId);
  repo_->AddType(type);

  // Test the basic properties.
  ASSERT_TRUE(type);
  EXPECT_EQ(L"void volatile*", type->GetName());
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
  EXPECT_EQ(L"void", pointer->GetContentType()->GetName());
  EXPECT_EQ(0U, pointer->GetContentType()->size());
}

TEST_F(TypesTest, PointerTypeWithDecoratedName) {
  // Build a Pointer instance.
  const TypeId kPtrTypeId = repo_->AddType(new BasicType(L"void", 0));
  PointerTypePtr ptr_type = new PointerType(4, PointerType::PTR_MODE_PTR);
  ptr_type->Finalize(Type::FLAG_VOLATILE, kPtrTypeId);

  TypePtr type = ptr_type;
  repo_->AddType(type);

  // Test the basic properties.
  ASSERT_TRUE(type);
  EXPECT_EQ(L"void volatile*", type->GetName());
  EXPECT_EQ(L"void volatile*", type->GetDecoratedName());
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
  EXPECT_EQ(L"void", pointer->GetContentType()->GetName());
  EXPECT_EQ(L"void", pointer->GetContentType()->GetDecoratedName());
  EXPECT_EQ(0U, pointer->GetContentType()->size());
}

TEST_F(TypesTest, ArrayType) {
  TypePtr int_type = new BasicType(L"int32_t", 0);
  const TypeId kIntTypeId = repo_->AddType(int_type);
  PointerTypePtr ptr_type = new PointerType(4, PointerType::PTR_MODE_PTR);
  ptr_type->Finalize(Type::FLAG_VOLATILE, kIntTypeId);
  const TypeId kPtrTypeId = repo_->AddType(ptr_type);

  ArrayTypePtr array = new ArrayType(10 * ptr_type->size());
  repo_->AddType(array);
  array->Finalize(Type::FLAG_CONST, kIntTypeId, 10, kPtrTypeId);

  ASSERT_EQ(kIntTypeId, array->index_type_id());
  ASSERT_EQ(10, array->num_elements());
  ASSERT_EQ(kPtrTypeId, array->element_type_id());
  ASSERT_EQ(int_type, array->GetIndexType());
  ASSERT_EQ(ptr_type, array->GetElementType());
  ASSERT_EQ(ptr_type, array->GetElementType());
  ASSERT_EQ(L"int32_t volatile* const[10]", array->GetName());
  ASSERT_EQ(L"int32_t volatile* const[10]", array->GetDecoratedName());
  ASSERT_FALSE(array->is_volatile());
}

TEST_F(TypesTest, FunctionType) {
  // Build a UDT instance.
  FunctionType::Arguments args;
  const TypeId kBasicTypeId = repo_->AddType(new BasicType(L"uint32_t", 4));
  args.push_back(FunctionType::ArgumentType(Type::FLAG_CONST, kBasicTypeId));
  args.push_back(FunctionType::ArgumentType(Type::FLAG_VOLATILE, kBasicTypeId));
  const TypeId kShortTypeId = repo_->AddType(new BasicType(L"short", 2));
  args.push_back(FunctionType::ArgumentType(kNoTypeFlags, kShortTypeId));

  const TypeId kBoolTypeId = repo_->AddType(new BasicType(L"bool", 1));
  FunctionType::ArgumentType ret_value(Type::FLAG_CONST, kBoolTypeId);

  const TypeId kClassType = repo_->AddType(new UserDefinedType(
      L"foo", L"decorated_foo", 10, UserDefinedType::UDT_CLASS));

  FunctionTypePtr function = new FunctionType(FunctionType::CALL_NEAR_C);
  function->Finalize(ret_value, args, kClassType);

  repo_->AddType(function);

  // Up-cast it.
  TypePtr type(function);
  function = nullptr;

  ASSERT_EQ(Type::FUNCTION_TYPE_KIND, type->kind());
  EXPECT_EQ(L"bool const (foo::)(uint32_t const, uint32_t volatile, short)",
            type->GetName());
  EXPECT_EQ(
      L"bool const (decorated_foo::)(uint32_t const, uint32_t volatile, short)",
      type->GetDecoratedName());
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
  EXPECT_EQ(L"foo", udt->GetName());
  EXPECT_EQ(L"decorated_foo", udt->GetDecoratedName());

  EXPECT_TRUE(function->argument_types()[0].is_const());
  EXPECT_FALSE(function->argument_types()[0].is_volatile());
  EXPECT_EQ(kBasicTypeId, function->argument_types()[0].type_id());
  BasicTypePtr basic_type;
  ASSERT_TRUE(function->GetArgumentType(0)->CastTo(&basic_type));
  EXPECT_EQ(L"uint32_t", basic_type->GetName());
  EXPECT_EQ(4, basic_type->size());

  EXPECT_FALSE(function->argument_types()[1].is_const());
  EXPECT_TRUE(function->argument_types()[1].is_volatile());
  EXPECT_EQ(kBasicTypeId, function->argument_types()[1].type_id());
  ASSERT_TRUE(function->GetArgumentType(1)->CastTo(&basic_type));
  EXPECT_EQ(L"uint32_t", basic_type->GetName());
  EXPECT_EQ(4, basic_type->size());

  EXPECT_FALSE(function->argument_types()[2].is_const());
  EXPECT_FALSE(function->argument_types()[2].is_volatile());
  EXPECT_EQ(kShortTypeId, function->argument_types()[2].type_id());
  ASSERT_TRUE(function->GetArgumentType(2)->CastTo(&basic_type));
  EXPECT_EQ(L"short", basic_type->GetName());
  EXPECT_EQ(2, basic_type->size());

  EXPECT_TRUE(function->return_type().is_const());
  EXPECT_FALSE(function->return_type().is_volatile());
  EXPECT_EQ(kBoolTypeId, function->return_type().type_id());
  ASSERT_TRUE(function->GetReturnType()->CastTo(&basic_type));
  EXPECT_EQ(L"bool", basic_type->GetName());
  EXPECT_EQ(1, basic_type->size());
}

TEST_F(TypesTest, GlobalType) {
  const TypeId kBasicTypeId = repo_->AddType(new BasicType(L"int", 4));
  uint64_t kRVA = 0xCAFEBABE;
  TypePtr type = new GlobalType(L"foo", kRVA, kBasicTypeId, 4);
  EXPECT_EQ(Type::GLOBAL_TYPE_KIND, type->kind());
  EXPECT_EQ(L"foo", type->GetName());
  EXPECT_EQ(4, type->size());

  ASSERT_NE(0U, repo_->AddType(type));

  // Cast it down.
  GlobalTypePtr global;
  ASSERT_TRUE(type->CastTo(&global));

  EXPECT_EQ(kRVA, global->rva());
  EXPECT_EQ(kBasicTypeId, global->data_type_id());

  TypePtr data_type = global->GetDataType();
  ASSERT_NE(nullptr, data_type);
  EXPECT_EQ(L"int", data_type->GetName());
}

TEST_F(TypesTest, WildcardType) {
  // Build a wildcard instance.
  TypePtr type = new WildcardType(L"Wildcard", 4);
  repo_->AddType(type);

  // Test the basic properties.
  ASSERT_TRUE(type);
  EXPECT_EQ(L"Wildcard", type->GetName());
  EXPECT_EQ(L"Wildcard", type->GetDecoratedName());
  EXPECT_EQ(4U, type->size());

  // Downcast and test its fields.
  WildcardTypePtr wildcard;
  ASSERT_TRUE(type->CastTo(&wildcard));
  ASSERT_TRUE(wildcard);
}

}  // namespace refinery
