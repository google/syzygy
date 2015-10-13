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

#include "syzygy/refinery/types/dia_crawler.h"

#include "base/path_service.h"
#include "base/debug/alias.h"
#include "base/files/file_path.h"
#include "base/memory/ref_counted.h"
#include "base/strings/string_util.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/refinery/types/type_repository.h"


namespace refinery {

namespace {

class DiaCrawlerTest : public testing::Test {
 protected:
  void SetUp() override {
    DiaCrawler crawler;

    ASSERT_TRUE(crawler.InitializeForFile(testing::GetSrcRelativePath(
        L"syzygy\\refinery\\test_data\\test_types.dll.pdb")));

    types_ = new TypeRepository();
    ASSERT_TRUE(crawler.GetTypes(types_.get()));
  }

  TypePtr FindTypeEndingWith(const base::string16& str) {
    for (auto it : *types_) {
      if (base::EndsWith(it->name(), str, base::CompareCase::SENSITIVE))
        return it;
    }
    return nullptr;
  }

  scoped_refptr<TypeRepository> types_;
};

}  // namespace

TEST_F(DiaCrawlerTest, TestSimpleUDT) {
  TypePtr type = FindTypeEndingWith(L"::TestSimpleUDT");
  ASSERT_TRUE(type);

  EXPECT_EQ(16, type->size());
  EXPECT_TRUE(base::EndsWith(type->name(), L"::TestSimpleUDT",
                             base::CompareCase::SENSITIVE));

  EXPECT_EQ(Type::USER_DEFINED_TYPE_KIND, type->kind());

  UserDefinedTypePtr udt;
  ASSERT_TRUE(type->CastTo(&udt));
  ASSERT_TRUE(udt);

  EXPECT_FALSE(udt->is_fwd_decl());
  EXPECT_EQ(UserDefinedType::UDT_STRUCT, udt->udt_kind());

  const UserDefinedType::Fields& fields = udt->fields();
  ASSERT_EQ(6U, fields.size());

  EXPECT_EQ(0, fields[0].offset());
  EXPECT_EQ(L"one", fields[0].name());
  EXPECT_FALSE(fields[0].is_const());
  EXPECT_FALSE(fields[0].is_volatile());
  EXPECT_EQ(0, fields[0].bit_pos());
  EXPECT_EQ(0, fields[0].bit_len());
  EXPECT_EQ(Type::BASIC_TYPE_KIND, udt->GetFieldType(0)->kind());
  EXPECT_EQ(4, udt->GetFieldType(0)->size());
  EXPECT_EQ(L"int32_t", udt->GetFieldType(0)->name());

  EXPECT_EQ(4, fields[1].offset());
  EXPECT_EQ(L"two", fields[1].name());
  EXPECT_TRUE(fields[1].is_const());
  EXPECT_FALSE(fields[1].is_volatile());
  EXPECT_EQ(0, fields[1].bit_pos());
  EXPECT_EQ(0, fields[1].bit_len());
  EXPECT_EQ(Type::BASIC_TYPE_KIND, udt->GetFieldType(1)->kind());
  EXPECT_EQ(1, udt->GetFieldType(1)->size());
  EXPECT_EQ(L"char", udt->GetFieldType(1)->name());

  EXPECT_EQ(8, fields[2].offset());
  EXPECT_EQ(L"three", fields[2].name());
  EXPECT_FALSE(fields[2].is_const());
  EXPECT_FALSE(fields[2].is_volatile());
  EXPECT_EQ(0, fields[2].bit_pos());
  EXPECT_EQ(0, fields[2].bit_len());
  ASSERT_EQ(Type::POINTER_TYPE_KIND, udt->GetFieldType(2)->kind());
  EXPECT_EQ(4, udt->GetFieldType(2)->size());
  PointerTypePtr ptr;
  ASSERT_TRUE(udt->GetFieldType(2)->CastTo(&ptr));
  ASSERT_TRUE(ptr);
  EXPECT_EQ(4, ptr->size());
  EXPECT_FALSE(ptr->is_const());
  EXPECT_TRUE(ptr->is_volatile());
  ASSERT_TRUE(ptr->GetContentType());
  ASSERT_EQ(PointerType::PTR_MODE_PTR, ptr->ptr_mode());
  EXPECT_EQ(Type::POINTER_TYPE_KIND, ptr->GetContentType()->kind());
  EXPECT_EQ(L"int16_t const* volatile*", ptr->name());

  ASSERT_TRUE(ptr->GetContentType()->CastTo(&ptr));
  ASSERT_TRUE(ptr);
  EXPECT_EQ(4, ptr->size());
  EXPECT_TRUE(ptr->is_const());
  EXPECT_FALSE(ptr->is_volatile());
  ASSERT_EQ(PointerType::PTR_MODE_PTR, ptr->ptr_mode());
  ASSERT_TRUE(ptr->GetContentType());
  EXPECT_EQ(L"int16_t const*", ptr->name());
  EXPECT_EQ(Type::BASIC_TYPE_KIND, ptr->GetContentType()->kind());
  EXPECT_EQ(L"int16_t", ptr->GetContentType()->name());
  EXPECT_EQ(2, ptr->GetContentType()->size());

  EXPECT_EQ(12, fields[3].offset());
  EXPECT_EQ(L"four", fields[3].name());
  EXPECT_TRUE(fields[3].is_const());
  EXPECT_TRUE(fields[3].is_volatile());
  EXPECT_EQ(0, fields[3].bit_pos());
  EXPECT_EQ(0, fields[3].bit_len());
  EXPECT_EQ(Type::BASIC_TYPE_KIND, udt->GetFieldType(3)->kind());
  EXPECT_EQ(2, udt->GetFieldType(3)->size());
  EXPECT_EQ(L"uint16_t", udt->GetFieldType(3)->name());

  // Can't do offsetof/sizeof on bit fields.
  EXPECT_EQ(14, fields[4].offset());
  EXPECT_EQ(L"five", fields[4].name());
  EXPECT_FALSE(fields[4].is_const());
  EXPECT_FALSE(fields[4].is_volatile());
  EXPECT_EQ(0, fields[4].bit_pos());
  EXPECT_EQ(3, fields[4].bit_len());
  EXPECT_EQ(Type::BASIC_TYPE_KIND, udt->GetFieldType(4)->kind());
  EXPECT_EQ(2, udt->GetFieldType(4)->size());
  EXPECT_EQ(L"uint16_t", udt->GetFieldType(4)->name());

  EXPECT_EQ(14, fields[5].offset());
  EXPECT_EQ(L"six", fields[5].name());
  EXPECT_FALSE(fields[5].is_const());
  EXPECT_FALSE(fields[5].is_volatile());
  EXPECT_EQ(3, fields[5].bit_pos());
  EXPECT_EQ(5, fields[5].bit_len());
  EXPECT_EQ(Type::BASIC_TYPE_KIND, udt->GetFieldType(5)->kind());
  EXPECT_EQ(2, udt->GetFieldType(5)->size());
  EXPECT_EQ(L"uint16_t", udt->GetFieldType(5)->name());
}

TEST_F(DiaCrawlerTest, TestReference) {
  TypePtr type = FindTypeEndingWith(L"::TestReference");
  ASSERT_TRUE(type);
  EXPECT_TRUE(
      EndsWith(type->name(), L"::TestReference", base::CompareCase::SENSITIVE));
  EXPECT_EQ(Type::USER_DEFINED_TYPE_KIND, type->kind());

  UserDefinedTypePtr udt;
  ASSERT_TRUE(type->CastTo(&udt));
  ASSERT_TRUE(udt);

  const UserDefinedType::Fields& fields = udt->fields();
  ASSERT_EQ(2U, fields.size());

  EXPECT_EQ(L"value", fields[0].name());

  EXPECT_EQ(L"reference", fields[1].name());
  EXPECT_FALSE(fields[1].is_const());
  EXPECT_FALSE(fields[1].is_volatile());
  ASSERT_EQ(Type::POINTER_TYPE_KIND, udt->GetFieldType(1)->kind());
  PointerTypePtr ptr;
  ASSERT_TRUE(udt->GetFieldType(1)->CastTo(&ptr));
  ASSERT_TRUE(ptr);
  EXPECT_EQ(4, ptr->size());
  EXPECT_TRUE(ptr->is_const());
  EXPECT_FALSE(ptr->is_volatile());
  ASSERT_EQ(PointerType::PTR_MODE_REF, ptr->ptr_mode());
  EXPECT_EQ(L"int32_t const&", ptr->name());
}

TEST_F(DiaCrawlerTest, TestArray) {
  TypePtr type = FindTypeEndingWith(L"::TestArrays");
  ASSERT_TRUE(type);

  UserDefinedTypePtr udt;
  ASSERT_TRUE(type->CastTo(&udt));
  ASSERT_TRUE(udt);

  ASSERT_EQ(2U, udt->fields().size());

  ArrayTypePtr int_array;
  ASSERT_TRUE(udt->GetFieldType(0)->CastTo(&int_array));
  ASSERT_TRUE(int_array);

  EXPECT_EQ(30, int_array->num_elements());
  EXPECT_EQ(L"int32_t const[30]", int_array->name());
  EXPECT_EQ(sizeof(int) * 30, int_array->size());
  EXPECT_TRUE(int_array->is_const());
  EXPECT_FALSE(int_array->is_volatile());

  TypePtr index_type = int_array->GetIndexType();
  EXPECT_EQ(L"uint32_t", index_type->name());

  TypePtr element_type = int_array->GetElementType();
  EXPECT_EQ(L"int32_t", element_type->name());

  PointerTypePtr array_ptr;
  ASSERT_TRUE(udt->GetFieldType(1)->CastTo(&array_ptr));

  ArrayTypePtr ptr_array;
  ASSERT_TRUE(array_ptr->GetContentType()->CastTo(&ptr_array));

  EXPECT_EQ(32, ptr_array->num_elements());
  EXPECT_EQ(L"testing::TestRecursiveUDT* volatile[32]", ptr_array->name());
  EXPECT_EQ(sizeof(void*) * 32, ptr_array->size());
  EXPECT_FALSE(ptr_array->is_const());
  EXPECT_TRUE(ptr_array->is_volatile());

  index_type = ptr_array->GetIndexType();
  EXPECT_EQ(L"uint32_t", index_type->name());

  element_type = ptr_array->GetElementType();
  EXPECT_EQ(L"testing::TestRecursiveUDT*", element_type->name());
}

TEST_F(DiaCrawlerTest, TestFunctionType) {
  TypePtr type =
      FindTypeEndingWith(L"void (testing::TestAllInOneUDT::)(int32_t)");
  ASSERT_TRUE(type);

  FunctionTypePtr function;
  ASSERT_EQ(Type::FUNCTION_TYPE_KIND, type->kind());
  ASSERT_TRUE(type->CastTo(&function));
  ASSERT_TRUE(function);

  const FunctionType::Arguments& args = function->argument_types();

  EXPECT_EQ(1U, args.size());

  EXPECT_TRUE(function->IsMemberFunction());
  EXPECT_FALSE(function->return_type().is_const());
  EXPECT_FALSE(function->return_type().is_volatile());
  EXPECT_EQ(function->GetReturnType()->name(), L"void");

  EXPECT_FALSE(args[0].is_const());
  EXPECT_FALSE(args[0].is_volatile());
  EXPECT_EQ(function->GetArgumentType(0)->name(), L"int32_t");

  // Find the containing class.
  type = FindTypeEndingWith(L"::TestAllInOneUDT");
  ASSERT_TRUE(type);

  // Check that the function points to its containing class.
  EXPECT_EQ(function->containing_class_id(), type->type_id());

  EXPECT_EQ(function->name(), L"void (" + type->name() + L"::)(int32_t)");
}

TEST_F(DiaCrawlerTest, TestFunctions) {
  TypePtr type = FindTypeEndingWith(L"::TestFunctions");
  ASSERT_TRUE(type);

  UserDefinedTypePtr udt;
  ASSERT_TRUE(type->CastTo(&udt));
  ASSERT_TRUE(udt);

  ASSERT_EQ(0U, udt->fields().size());
  ASSERT_EQ(4U, udt->functions().size());

  const UserDefinedType::Functions& functions = udt->functions();
  FunctionTypePtr function;

  // First function is a constructor.
  EXPECT_EQ(L"TestFunctions", functions[0].name());
  EXPECT_TRUE(udt->GetFunctionType(0)->CastTo(&function));
  EXPECT_EQ(0U, function->argument_types().size());
  EXPECT_EQ(function->GetReturnType()->name(), L"void");
  EXPECT_EQ(udt->type_id(), function->containing_class_id());

  EXPECT_EQ(L"NonOverloadedFunction", functions[1].name());
  EXPECT_TRUE(udt->GetFunctionType(1)->CastTo(&function));
  EXPECT_EQ(0U, function->argument_types().size());
  EXPECT_EQ(function->GetReturnType()->name(), L"void");
  EXPECT_EQ(udt->type_id(), function->containing_class_id());

  EXPECT_EQ(L"OverloadedFunction", functions[2].name());
  EXPECT_TRUE(udt->GetFunctionType(2)->CastTo(&function));
  EXPECT_EQ(1U, function->argument_types().size());
  EXPECT_EQ(function->GetArgumentType(0)->name(), L"int32_t");
  EXPECT_EQ(function->GetReturnType()->name(), L"void");
  EXPECT_EQ(udt->type_id(), function->containing_class_id());

  EXPECT_EQ(L"OverloadedFunction", functions[3].name());
  EXPECT_TRUE(udt->GetFunctionType(3)->CastTo(&function));
  EXPECT_EQ(0U, function->argument_types().size());
  EXPECT_EQ(function->GetReturnType()->name(), L"int32_t");
  EXPECT_EQ(udt->type_id(), function->containing_class_id());
}

TEST_F(DiaCrawlerTest, TestUnion) {
  TypePtr type = FindTypeEndingWith(L"::TestUnion");
  ASSERT_TRUE(type);

  ASSERT_EQ(Type::USER_DEFINED_TYPE_KIND, type->kind());

  UserDefinedTypePtr udt;
  ASSERT_TRUE(type->CastTo(&udt));
  ASSERT_TRUE(udt);

  EXPECT_EQ(0, udt->functions().size());
  EXPECT_EQ(2U, udt->fields().size());
  EXPECT_FALSE(udt->is_fwd_decl());
  EXPECT_EQ(UserDefinedType::UDT_UNION, udt->udt_kind());
}

}  // namespace refinery
