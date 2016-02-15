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

#include <windows.h>

#include "base/path_service.h"
#include "base/containers/hash_tables.h"
#include "base/debug/alias.h"
#include "base/files/file_path.h"
#include "base/memory/ref_counted.h"
#include "base/strings/string_util.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/refinery/types/type_repository.h"
#include "syzygy/refinery/types/unittest_util.h"


namespace refinery {

namespace {

const bool kIsConst = true;
const bool kIsVolatile = true;

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
      if (base::EndsWith(it->GetName(), str, base::CompareCase::SENSITIVE))
        return it;
    }
    return nullptr;
  }

  void ValidateMemberField(FieldPtr field,
                           const base::string16& name,
                           ptrdiff_t offset,
                           bool is_const,
                           bool is_volatile,
                           size_t bit_pos,
                           size_t bit_len) {
    EXPECT_EQ(offset, field->offset());
    // Note: type_id is not validated.
    MemberFieldPtr member;
    ASSERT_TRUE(field->CastTo(&member));  // implicitely validates kind.

    EXPECT_EQ(name, member->name());
    EXPECT_EQ(is_const, member->is_const());
    EXPECT_EQ(is_volatile, member->is_volatile());
    EXPECT_EQ(bit_pos, member->bit_pos());
    EXPECT_EQ(bit_len, member->bit_len());
  }

  scoped_refptr<TypeRepository> types_;
};

}  // namespace

TEST_F(DiaCrawlerTest, TestPointerTypesAreFinalized) {
  // Ensure all pointer types have been finalized (ie content type is set).
  for (auto it : *types_) {
    PointerTypePtr ptr;
    if (it->CastTo(&ptr))
      ASSERT_NE(kNoTypeId, ptr->content_type_id());
  }
}

TEST_F(DiaCrawlerTest, TestSimpleUDT) {
  TypePtr type = FindTypeEndingWith(L"::TestSimpleUDT");
  ASSERT_TRUE(type);

  EXPECT_EQ(16, type->size());
  EXPECT_TRUE(base::EndsWith(type->GetName(), L"::TestSimpleUDT",
                             base::CompareCase::SENSITIVE));

  EXPECT_EQ(Type::USER_DEFINED_TYPE_KIND, type->kind());

  UserDefinedTypePtr udt;
  ASSERT_TRUE(type->CastTo(&udt));
  ASSERT_TRUE(udt);

  EXPECT_FALSE(udt->is_fwd_decl());
  EXPECT_EQ(UserDefinedType::UDT_STRUCT, udt->udt_kind());

  const UserDefinedType::Fields& fields = udt->fields();
  ASSERT_EQ(6U, fields.size());

  ASSERT_NO_FATAL_FAILURE(ValidateMemberField(fields[0], L"one", 0U, !kIsConst,
                                              !kIsVolatile, 0U, 0U));
  EXPECT_EQ(Type::BASIC_TYPE_KIND, udt->GetFieldType(0)->kind());
  EXPECT_EQ(4, udt->GetFieldType(0)->size());
  EXPECT_EQ(L"int32_t", udt->GetFieldType(0)->GetName());

  ASSERT_NO_FATAL_FAILURE(ValidateMemberField(fields[1], L"two", 4U, kIsConst,
                                              !kIsVolatile, 0U, 0U));
  EXPECT_EQ(Type::BASIC_TYPE_KIND, udt->GetFieldType(1)->kind());
  EXPECT_EQ(1, udt->GetFieldType(1)->size());
  EXPECT_EQ(L"char", udt->GetFieldType(1)->GetName());

  ASSERT_NO_FATAL_FAILURE(ValidateMemberField(fields[2], L"three", 8U,
                                              !kIsConst, !kIsVolatile, 0U, 0U));
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
  EXPECT_EQ(L"int16_t const* volatile*", ptr->GetName());

  ASSERT_TRUE(ptr->GetContentType()->CastTo(&ptr));
  ASSERT_TRUE(ptr);
  EXPECT_EQ(4, ptr->size());
  EXPECT_TRUE(ptr->is_const());
  EXPECT_FALSE(ptr->is_volatile());
  ASSERT_EQ(PointerType::PTR_MODE_PTR, ptr->ptr_mode());
  ASSERT_TRUE(ptr->GetContentType());
  EXPECT_EQ(L"int16_t const*", ptr->GetName());
  EXPECT_EQ(Type::BASIC_TYPE_KIND, ptr->GetContentType()->kind());
  EXPECT_EQ(L"int16_t", ptr->GetContentType()->GetName());
  EXPECT_EQ(2, ptr->GetContentType()->size());

  ASSERT_NO_FATAL_FAILURE(ValidateMemberField(fields[3], L"four", 12U, kIsConst,
                                              kIsVolatile, 0U, 0U));
  EXPECT_EQ(Type::BASIC_TYPE_KIND, udt->GetFieldType(3)->kind());
  EXPECT_EQ(2, udt->GetFieldType(3)->size());
  EXPECT_EQ(L"uint16_t", udt->GetFieldType(3)->GetName());

  // Can't do offsetof/sizeof on bit fields.
  ASSERT_NO_FATAL_FAILURE(ValidateMemberField(fields[4], L"five", 14U,
                                              !kIsConst, !kIsVolatile, 0U, 3U));
  EXPECT_EQ(Type::BASIC_TYPE_KIND, udt->GetFieldType(4)->kind());
  EXPECT_EQ(2, udt->GetFieldType(4)->size());
  EXPECT_EQ(L"uint16_t", udt->GetFieldType(4)->GetName());

  ASSERT_NO_FATAL_FAILURE(ValidateMemberField(fields[5], L"six", 14U, !kIsConst,
                                              !kIsVolatile, 3U, 5U));
  EXPECT_EQ(Type::BASIC_TYPE_KIND, udt->GetFieldType(5)->kind());
  EXPECT_EQ(2, udt->GetFieldType(5)->size());
  EXPECT_EQ(L"uint16_t", udt->GetFieldType(5)->GetName());
}

TEST_F(DiaCrawlerTest, TestReference) {
  TypePtr type = FindTypeEndingWith(L"::TestReference");
  ASSERT_TRUE(type);
  EXPECT_TRUE(EndsWith(type->GetName(), L"::TestReference",
                       base::CompareCase::SENSITIVE));
  EXPECT_EQ(Type::USER_DEFINED_TYPE_KIND, type->kind());

  UserDefinedTypePtr udt;
  ASSERT_TRUE(type->CastTo(&udt));
  ASSERT_TRUE(udt);

  const UserDefinedType::Fields& fields = udt->fields();
  ASSERT_EQ(2U, fields.size());

  MemberFieldPtr member;
  ASSERT_TRUE(fields[0]->CastTo(&member));
  EXPECT_EQ(L"value", member->name());

  ASSERT_TRUE(fields[1]->CastTo(&member));
  EXPECT_EQ(L"reference", member->name());
  EXPECT_FALSE(member->is_const());
  EXPECT_FALSE(member->is_volatile());
  ASSERT_EQ(Type::POINTER_TYPE_KIND, udt->GetFieldType(1)->kind());
  PointerTypePtr ptr;
  ASSERT_TRUE(udt->GetFieldType(1)->CastTo(&ptr));
  ASSERT_TRUE(ptr);
  EXPECT_EQ(4, ptr->size());
  EXPECT_TRUE(ptr->is_const());
  EXPECT_FALSE(ptr->is_volatile());
  ASSERT_EQ(PointerType::PTR_MODE_REF, ptr->ptr_mode());
  EXPECT_EQ(L"int32_t const&", ptr->GetName());
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
  EXPECT_EQ(L"int32_t const[30]", int_array->GetName());
  EXPECT_EQ(sizeof(int) * 30, int_array->size());
  EXPECT_TRUE(int_array->is_const());
  EXPECT_FALSE(int_array->is_volatile());

  TypePtr index_type = int_array->GetIndexType();
  EXPECT_EQ(L"uint32_t", index_type->GetName());

  TypePtr element_type = int_array->GetElementType();
  EXPECT_EQ(L"int32_t", element_type->GetName());

  PointerTypePtr array_ptr;
  ASSERT_TRUE(udt->GetFieldType(1)->CastTo(&array_ptr));

  ArrayTypePtr ptr_array;
  ASSERT_TRUE(array_ptr->GetContentType()->CastTo(&ptr_array));

  EXPECT_EQ(32, ptr_array->num_elements());
  EXPECT_EQ(L"testing::TestRecursiveUDT* volatile[32]", ptr_array->GetName());
  EXPECT_EQ(sizeof(void*) * 32, ptr_array->size());
  EXPECT_FALSE(ptr_array->is_const());
  EXPECT_TRUE(ptr_array->is_volatile());

  index_type = ptr_array->GetIndexType();
  EXPECT_EQ(L"uint32_t", index_type->GetName());

  element_type = ptr_array->GetElementType();
  EXPECT_EQ(L"testing::TestRecursiveUDT*", element_type->GetName());
}

TEST_F(DiaCrawlerTest, TestFunctionType) {
  TypePtr type =
      FindTypeEndingWith(L"char const (testing::TestAllInOneUDT::)(int32_t)");
  ASSERT_TRUE(type);

  FunctionTypePtr function;
  ASSERT_EQ(Type::FUNCTION_TYPE_KIND, type->kind());
  ASSERT_TRUE(type->CastTo(&function));
  ASSERT_TRUE(function);

  const FunctionType::Arguments& args = function->argument_types();

  EXPECT_EQ(1U, args.size());

  EXPECT_TRUE(function->IsMemberFunction());
  EXPECT_TRUE(function->return_type().is_const());
  EXPECT_FALSE(function->return_type().is_volatile());
  EXPECT_EQ(function->GetReturnType()->GetName(), L"char");

  EXPECT_FALSE(args[0].is_const());
  EXPECT_FALSE(args[0].is_volatile());
  EXPECT_EQ(function->GetArgumentType(0)->GetName(), L"int32_t");

  // Find the containing class.
  type = FindTypeEndingWith(L"::TestAllInOneUDT");
  ASSERT_TRUE(type);

  // Check that the function points to its containing class.
  EXPECT_EQ(function->containing_class_id(), type->type_id());

  EXPECT_EQ(function->GetName(),
            L"char const (" + type->GetName() + L"::)(int32_t)");
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
  EXPECT_EQ(function->GetReturnType()->GetName(), L"void");
  EXPECT_EQ(udt->type_id(), function->containing_class_id());

  EXPECT_EQ(L"NonOverloadedFunction", functions[1].name());
  EXPECT_TRUE(udt->GetFunctionType(1)->CastTo(&function));
  EXPECT_EQ(0U, function->argument_types().size());
  EXPECT_EQ(function->GetReturnType()->GetName(), L"void");
  EXPECT_EQ(udt->type_id(), function->containing_class_id());

  EXPECT_EQ(L"OverloadedFunction", functions[2].name());
  EXPECT_TRUE(udt->GetFunctionType(2)->CastTo(&function));
  EXPECT_EQ(1U, function->argument_types().size());
  EXPECT_EQ(function->GetArgumentType(0)->GetName(), L"int32_t");
  EXPECT_EQ(function->GetReturnType()->GetName(), L"void");
  EXPECT_EQ(udt->type_id(), function->containing_class_id());

  EXPECT_EQ(L"OverloadedFunction", functions[3].name());
  EXPECT_TRUE(udt->GetFunctionType(3)->CastTo(&function));
  EXPECT_EQ(0U, function->argument_types().size());
  EXPECT_EQ(function->GetReturnType()->GetName(), L"int32_t");
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

TEST_F(DiaCrawlerTest, TestGlobals) {
  TypePtr type = FindTypeEndingWith(L"::test_global");
  ASSERT_TRUE(type);

  ASSERT_EQ(Type::GLOBAL_TYPE_KIND, type->kind());

  GlobalTypePtr global;
  ASSERT_TRUE(type->CastTo(&global));
  ASSERT_TRUE(global);

  ASSERT_EQ(global->GetDataType(), FindTypeEndingWith(L"TestAllInOneUDT"));
  ASSERT_NE(0, global->rva());
}

namespace {
typedef bool (*GetExpectedVftableVAsPtr)(unsigned buffer_size,
                                         unsigned long long* vftable_vas,
                                         unsigned* count);
}  // namespace

class DiaCrawlerVTableTest : public testing::PdbCrawlerVTableTestBase {
 protected:
  void GetVFTableRVAs(const wchar_t* pdb_path_str,
                      base::hash_set<RelativeAddress>* vftable_rvas) override {
    DCHECK(pdb_path_str);  DCHECK(vftable_rvas);

    DiaCrawler crawler;
    ASSERT_TRUE(
        crawler.InitializeForFile(testing::GetSrcRelativePath(pdb_path_str)));
    ASSERT_TRUE(crawler.GetVFTableRVAs(vftable_rvas));
  }
};

TEST_F(DiaCrawlerVTableTest, TestGetVFTableRVAs) {
  // A pdb without OMAP.
  ASSERT_NO_FATAL_FAILURE(PerformGetVFTableRVAsTest(
      L"syzygy\\refinery\\test_data\\test_vtables.dll.pdb",
      L"syzygy\\refinery\\test_data\\test_vtables.dll"));
}

}  // namespace refinery
