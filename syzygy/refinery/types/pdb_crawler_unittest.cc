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

#include "syzygy/refinery/types/pdb_crawler.h"

#include "base/path_service.h"
#include "base/debug/alias.h"
#include "base/files/file_path.h"
#include "base/strings/string_util.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/refinery/types/type.h"
#include "syzygy/refinery/types/type_repository.h"

namespace refinery {

namespace {

class PdbCrawlerTest : public testing::Test {
 protected:
  virtual void SetUp() {
    test_types_file_ = testing::GetSrcRelativePath(
        L"syzygy\\refinery\\test_data\\test_types.dll.pdb");
    LoadTypes();
  }

  void LoadTypes() {
    ASSERT_TRUE(crawler_.InitializeForFile(test_types_file_));

    ASSERT_TRUE(crawler_.GetTypes(&types_));
    ASSERT_LE(1U, types_.size());
  }

  std::vector<TypePtr> FindTypesBySuffix(const base::string16& suffix) {
    std::vector<TypePtr> found_types;
    for (auto it = types_.begin(); it != types_.end(); ++it) {
      if (base::EndsWith((*it)->name(), suffix, base::CompareCase::SENSITIVE)) {
        found_types.push_back(*it);
      }
    }
    return found_types;
  }

  PdbCrawler crawler_;
  TypeRepository types_;
  base::FilePath test_types_file_;
};

}  // namespace

TEST_F(PdbCrawlerTest, TestSimpleUDT) {
  auto simple_udt = FindTypesBySuffix(L"::TestSimpleUDT");

  ASSERT_EQ(1U, simple_udt.size());

  TypePtr type = simple_udt[0];

  ASSERT_TRUE(type);

  EXPECT_EQ(16, type->size());
  EXPECT_TRUE(
      EndsWith(type->name(), L"::TestSimpleUDT", base::CompareCase::SENSITIVE));

  EXPECT_EQ(Type::USER_DEFINED_TYPE_KIND, type->kind());

  UserDefinedTypePtr udt;
  ASSERT_TRUE(type->CastTo(&udt));
  ASSERT_TRUE(udt);

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
  EXPECT_EQ(Type::POINTER_TYPE_KIND, ptr->GetContentType()->kind());
  EXPECT_EQ(L"int16_t const* volatile*", ptr->name());

  ASSERT_TRUE(ptr->GetContentType()->CastTo(&ptr));
  ASSERT_TRUE(ptr);
  EXPECT_EQ(4, ptr->size());
  EXPECT_TRUE(ptr->is_const());
  EXPECT_FALSE(ptr->is_volatile());
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

  // TODO(mopler): Process and test bitfields. In the current implementation
  // the member field of bitfields point to a non-existent types.
}

TEST_F(PdbCrawlerTest, TestCollidingUDTs) {
  auto colliding_types = FindTypesBySuffix(L"::TestCollidingUDT");

  ASSERT_EQ(2U, colliding_types.size());
  TypePtr type1 = colliding_types[0];
  TypePtr type2 = colliding_types[1];

  ASSERT_TRUE(type1);
  ASSERT_TRUE(type2);

  EXPECT_EQ(type1->name(), type2->name());
  EXPECT_NE(type1->decorated_name(), type2->decorated_name());

  EXPECT_EQ(Type::USER_DEFINED_TYPE_KIND, type1->kind());
  EXPECT_EQ(Type::USER_DEFINED_TYPE_KIND, type2->kind());

  UserDefinedTypePtr udt1;
  UserDefinedTypePtr udt2;

  ASSERT_TRUE(type1->CastTo(&udt1));
  ASSERT_TRUE(udt1);
  ASSERT_TRUE(type2->CastTo(&udt2));
  ASSERT_TRUE(udt2);

  EXPECT_NE(udt1->fields().size(), udt2->fields().size());
}

TEST_F(PdbCrawlerTest, TestRecursiveUDTs) {
  auto recursive_udt = FindTypesBySuffix(L"::TestRecursiveUDT");

  ASSERT_EQ(1U, recursive_udt.size());

  TypePtr type = recursive_udt[0];

  ASSERT_TRUE(type);

  ASSERT_EQ(Type::USER_DEFINED_TYPE_KIND, type->kind());

  UserDefinedTypePtr udt;
  ASSERT_TRUE(type->CastTo(&udt));
  ASSERT_TRUE(udt);

  EXPECT_EQ(2, udt->fields().size());
  ASSERT_EQ(Type::POINTER_TYPE_KIND, udt->GetFieldType(0)->kind());
  ASSERT_EQ(Type::POINTER_TYPE_KIND, udt->GetFieldType(1)->kind());

  PointerTypePtr ptr1;
  PointerTypePtr ptr2;

  ASSERT_TRUE(udt->GetFieldType(0)->CastTo(&ptr1));
  ASSERT_TRUE(udt->GetFieldType(1)->CastTo(&ptr2));

  EXPECT_EQ(udt, ptr1->GetContentType());
  EXPECT_EQ(udt, ptr2->GetContentType());
}

}  // namespace refinery
