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
#include "base/strings/string_util.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/refinery/types/type_repository.h"


namespace refinery {

namespace {

class DiaCrawlerTest : public testing::Test {
 protected:
};

}  // namespace

TEST_F(DiaCrawlerTest, InitializeForFile) {
  DiaCrawler crawler;

  ASSERT_TRUE(crawler.InitializeForFile(
      testing::GetSrcRelativePath(
          L"syzygy\\refinery\\test_data\\test_types.dll.pdb")));

  TypeRepository types;
  ASSERT_TRUE(crawler.GetTypes(&types));

  // TODO(siggi): Types can be duplicated for some reason - maybe the crawler
  // should eliminate dupes?
  ASSERT_LE(1U, types.size());

  // TODO(siggi): This needs rewriting.
  TypePtr type;
  for (auto it = types.begin(); it != types.end(); ++it) {
    if (EndsWith((*it)->name(), L"::TestSimpleUDT", true)) {
      type = *it;
      break;
    }
  }
  ASSERT_TRUE(type);

  EXPECT_EQ(16, type->size());
  EXPECT_TRUE(EndsWith(type->name(), L"::TestSimpleUDT", true));

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

}  // namespace refinery
