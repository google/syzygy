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

namespace refinery {

namespace {

class DiaCrawlerTest : public testing::Test {
 protected:
  void SetUp() override {
    ASSERT_TRUE(PathService::Get(base::FILE_EXE, &self_));
  }

  const base::FilePath& self() const { return self_; }

  // TODO(siggi): More testing, including static members, function members,
  //    thread-local data etc.
  struct TestSimpleUDT {
    int one;
    const char two;
    short const* volatile three;
    const volatile unsigned short four;
    unsigned short five:1;
  };

 private:
  base::FilePath self_;
};

}  // namespace

TEST_F(DiaCrawlerTest, InitializeForFile) {
  DiaCrawler crawler;

  ASSERT_TRUE(crawler.InitializeForFile(self()));

  std::vector<TypePtr> types;
  ASSERT_TRUE(crawler.GetTypes(L"*DiaCrawlerTest::TestSimpleUDT", &types));

  // TODO(siggi): Types can be duplicated for some reason - maybe the crawler
  // should eliminate dupes?
  ASSERT_LE(1U, types.size());

  TypePtr type = types[0];
  ASSERT_TRUE(type);

  TestSimpleUDT test = { 0, 0, 0, 0, 0 };
  base::debug::Alias(&test);

  EXPECT_EQ(sizeof(test), type->size());
  EXPECT_TRUE(EndsWith(type->name(), L"DiaCrawlerTest::TestSimpleUDT", true));

  EXPECT_EQ(Type::USER_DEFINED_TYPE_KIND, type->kind());

  UserDefinedTypePtr udt;
  ASSERT_TRUE(types[0]->CastTo(&udt));
  ASSERT_TRUE(udt);

  const UserDefinedType::Fields& fields = udt->fields();
  ASSERT_EQ(5U, fields.size());

  EXPECT_EQ(offsetof(TestSimpleUDT, one), fields[0].offset());
  EXPECT_EQ(L"one", fields[0].name());
  EXPECT_FALSE(fields[0].is_const());
  EXPECT_FALSE(fields[0].is_volatile());
  EXPECT_EQ(Type::BASIC_TYPE_KIND, fields[0].type()->kind());
  EXPECT_EQ(sizeof(test.one), fields[0].type()->size());
  // TODO(siggi): Assert on type's name.

  EXPECT_EQ(offsetof(TestSimpleUDT, two), fields[1].offset());
  EXPECT_EQ(L"two", fields[1].name());
  EXPECT_TRUE(fields[1].is_const());
  EXPECT_FALSE(fields[1].is_volatile());
  EXPECT_EQ(Type::BASIC_TYPE_KIND, fields[1].type()->kind());
  EXPECT_EQ(sizeof(test.two), fields[1].type()->size());
  // TODO(siggi): Assert on type's name.

  EXPECT_EQ(offsetof(TestSimpleUDT, three), fields[2].offset());
  EXPECT_EQ(L"three", fields[2].name());
  EXPECT_FALSE(fields[2].is_const());
  EXPECT_TRUE(fields[2].is_volatile());
  ASSERT_EQ(Type::POINTER_TYPE_KIND, fields[2].type()->kind());
  EXPECT_EQ(sizeof(test.three), fields[2].type()->size());
  PointerTypePtr ptr;
  ASSERT_TRUE(fields[2].type()->CastTo(&ptr));
  ASSERT_TRUE(ptr);
  EXPECT_TRUE(ptr->is_const());
  EXPECT_FALSE(ptr->is_volatile());
  ASSERT_TRUE(ptr->type());
  EXPECT_EQ(Type::BASIC_TYPE_KIND, ptr->type()->kind());
  // TODO(siggi): Assert on type's name.

  EXPECT_EQ(offsetof(TestSimpleUDT, four), fields[3].offset());
  EXPECT_EQ(L"four", fields[3].name());
  EXPECT_TRUE(fields[3].is_const());
  EXPECT_TRUE(fields[3].is_volatile());
  EXPECT_EQ(Type::BASIC_TYPE_KIND, fields[3].type()->kind());
  EXPECT_EQ(sizeof(test.four), fields[3].type()->size());
  // TODO(siggi): Assert on type's name.

  // Can't do offsetof/sizeof on bit fields.
  EXPECT_EQ(offsetof(TestSimpleUDT, four) + sizeof(test.four),
            fields[4].offset());
  EXPECT_EQ(L"five", fields[4].name());
  EXPECT_FALSE(fields[4].is_const());
  EXPECT_FALSE(fields[4].is_volatile());
  EXPECT_EQ(Type::BITFIELD_TYPE_KIND, fields[4].type()->kind());
  // TODO(siggi): Assert on type's name.
}

}  // namespace refinery
