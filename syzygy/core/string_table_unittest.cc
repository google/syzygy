// Copyright 2013 Google Inc. All Rights Reserved.
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

#include "syzygy/core/string_table.h"

#include "gtest/gtest.h"

namespace core {

namespace {

class TestStringTable : public StringTable {
 public:
  using StringTable::string_table_;
};

}  // namespace

TEST(StringTableTest, DefaultConstructor) {
  TestStringTable strtab;
  EXPECT_TRUE(strtab.string_table_.empty());
}

TEST(StringTableTest, InternString) {
  TestStringTable strtab;

  // The pool is initially empty.
  EXPECT_EQ(0U, strtab.string_table_.size());

  const std::string& str1 = strtab.InternString("foo");
  const std::string& str2 = strtab.InternString("bar");
  const std::string& str3 = strtab.InternString("foo");
  const std::string& str4 = strtab.InternString("foo");
  const std::string& str5 = strtab.InternString("bat");

  // Validate the size of the internal strings pool.
  EXPECT_EQ(3U, strtab.string_table_.size());

  // Validate string sharing.
  EXPECT_FALSE(str1.c_str() == str2.c_str());
  EXPECT_TRUE(str1.c_str() == str3.c_str());
  EXPECT_TRUE(str1.c_str() == str4.c_str());
  EXPECT_FALSE(str1.c_str() == str5.c_str());
}

}  // namespace core
