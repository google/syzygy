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

#include "syzygy/pehacker/variables.h"

#include "base/logging.h"
#include "gtest/gtest.h"

namespace pehacker {

namespace {

class VariablesTest : public testing::Test {
 public:
  VariablesTest() : previous_log_level_(0) {
  }

  void SetUp() {
    // Silence logging.
    previous_log_level_ = logging::GetMinLogLevel();
    logging::SetMinLogLevel(logging::LOG_FATAL);
  }

  void TearDown() {
    // Restore logging to its previous level.
    logging::SetMinLogLevel(previous_log_level_);
    previous_log_level_ = 0;
  }

  int previous_log_level_;
};

}  // namespace

TEST_F(VariablesTest, VariableNameIsValid) {
  EXPECT_FALSE(VariableNameIsValid("foo bar"));
  EXPECT_FALSE(VariableNameIsValid("foo-bar"));
  EXPECT_FALSE(VariableNameIsValid("foo@bar"));
  EXPECT_FALSE(VariableNameIsValid("foo!bar"));
  EXPECT_FALSE(VariableNameIsValid("var%"));
  EXPECT_TRUE(VariableNameIsValid("123"));
  EXPECT_TRUE(VariableNameIsValid("foo"));
  EXPECT_TRUE(VariableNameIsValid("foo123"));
  EXPECT_TRUE(VariableNameIsValid("foo_bar"));
  EXPECT_TRUE(VariableNameIsValid("foo_bar_1"));
  EXPECT_TRUE(VariableNameIsValid("__"));
}

TEST_F(VariablesTest, ConvertVariableToString) {
  std::string result;

  base::DictionaryValue d;
  base::ListValue l;
  base::FundamentalValue f(static_cast<double>(3.14));
  EXPECT_FALSE(ConvertVariableToString(d, &result));
  EXPECT_FALSE(ConvertVariableToString(l, &result));
  EXPECT_FALSE(ConvertVariableToString(f, &result));

  base::FundamentalValue b(static_cast<bool>(true));
  base::FundamentalValue i(static_cast<int>(42));
  base::StringValue s("string");
  EXPECT_TRUE(ConvertVariableToString(b, &result));
  EXPECT_EQ("1", result);
  EXPECT_TRUE(ConvertVariableToString(i, &result));
  EXPECT_EQ("42", result);
  EXPECT_TRUE(ConvertVariableToString(s, &result));
  EXPECT_EQ("string", result);
}

TEST_F(VariablesTest, ConvertVariableToJson) {
  std::string result;

  base::DictionaryValue d;
  base::ListValue l;
  base::FundamentalValue f(static_cast<double>(3.14));
  EXPECT_FALSE(ConvertVariableToJson(d, &result));
  EXPECT_FALSE(ConvertVariableToJson(l, &result));
  EXPECT_FALSE(ConvertVariableToJson(f, &result));

  base::FundamentalValue b(static_cast<bool>(true));
  base::FundamentalValue i(static_cast<int>(42));
  base::StringValue s("string");
  EXPECT_TRUE(ConvertVariableToJson(b, &result));
  EXPECT_EQ("1", result);
  EXPECT_TRUE(ConvertVariableToJson(i, &result));
  EXPECT_EQ("42", result);
  EXPECT_TRUE(ConvertVariableToJson(s, &result));
  EXPECT_EQ("\"string\"", result);
}

TEST_F(VariablesTest, ParseVariableFailsForInvalidNames) {
  base::DictionaryValue d;
  EXPECT_FALSE(ParseVariable("foo bar", "", &d));
  EXPECT_FALSE(ParseVariable("foo-bar", "", &d));
  EXPECT_FALSE(ParseVariable("foo@bar", "", &d));

  base::StringValue s("");
  EXPECT_FALSE(ParseVariable("foo bar", s, &d));
  EXPECT_FALSE(ParseVariable("foo-bar", s, &d));
  EXPECT_FALSE(ParseVariable("foo@bar", s, &d));
}

TEST_F(VariablesTest, ParseVariableFailsForInvalidStringValues) {
  base::DictionaryValue d;
  EXPECT_FALSE(ParseVariable("var", "[]", &d));
  EXPECT_FALSE(ParseVariable("var", "{}", &d));
  EXPECT_FALSE(ParseVariable("var", "3.14", &d));

  base::ListValue l;
  base::FundamentalValue f(static_cast<double>(3.14));
  EXPECT_FALSE(ParseVariable("var", d, &d));
  EXPECT_FALSE(ParseVariable("var", l, &d));
  EXPECT_FALSE(ParseVariable("var", f, &d));
}

TEST_F(VariablesTest, ParseVariableFailsCollision) {
  base::DictionaryValue d;
  EXPECT_TRUE(ParseVariable("var", "3", &d));
  EXPECT_FALSE(ParseVariable("var", "4", &d));

  base::StringValue s("hey");
  EXPECT_FALSE(ParseVariable("var", s, &d));

  int var = 0;
  EXPECT_TRUE(d.GetInteger("var", &var));
  EXPECT_EQ(3, var);
}

TEST_F(VariablesTest, ParseVariableSucceedsDefault) {
  base::DictionaryValue d;
  EXPECT_TRUE(ParseVariable("var1", "1", &d));
  EXPECT_TRUE(ParseVariable("var2%", "2", &d));
  EXPECT_TRUE(ParseVariable("var1%", "0", &d));

  int var1 = 0;
  int var2 = 0;
  EXPECT_TRUE(d.GetInteger("var1", &var1));
  EXPECT_TRUE(d.GetInteger("var2", &var2));
  EXPECT_EQ(1, var1);
  EXPECT_EQ(2, var2);
}

TEST_F(VariablesTest, ParseVariableSucceeds) {
  base::DictionaryValue d;
  EXPECT_TRUE(ParseVariable("var1", "true", &d));
  EXPECT_TRUE(ParseVariable("var2", "3", &d));
  EXPECT_TRUE(ParseVariable("var3", "string", &d));
  EXPECT_TRUE(ParseVariable("var4", "\"string\"", &d));
  EXPECT_TRUE(ParseVariable("var5", "", &d));

  std::string s;
  int i = 0;
  bool b = false;

  EXPECT_TRUE(d.GetBoolean("var1", &b));
  EXPECT_TRUE(b);

  EXPECT_TRUE(d.GetInteger("var2", &i));
  EXPECT_EQ(3, i);

  EXPECT_TRUE(d.GetString("var3", &s));
  EXPECT_EQ("string", s);

  EXPECT_TRUE(d.GetString("var4", &s));
  EXPECT_EQ("string", s);

  EXPECT_TRUE(d.GetString("var5", &s));
  EXPECT_TRUE(s.empty());
}

TEST_F(VariablesTest, MergeVariables) {
  base::DictionaryValue dst;
  base::DictionaryValue src;

  src.SetInteger("var1%", 3);
  src.SetInteger("var2", 45);

  dst.SetInteger("var1", 42);

  EXPECT_TRUE(MergeVariables(src, &dst));

  int i = 0;
  EXPECT_TRUE(dst.GetInteger("var1", &i));
  EXPECT_EQ(42, i);
  EXPECT_TRUE(dst.GetInteger("var2", &i));
  EXPECT_EQ(45, i);

  // This will fail a second time becase var2 is defined.
  EXPECT_FALSE(MergeVariables(src, &dst));

  EXPECT_TRUE(dst.GetInteger("var1", &i));
  EXPECT_EQ(42, i);
  EXPECT_TRUE(dst.GetInteger("var2", &i));
  EXPECT_EQ(45, i);
}

TEST_F(VariablesTest, ExpandVariables) {
  base::DictionaryValue d;
  d.SetString("var1", "foo");
  d.SetString("var2", "$(var1)bar");
  d.SetString("var3", "$(var4)");
  d.SetString("var4", "$(var3)");

  std::string s;
  EXPECT_FALSE(ExpandVariables(d, "$", &s));        // Hanging $.
  EXPECT_FALSE(ExpandVariables(d, "$$$", &s));      // Hanging $.
  EXPECT_FALSE(ExpandVariables(d, "$(foo", &s));    // Mismatched parenthesis.
  EXPECT_FALSE(ExpandVariables(d, "$()", &s));      // Empty name.
  EXPECT_FALSE(ExpandVariables(d, "$(var5)", &s));  // Missing variable.
  EXPECT_FALSE(ExpandVariables(d, "$(var4)", &s));  // Circular definition.

  EXPECT_TRUE(ExpandVariables(d, "$$", &s));
  EXPECT_EQ("$", s);

  EXPECT_TRUE(ExpandVariables(d, "$$(var1)", &s));
  EXPECT_EQ("$(var1)", s);

  EXPECT_TRUE(ExpandVariables(d, "$(var2)", &s));
  EXPECT_EQ("foobar", s);

  EXPECT_TRUE(ExpandVariables(d, "$(var1)-$(var2)", &s));
  EXPECT_EQ("foo-foobar", s);

  EXPECT_TRUE(ExpandVariables(d, "$$$(var1)", &s));
  EXPECT_EQ("$foo", s);
}

}  // namespace pehacker
