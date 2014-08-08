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

#include "syzygy/genfilter/filter_compiler.h"

#include "base/file_util.h"
#include "gtest/gtest.h"
#include "syzygy/common/unittest_util.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/unittest_util.h"

namespace genfilter {

namespace {

class TestFilterCompiler : public FilterCompiler {
 public:
  using FilterCompiler::Rule;
  using FilterCompiler::RuleMap;
  using FilterCompiler::RulePointers;

  using FilterCompiler::rule_map_;
  using FilterCompiler::rules_by_type_;

  TestFilterCompiler() { }

  // Returns the |index|th rule.
  const Rule& rule(size_t index) const {
    RuleMap::const_iterator it = rule_map_.find(index);
    return it->second;
  }
};

class FilterCompilerTest : public testing::PELibUnitTest {
 public:
  typedef testing::PELibUnitTest Super;

  virtual void SetUp() OVERRIDE {
    Super::SetUp();
    ASSERT_NO_FATAL_FAILURE(CreateTemporaryDir(&temp_dir_));
    test_dll_ = testing::GetExeRelativePath(testing::kTestDllName);
    test_dll_pdb_ = testing::GetOutputRelativePath(testing::kTestDllPdbName);
    dummy_dll_ = testing::GetExeRelativePath(L"this-does-not-exist.dll");
    dummy_pdb_ = testing::GetExeRelativePath(L"this-does-not-exist.pdb");
    mismatched_test_dll_pdb_ =
        testing::GetSrcRelativePath(L"pe\\test_data\\test_dll.pdb");
    filter_txt_ = temp_dir_.Append(L"filter.txt");
  }

  virtual void TearDown() OVERRIDE {
    ASSERT_TRUE(base::DeleteFile(temp_dir_, true));
    Super::TearDown();
  }

  void CreateFilterDescriptionFile(const base::StringPiece& line) {
    base::ScopedFILE file(base::OpenFile(filter_txt_, "wb"));
    ::fprintf(file.get(), "%.*s\n", line.length(), line.data());
  }

  void CreateFilterDescriptionFile() {
    base::ScopedFILE file(base::OpenFile(filter_txt_, "wb"));
    ::fprintf(file.get(), "# This is a comment.\n");
    ::fprintf(file.get(), "\n");
    ::fprintf(file.get(), "+function:DllMain  # Another comment.\n");
    ::fprintf(file.get(), " + function : ThisFunctionDoesNotExist \n");
    ::fprintf(file.get(), "-public_symbol:\\?function1.*\n");
  }

  // A temporary folder for holding filter files, etc.
  base::FilePath temp_dir_;

  // A handful of paths.
  base::FilePath test_dll_;
  base::FilePath test_dll_pdb_;
  base::FilePath dummy_dll_;
  base::FilePath dummy_pdb_;
  base::FilePath mismatched_test_dll_pdb_;
  base::FilePath filter_txt_;
};

}  // namespace

TEST_F(FilterCompilerTest, Constructor) {
  TestFilterCompiler fc;
  EXPECT_TRUE(fc.image_path().empty());
  EXPECT_TRUE(fc.pdb_path().empty());
  EXPECT_TRUE(fc.rule_map_.empty());
  for (size_t i = 0; i < arraysize(fc.rules_by_type_); ++i) {
    EXPECT_TRUE(fc.rules_by_type_[i].empty());
  }
}

TEST_F(FilterCompilerTest, InitFailsInvalidPePath) {
  DisableLogging();

  TestFilterCompiler fc1;
  EXPECT_FALSE(fc1.Init(dummy_dll_));

  TestFilterCompiler fc2;
  EXPECT_FALSE(fc2.Init(dummy_dll_, base::FilePath()));
}

TEST_F(FilterCompilerTest, InitFailsInvalidPdbPath) {
  DisableLogging();

  TestFilterCompiler fc;
  EXPECT_FALSE(fc.Init(test_dll_, dummy_pdb_));
}

TEST_F(FilterCompilerTest, InitFailsMismatchedPeAndPdb) {
  DisableLogging();

  TestFilterCompiler fc;
  EXPECT_FALSE(fc.Init(test_dll_, mismatched_test_dll_pdb_));
}

TEST_F(FilterCompilerTest, InitSucceedsSpecifiedPdb) {
  TestFilterCompiler fc;
  EXPECT_TRUE(fc.Init(test_dll_, test_dll_pdb_));
  EXPECT_EQ(test_dll_, fc.image_path());
  EXPECT_EQ(test_dll_pdb_, fc.pdb_path());
}

TEST_F(FilterCompilerTest, InitSucceedsSearchForPdb) {
  TestFilterCompiler fc1;
  EXPECT_TRUE(fc1.Init(test_dll_));
  EXPECT_EQ(test_dll_, fc1.image_path());
  EXPECT_SAME_FILE(test_dll_pdb_, fc1.pdb_path());

  TestFilterCompiler fc2;
  EXPECT_TRUE(fc2.Init(test_dll_, base::FilePath()));
  EXPECT_EQ(test_dll_, fc2.image_path());
  EXPECT_SAME_FILE(test_dll_pdb_, fc2.pdb_path());
}

TEST_F(FilterCompilerTest, AddRule) {
  DisableLogging();

  TestFilterCompiler fc;
  ASSERT_TRUE(fc.Init(test_dll_, test_dll_pdb_));
  EXPECT_EQ(0u, fc.rule_map_.size());
  EXPECT_EQ(0u, fc.rules_by_type_[FilterCompiler::kFunctionRule].size());
  EXPECT_EQ(0u, fc.rules_by_type_[FilterCompiler::kPublicSymbolRule].size());

  EXPECT_FALSE(fc.AddRule(FilterCompiler::kAddToFilter,
                          FilterCompiler::kFunctionRule,
                          "broken(regex[foo"));

  EXPECT_TRUE(fc.AddRule(FilterCompiler::kAddToFilter,
                         FilterCompiler::kFunctionRule,
                         "foo"));
  EXPECT_EQ(1u, fc.rule_map_.size());
  EXPECT_EQ(1u, fc.rules_by_type_[FilterCompiler::kFunctionRule].size());
  EXPECT_EQ(0u, fc.rules_by_type_[FilterCompiler::kPublicSymbolRule].size());

  EXPECT_TRUE(fc.AddRule(FilterCompiler::kSubtractFromFilter,
                         FilterCompiler::kPublicSymbolRule,
                         "bar"));
  EXPECT_EQ(2u, fc.rule_map_.size());
  EXPECT_EQ(1u, fc.rules_by_type_[FilterCompiler::kFunctionRule].size());
  EXPECT_EQ(1u, fc.rules_by_type_[FilterCompiler::kPublicSymbolRule].size());
}

TEST_F(FilterCompilerTest, ParseFilterDescriptionFileMissingFile) {
  DisableLogging();

  TestFilterCompiler fc;
  ASSERT_TRUE(fc.Init(test_dll_, test_dll_pdb_));

  EXPECT_FALSE(fc.ParseFilterDescriptionFile(filter_txt_));
}

TEST_F(FilterCompilerTest, ParseFilterDescriptionFileBadModificationType) {
  DisableLogging();

  ASSERT_NO_FATAL_FAILURE(CreateFilterDescriptionFile("?function:foo"));

  TestFilterCompiler fc;
  ASSERT_TRUE(fc.Init(test_dll_, test_dll_pdb_));

  EXPECT_FALSE(fc.ParseFilterDescriptionFile(filter_txt_));
}

TEST_F(FilterCompilerTest, ParseFilterDescriptionFileBadRuleType) {
  DisableLogging();

  ASSERT_NO_FATAL_FAILURE(CreateFilterDescriptionFile(
      "+invalid_type:foo"));

  TestFilterCompiler fc;
  ASSERT_TRUE(fc.Init(test_dll_, test_dll_pdb_));

  EXPECT_FALSE(fc.ParseFilterDescriptionFile(filter_txt_));
}

TEST_F(FilterCompilerTest, ParseFilterDescriptionFileBadRegex) {
  DisableLogging();

  ASSERT_NO_FATAL_FAILURE(CreateFilterDescriptionFile(
      "+function:broken(regex[ab"));

  TestFilterCompiler fc;
  ASSERT_TRUE(fc.Init(test_dll_, test_dll_pdb_));

  EXPECT_FALSE(fc.ParseFilterDescriptionFile(filter_txt_));
}

TEST_F(FilterCompilerTest, ParseFilterDescriptionFileSucceeds) {
  ASSERT_NO_FATAL_FAILURE(CreateFilterDescriptionFile());

  TestFilterCompiler fc;
  ASSERT_TRUE(fc.Init(test_dll_, test_dll_pdb_));

  ASSERT_TRUE(fc.ParseFilterDescriptionFile(filter_txt_));
  EXPECT_EQ(3u, fc.rule_map_.size());
  EXPECT_EQ(FilterCompiler::kFunctionRule, fc.rule(0).rule_type);
  EXPECT_EQ(FilterCompiler::kFunctionRule, fc.rule(1).rule_type);
  EXPECT_EQ(FilterCompiler::kPublicSymbolRule, fc.rule(2).rule_type);
  EXPECT_EQ(FilterCompiler::kAddToFilter, fc.rule(0).modification_type);
  EXPECT_EQ(FilterCompiler::kAddToFilter, fc.rule(1).modification_type);
  EXPECT_EQ(FilterCompiler::kSubtractFromFilter, fc.rule(2).modification_type);
}

TEST_F(FilterCompilerTest, Compile) {
  ASSERT_NO_FATAL_FAILURE(CreateFilterDescriptionFile());

  TestFilterCompiler fc;
  ASSERT_TRUE(fc.Init(test_dll_, test_dll_pdb_));
  ASSERT_TRUE(fc.ParseFilterDescriptionFile(filter_txt_));
  ASSERT_EQ(3u, fc.rule_map_.size());  // Three rules should have been parsed.

  pe::ImageFilter filter;
  EXPECT_TRUE(fc.Compile(&filter));

  // The first and last rules should have matched actual symbol info.
  EXPECT_EQ(1u, fc.rule(0).ranges.size());
  EXPECT_EQ(0u, fc.rule(1).ranges.size());
  EXPECT_EQ(1u, fc.rule(2).ranges.size());

  // The image filter should be non-empty.
  EXPECT_LT(0u, filter.filter.size());
}

}  // namespace genfilter
