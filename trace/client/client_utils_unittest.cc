// Copyright 2012 Google Inc. All Rights Reserved.
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

#include "syzygy/trace/client/client_utils.h"

#include "base/environment.h"
#include "base/utf_string_conversions.h"
#include "base/memory/scoped_ptr.h"
#include "gtest/gtest.h"
#include "syzygy/core/file_util.h"
#include "syzygy/core/unittest_util.h"

// http://blogs.msdn.com/oldnewthing/archive/2004/10/25/247180.aspx
extern "C" IMAGE_DOS_HEADER __ImageBase;

namespace trace {
namespace client {

namespace {

// A utility for ensuring that two file paths point to the same file. Upon
// failure, outputs the actual paths as well.
::testing::AssertionResult AssertAreSameFile(const char* path1_expr,
                                             const char* path2_expr,
                                             const FilePath& path1,
                                             const FilePath& path2) {
  core::FilePathCompareResult result = core::CompareFilePaths(path1, path2);
  if (result == core::kEquivalentFilePaths)
    return ::testing::AssertionSuccess();

  return ::testing::AssertionFailure() << "FilePathsReferToSameFile("
      << path1_expr << ", " << path2_expr << ") returned " << result
      << ", expected " << core::kEquivalentFilePaths << " (" << path1_expr
      << " = \"" << path1.value() << "\", " << path2_expr << " = \""
      << path2.value() << "\").";
}

// A gtest-like macro for ensuring two paths refer to the same file.
#define EXPECT_SAME_FILE(path1, path2) \
    EXPECT_PRED_FORMAT2(AssertAreSameFile, path1, path2)

class GetInstanceIdForModuleTest : public testing::Test {
 public:
  GetInstanceIdForModuleTest() : path_(L"C:\\path\\foo.exe") { }

  virtual void SetUp() OVERRIDE {
    testing::Test::SetUp();
    env_.reset(base::Environment::Create());
  }

  void SetEnvVar(const base::StringPiece& string) {
    ASSERT_TRUE(env_->SetVar(::kSyzygyRpcInstanceIdEnvVar, string.as_string()));
  }

  void UnsetEnvVar() {
    ASSERT_TRUE(env_->UnSetVar(::kSyzygyRpcInstanceIdEnvVar));
  }

  FilePath path_;
  scoped_ptr<base::Environment> env_;
};

}  // namespace

TEST(GetModuleBaseAddressTest, WorksOnSelf) {
  void* module_base = NULL;
  EXPECT_TRUE(GetModuleBaseAddress(&GetModuleBaseAddress, &module_base));
  EXPECT_EQ(&__ImageBase, module_base);
}

TEST(GetModulePath, WorksOnSelf) {
  void* module_base = NULL;
  ASSERT_TRUE(GetModuleBaseAddress(&GetModuleBaseAddress, &module_base));

  FilePath module_path;
  EXPECT_TRUE(GetModulePath(module_base, &module_path));

  FilePath self_path =
      ::testing::GetExeRelativePath(L"rpc_client_lib_unittests.exe");
  EXPECT_SAME_FILE(self_path, module_path);
}

TEST_F(GetInstanceIdForModuleTest, ReturnsEmptyForNoEnvVar) {
  ASSERT_NO_FATAL_FAILURE(UnsetEnvVar());
  EXPECT_EQ(std::string(), GetInstanceIdForModule(path_));
}

TEST_F(GetInstanceIdForModuleTest, ReturnsEmptyForEmptyEnvVar) {
  ASSERT_NO_FATAL_FAILURE(SetEnvVar(""));
  EXPECT_EQ(std::string(), GetInstanceIdForModule(path_));
}

TEST_F(GetInstanceIdForModuleTest, ReturnsEmptyForNoMatch) {
  ASSERT_NO_FATAL_FAILURE(SetEnvVar("bar.exe,1;baz.exe,2"));
  EXPECT_EQ(std::string(""), GetInstanceIdForModule(path_));
}

TEST_F(GetInstanceIdForModuleTest, ReturnsGenericIdWhenNoPathMatches) {
  ASSERT_NO_FATAL_FAILURE(SetEnvVar("1 ;bar.exe,2"));
  EXPECT_EQ(std::string("1"), GetInstanceIdForModule(path_));
}

TEST_F(GetInstanceIdForModuleTest, ReturnsBaseNameId) {
  ASSERT_NO_FATAL_FAILURE(SetEnvVar("1; foo.exe , 2"));
  EXPECT_EQ(std::string("2"), GetInstanceIdForModule(path_));
}

TEST_F(GetInstanceIdForModuleTest, ReturnsExactPathId) {
  ASSERT_NO_FATAL_FAILURE(SetEnvVar("1;foo.exe,2;C:\\path\\foo.exe, 3 "));
  EXPECT_EQ(std::string("3"), GetInstanceIdForModule(path_));
}

TEST(GetInstanceIdForThisModule, WorksAsExpected) {
  FilePath self_path =
      ::testing::GetExeRelativePath(L"rpc_client_lib_unittests.exe");

  std::wstring env_var(self_path.value());
  env_var.append(L",1");

  scoped_ptr<base::Environment> env;
  env.reset(base::Environment::Create());
  ASSERT_TRUE(env->SetVar(::kSyzygyRpcInstanceIdEnvVar,
                          ::WideToUTF8(env_var)));

  EXPECT_EQ(std::string("1"), GetInstanceIdForThisModule());
}

}  // namespace client
}  // namespace trace
