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
#include "base/memory/scoped_ptr.h"
#include "base/strings/utf_string_conversions.h"
#include "gtest/gtest.h"
#include "syzygy/core/file_util.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/trace/client/rpc_session.h"

// http://blogs.msdn.com/oldnewthing/archive/2004/10/25/247180.aspx
extern "C" IMAGE_DOS_HEADER __ImageBase;

namespace trace {
namespace client {

namespace {

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

  base::FilePath path_;
  scoped_ptr<base::Environment> env_;
};

class IsRpcSessionMandatoryTest : public testing::Test {
 public:
  IsRpcSessionMandatoryTest() : path_(L"C:\\path\\foo.exe") { }

  virtual void SetUp() OVERRIDE {
    testing::Test::SetUp();
    env_.reset(base::Environment::Create());
  }

  void SetEnvVar(const base::StringPiece& string) {
    ASSERT_TRUE(env_->SetVar(::kSyzygyRpcSessionMandatoryEnvVar,
                             string.as_string()));
  }

  void UnsetEnvVar() {
    ASSERT_TRUE(env_->UnSetVar(::kSyzygyRpcSessionMandatoryEnvVar));
  }

  base::FilePath path_;
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

  base::FilePath module_path;
  EXPECT_TRUE(GetModulePath(module_base, &module_path));

  base::FilePath self_path =
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

TEST(GetInstanceIdForThisModuleTest, WorksAsExpected) {
  base::FilePath self_path =
      ::testing::GetExeRelativePath(L"rpc_client_lib_unittests.exe");

  std::wstring env_var(self_path.value());
  env_var.append(L",1");

  scoped_ptr<base::Environment> env;
  env.reset(base::Environment::Create());
  ASSERT_TRUE(env->SetVar(::kSyzygyRpcInstanceIdEnvVar,
                          base::WideToUTF8(env_var)));

  EXPECT_EQ(std::string("1"), GetInstanceIdForThisModule());
}

TEST_F(IsRpcSessionMandatoryTest, ReturnsFalseForNoEnvVar) {
  ASSERT_NO_FATAL_FAILURE(UnsetEnvVar());
  EXPECT_FALSE(IsRpcSessionMandatory(path_));
}

TEST_F(IsRpcSessionMandatoryTest, ReturnsFalseForEmptyEnvVar) {
  ASSERT_NO_FATAL_FAILURE(SetEnvVar(""));
  EXPECT_FALSE(IsRpcSessionMandatory(path_));
}

TEST_F(IsRpcSessionMandatoryTest, ReturnsFalseForNoMatch) {
  ASSERT_NO_FATAL_FAILURE(SetEnvVar("bar.exe,1;baz.exe,1"));
  EXPECT_FALSE(IsRpcSessionMandatory(path_));
}

TEST_F(IsRpcSessionMandatoryTest, ReturnsGlobalValueWhenNoPathMatches) {
  ASSERT_NO_FATAL_FAILURE(SetEnvVar("1 ; bar.exe,0"));
  EXPECT_TRUE(IsRpcSessionMandatory(path_));
}

TEST_F(IsRpcSessionMandatoryTest, ReturnsBaseNameValue) {
  ASSERT_NO_FATAL_FAILURE(SetEnvVar("0; foo.exe , 1"));
  EXPECT_TRUE(IsRpcSessionMandatory(path_));
}

TEST_F(IsRpcSessionMandatoryTest, ReturnsExactPathValue) {
  ASSERT_NO_FATAL_FAILURE(SetEnvVar("0;foo.exe,0;C:\\path\\foo.exe, 1 "));
  EXPECT_TRUE(IsRpcSessionMandatory(path_));
}

TEST_F(IsRpcSessionMandatoryTest, NonNumericIgnored) {
  ASSERT_NO_FATAL_FAILURE(SetEnvVar("foo.exe,baz;C:\\path\\foo.exe,bar"));
  EXPECT_FALSE(IsRpcSessionMandatory(path_));
}

TEST(IsRpcSessionMandatoryThisModuleTest, WorksAsExpected) {
  base::FilePath self_path =
      ::testing::GetExeRelativePath(L"rpc_client_lib_unittests.exe");

  std::wstring env_var(self_path.value());
  env_var.append(L",1");

  scoped_ptr<base::Environment> env;
  env.reset(base::Environment::Create());
  ASSERT_TRUE(env->SetVar(::kSyzygyRpcSessionMandatoryEnvVar,
                          base::WideToUTF8(env_var)));

  EXPECT_TRUE(IsRpcSessionMandatoryForThisModule());
}

TEST(InitializeRpcSessionTest, FailureSessionNotMandatory) {
  base::FilePath self_path =
      ::testing::GetExeRelativePath(L"rpc_client_lib_unittests.exe");

  scoped_ptr<base::Environment> env;
  env.reset(base::Environment::Create());

  std::wstring env_var(self_path.value());
  env_var.append(L",0");
  ASSERT_TRUE(env->SetVar(::kSyzygyRpcSessionMandatoryEnvVar,
                          base::WideToUTF8(env_var)));

  env_var = self_path.value();
  std::wstring id(L"dummy-id");
  env_var.append(L",");
  env_var.append(id);
  ASSERT_TRUE(env->SetVar(::kSyzygyRpcInstanceIdEnvVar,
                          base::WideToUTF8(env_var)));

  RpcSession session;
  TraceFileSegment segment;
  EXPECT_FALSE(InitializeRpcSession(&session, &segment));

  EXPECT_EQ(id, session.instance_id());
}

// TODO(chrisha): A more involved unittest where we launch a child process
//     whose RPC connection is mandatory, but unable to be initialized. Make
//     sure that it crashes as expected.

}  // namespace client
}  // namespace trace
