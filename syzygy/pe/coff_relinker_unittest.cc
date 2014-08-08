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

#include "syzygy/pe/coff_relinker.h"

#include "base/file_util.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/common/defs.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/unittest_util.h"

namespace pe {
namespace {

using block_graph::BlockGraph;
using block_graph::BlockGraphOrdererInterface;
using block_graph::BlockGraphTransformInterface;
using block_graph::OrderedBlockGraph;
using block_graph::TransformPolicyInterface;
using testing::_;
using testing::Return;
using testing::StrictMock;

class TestCoffRelinker : public CoffRelinker {
 public:
  explicit TestCoffRelinker(const CoffTransformPolicy* transform_policy)
      : CoffRelinker(transform_policy) {
  }

  using CoffRelinker::transforms_;
  using CoffRelinker::orderers_;
};

class CoffRelinkerTest : public testing::PELibUnitTest {
 public:
  virtual void SetUp() OVERRIDE {
    testing::PELibUnitTest::SetUp();

    test_dll_obj_path_ =
        testing::GetExeTestDataRelativePath(testing::kTestDllCoffObjName);
    ASSERT_NO_FATAL_FAILURE(CreateTemporaryDir(&temp_dir_path_));
    new_test_dll_obj_path_ = temp_dir_path_.Append(L"test_dll.obj");
    new_test_dll_path_ = temp_dir_path_.Append(testing::kTestDllName);
  }

  CoffTransformPolicy policy_;
  base::FilePath test_dll_obj_path_;
  base::FilePath new_test_dll_obj_path_;
  base::FilePath new_test_dll_path_;
  base::FilePath temp_dir_path_;
};

class MockTransform : public BlockGraphTransformInterface {
 public:
  const char* name() const { return "MockTransform"; }
  MOCK_METHOD3(TransformBlockGraph,
               bool(const TransformPolicyInterface*,
                    BlockGraph*,
                    BlockGraph::Block*));
};

class MockOrderer : public BlockGraphOrdererInterface {
 public:
  const char* name() const { return "MockOrderer"; }
  MOCK_METHOD2(OrderBlockGraph,
               bool(OrderedBlockGraph*,
                    BlockGraph::Block*));
};

}  // namespace

TEST_F(CoffRelinkerTest, InitFailsOnUnspecifiedInput) {
  TestCoffRelinker relinker(&policy_);

  relinker.set_output_path(new_test_dll_obj_path_);
  EXPECT_FALSE(relinker.Init());
}

TEST_F(CoffRelinkerTest, InitFailsOnUnspecifiedOutput) {
  TestCoffRelinker relinker(&policy_);

  relinker.set_input_path(test_dll_obj_path_);
  EXPECT_FALSE(relinker.Init());
}

TEST_F(CoffRelinkerTest, InitFailsOnNonexistentInput) {
  TestCoffRelinker relinker(&policy_);

  relinker.set_input_path(temp_dir_path_.Append(L"nonexistent.dll"));
  relinker.set_output_path(new_test_dll_obj_path_);
  EXPECT_FALSE(relinker.Init());
}

TEST_F(CoffRelinkerTest, InitFailsOnDisallowedOverwrite) {
  TestCoffRelinker relinker(&policy_);

  // Copy the image in case the test actually does overwrite the input; this
  // way we don't accidentally turf our test data.
  base::CopyFile(test_dll_obj_path_, new_test_dll_obj_path_);

  relinker.set_input_path(new_test_dll_obj_path_);
  relinker.set_output_path(new_test_dll_obj_path_);

  relinker.set_allow_overwrite(false);
  EXPECT_FALSE(relinker.Init());
}

TEST_F(CoffRelinkerTest, InitSucceeds) {
  TestCoffRelinker relinker(&policy_);

  relinker.set_input_path(test_dll_obj_path_);
  relinker.set_output_path(new_test_dll_obj_path_);

  EXPECT_TRUE(relinker.Init());
}

TEST_F(CoffRelinkerTest, IntermediateAccessors) {
  TestCoffRelinker relinker(&policy_);

  relinker.set_input_path(test_dll_obj_path_);
  relinker.set_output_path(new_test_dll_obj_path_);

  EXPECT_TRUE(relinker.Init());

  EXPECT_EQ(test_dll_obj_path_, relinker.input_image_file().path());
  EXPECT_TRUE(relinker.headers_block() != NULL);
}

TEST_F(CoffRelinkerTest, FailsWhenTransformFails) {
  TestCoffRelinker relinker(&policy_);
  StrictMock<MockTransform> transform;

  EXPECT_CALL(transform, TransformBlockGraph(_, _, _)).WillOnce(Return(false));

  relinker.AppendTransform(&transform);
  relinker.set_input_path(test_dll_obj_path_);
  relinker.set_output_path(new_test_dll_obj_path_);
  EXPECT_TRUE(relinker.Init());
  EXPECT_FALSE(relinker.Relink());
}

TEST_F(CoffRelinkerTest, FailsWhenOrdererFails) {
  TestCoffRelinker relinker(&policy_);
  StrictMock<MockOrderer> orderer;

  EXPECT_CALL(orderer, OrderBlockGraph(_, _)).WillOnce(Return(false));

  relinker.AppendOrderer(&orderer);
  relinker.set_input_path(test_dll_obj_path_);
  relinker.set_output_path(new_test_dll_obj_path_);
  EXPECT_TRUE(relinker.Init());
  EXPECT_FALSE(relinker.Relink());
}

TEST_F(CoffRelinkerTest, Success) {
  TestCoffRelinker relinker(&policy_);
  StrictMock<MockTransform> transform;
  StrictMock<MockOrderer> orderer;

  EXPECT_CALL(transform, TransformBlockGraph(_, _, _)).WillOnce(Return(true));
  EXPECT_CALL(orderer, OrderBlockGraph(_, _)).WillOnce(Return(true));

  relinker.AppendTransform(&transform);
  relinker.AppendOrderer(&orderer);

  relinker.set_input_path(test_dll_obj_path_);
  relinker.set_output_path(new_test_dll_obj_path_);

  EXPECT_TRUE(relinker.Init());
  EXPECT_TRUE(relinker.Relink());
}

TEST_F(CoffRelinkerTest, IdentityRelink) {
  TestCoffRelinker relinker(&policy_);

  relinker.set_input_path(test_dll_obj_path_);
  relinker.set_output_path(new_test_dll_obj_path_);

  EXPECT_TRUE(relinker.Init());
  EXPECT_TRUE(relinker.Relink());

  EXPECT_TRUE(base::PathExists(relinker.output_path()));

  // We assume the contents of the file are what they should be;
  // CoffImageLayoutBuilder has more unit tests that check the specifics of
  // writing COFF files.
}

}  // namespace pe
