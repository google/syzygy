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

#include "syzygy/pe/pe_coff_relinker.h"

#include "base/file_util.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/unittest_util.h"
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

class TestPECoffRelinker : public PECoffRelinker {
 public:
  explicit TestPECoffRelinker(const TransformPolicyInterface* transform_policy)
      : PECoffRelinker(transform_policy) {
  }

  using PECoffRelinker::transforms_;
  using PECoffRelinker::orderers_;

  virtual ImageFormat image_format() const OVERRIDE {
    return BlockGraph::PE_IMAGE;
  }

  virtual bool Init() OVERRIDE { return true; }
  virtual bool Relink() OVERRIDE { return true; }
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
  MOCK_METHOD2(OrderBlockGraph, bool(OrderedBlockGraph*, BlockGraph::Block*));
};

}  // namespace

TEST(PECoffRelinkerTest, Properties) {
  testing::DummyTransformPolicy policy;
  TestPECoffRelinker relinker(&policy);
  base::FilePath dummy_path(L"foo");

  EXPECT_EQ(base::FilePath(), relinker.input_path());
  relinker.set_input_path(dummy_path);
  EXPECT_EQ(dummy_path, relinker.input_path());

  EXPECT_EQ(base::FilePath(), relinker.output_path());
  relinker.set_output_path(dummy_path);
  EXPECT_EQ(dummy_path, relinker.output_path());

  EXPECT_FALSE(relinker.allow_overwrite());
  relinker.set_allow_overwrite(true);
  EXPECT_TRUE(relinker.allow_overwrite());
  relinker.set_allow_overwrite(false);
  EXPECT_FALSE(relinker.allow_overwrite());
}

TEST(PECoffRelinkerTest, AppendTransforms) {
  testing::DummyTransformPolicy policy;
  TestPECoffRelinker relinker(&policy);

  MockTransform transform1, transform2;
  std::vector<BlockGraphTransformInterface*> transforms;
  transforms.push_back(&transform2);

  relinker.AppendTransform(&transform1);
  relinker.AppendTransforms(transforms);

  std::vector<BlockGraphTransformInterface*> expected;
  expected.push_back(&transform1);
  expected.push_back(&transform2);

  EXPECT_EQ(expected, relinker.transforms_);
}

TEST(PECoffRelinkerTest, AppendOrderers) {
  testing::DummyTransformPolicy policy;
  TestPECoffRelinker relinker(&policy);

  MockOrderer orderer1, orderer2;
  std::vector<BlockGraphOrdererInterface*> orderers;
  orderers.push_back(&orderer2);

  relinker.AppendOrderer(&orderer1);
  relinker.AppendOrderers(orderers);

  std::vector<BlockGraphOrdererInterface*> expected;
  expected.push_back(&orderer1);
  expected.push_back(&orderer2);

  EXPECT_EQ(expected, relinker.orderers_);
}

}  // namespace pe
