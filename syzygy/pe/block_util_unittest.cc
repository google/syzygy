// Copyright 2012 Google Inc.
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

#include "syzygy/pe/block_util.h"

#include "gtest/gtest.h"

namespace pe {

namespace {

typedef block_graph::BlockGraph BlockGraph;

class BlockUtilTest: public testing::Test {
 public:
  virtual void SetUp() OVERRIDE {
  }

  enum ReferenceSource {
    kSelfCode,
    kSelfData,
    kCodeBlock,
    kDataBlock,
  };

  enum ReferenceTarget {
    kTopOfBlock,
    kInCode,
    kDataLabel,
    kInData
  };

  struct ReferrerConfiguration {
    bool operator<(const ReferrerConfiguration& rhs) const {
      if (ref_source < rhs.ref_source)
        return true;
      if (ref_source > rhs.ref_source)
        return false;
      if (ref_target < rhs.ref_target)
        return true;
      if (ref_target > rhs.ref_target)
        return false;
      if (ref_type < rhs.ref_type)
        return true;
      if (ref_type > rhs.ref_type)
        return false;
      if (ref_size < rhs.ref_size)
        return true;
      if (ref_size > rhs.ref_size)
        return false;
      if (ref_is_direct < rhs.ref_is_direct)
        return true;
      return false;
    }

    ReferenceSource ref_source;
    ReferenceTarget ref_target;
    BlockGraph::ReferenceType ref_type;
    size_t ref_size;
    bool ref_is_direct;
  };

  void TestCodeBlockReferrersAreClConsistent(
      const ReferrerConfiguration& config,
      bool expect_valid) {
    BlockGraph::Block* dst = image_.AddBlock(BlockGraph::CODE_BLOCK, 40, "s");

    BlockGraph::Offset src_offset = 0;

    // Get the source block and source offset.
    BlockGraph::Block* src = NULL;
    switch (config.ref_source) {
      case kSelfCode:
        src = dst;
        src_offset = 4;
        break;

      case kSelfData:
        src = dst;
        src_offset = 24;
        break;

      case kCodeBlock:
        src = image_.AddBlock(BlockGraph::CODE_BLOCK, 40, "c");
        src_offset = 4;
        break;

      case kDataBlock:
        src = image_.AddBlock(BlockGraph::DATA_BLOCK, 40, "d");
        src_offset = 4;
        break;
    }

    // Set up a data label in the destination block, which splits it in half.
    ASSERT_TRUE(dst->SetLabel(20, BlockGraph::Label("data",
                                                    BlockGraph::DATA_LABEL)));

    // We need the data label to be self-referenced otherwise the referrers test
    // will always fail. This is from a different offset than what we would
    // ever use for src_offset (4 or 24).
    ASSERT_TRUE(dst->SetReference(16,
        BlockGraph::Reference(BlockGraph::ABSOLUTE_REF, 4, dst, 20, 20)));

    // These are reference offsets in dst as a function of ref_target.
    const BlockGraph::Offset kRefOffsets[] = { 0, 10, 20, 30 };

    // Create the offset and the reference.
    BlockGraph::Offset ref_offset = kRefOffsets[config.ref_target];
    BlockGraph::Offset ref_base = ref_offset;
    if (!config.ref_is_direct)
      ref_base += 4;

    // Create the reference.
    BlockGraph::Reference ref(config.ref_type, config.ref_size, dst, ref_offset,
                              ref_base);
    ASSERT_TRUE(ref.IsValid());
    ASSERT_EQ(config.ref_is_direct, ref.IsDirect());

    // Hook it up.
    ASSERT_TRUE(src->SetReference(src_offset, ref));

    // Test the validity.
    ASSERT_EQ(expect_valid, CodeBlockReferrersAreClConsistent(dst));
  }

 protected:
  BlockGraph image_;
};

}  // namespace

TEST_F(BlockUtilTest, CodeBlockAttributesAreClConsistentHasInlAsm) {
  BlockGraph::Block* code = image_.AddBlock(BlockGraph::CODE_BLOCK, 40, "c");
  code->set_attribute(BlockGraph::HAS_INLINE_ASSEMBLY);
  ASSERT_FALSE(CodeBlockAttributesAreClConsistent(code));
}

TEST_F(BlockUtilTest, CodeBlockAttributesAreClConsistentUnsupportedCompiler) {
  BlockGraph::Block* code = image_.AddBlock(BlockGraph::CODE_BLOCK, 40, "c");
  code->set_attribute(BlockGraph::BUILT_BY_UNSUPPORTED_COMPILER);
  ASSERT_FALSE(CodeBlockAttributesAreClConsistent(code));
}

TEST_F(BlockUtilTest, DirectReferencesFromCodeAreClConsistent) {
  BlockGraph::Block* code1 = image_.AddBlock(BlockGraph::CODE_BLOCK, 40, "c1");
  BlockGraph::Block* code2 = image_.AddBlock(BlockGraph::CODE_BLOCK, 40, "c2");
  BlockGraph::Block* data1 = image_.AddBlock(BlockGraph::DATA_BLOCK, 40, "d1");

  // Direct code reference.
  EXPECT_TRUE(code1->SetReference(
      0, BlockGraph::Reference(BlockGraph::RELATIVE_REF, 4, code2, 0, 0)));

  // Direct data reference.
  EXPECT_TRUE(code1->SetReference(
      4, BlockGraph::Reference(BlockGraph::RELATIVE_REF, 4, data1, 0, 0)));

  // Direct self-reference.
  EXPECT_TRUE(code1->SetReference(
      8, BlockGraph::Reference(BlockGraph::RELATIVE_REF, 4, code1, 4, 4)));

  EXPECT_TRUE(CodeBlockReferencesAreClConsistent(code1));
}

TEST_F(BlockUtilTest, IndirectReferencesFromCodeToCodeAreNotClConsistent) {
  BlockGraph::Block* code1 = image_.AddBlock(BlockGraph::CODE_BLOCK, 40, "c1");
  BlockGraph::Block* code2 = image_.AddBlock(BlockGraph::CODE_BLOCK, 40, "c2");

  // Indirect code reference.
  EXPECT_TRUE(code1->SetReference(
      0, BlockGraph::Reference(BlockGraph::RELATIVE_REF, 4, code2, 0, 4)));

  EXPECT_FALSE(CodeBlockReferencesAreClConsistent(code1));
}

TEST_F(BlockUtilTest, IndirectReferencesFromCodeToDataAreClConsistent) {
  BlockGraph::Block* code1 = image_.AddBlock(BlockGraph::CODE_BLOCK, 40, "c1");
  BlockGraph::Block* data1 = image_.AddBlock(BlockGraph::DATA_BLOCK, 40, "d1");

  // Indirect data reference.
  EXPECT_TRUE(code1->SetReference(
      0, BlockGraph::Reference(BlockGraph::RELATIVE_REF, 4, data1, 0, 4)));

  EXPECT_TRUE(CodeBlockReferencesAreClConsistent(code1));
}

TEST_F(BlockUtilTest, IndirectSelfReferencesFromCodeAreNotClConsistent) {
  BlockGraph::Block* code1 = image_.AddBlock(BlockGraph::CODE_BLOCK, 40, "c1");

  // Indirect self reference.
  EXPECT_TRUE(code1->SetReference(
      0, BlockGraph::Reference(BlockGraph::RELATIVE_REF, 4, code1, 4, 8)));

  EXPECT_FALSE(CodeBlockReferencesAreClConsistent(code1));
}

TEST_F(BlockUtilTest, CodeBlockReferrersAreClConsistent) {
  // These are all the possible input values to be explored.
  const ReferenceSource kRefSource[] = {
      kSelfCode, kSelfData, kCodeBlock, kDataBlock };
  const ReferenceTarget kRefTarget[] = {
      kTopOfBlock, kInCode, kDataLabel, kInData };
  const BlockGraph::ReferenceType kRefType[] = {
      BlockGraph::PC_RELATIVE_REF, BlockGraph::ABSOLUTE_REF,
      BlockGraph::RELATIVE_REF, BlockGraph::FILE_OFFSET_REF };
  const size_t kRefSize[] = { 1, 4 };
  const bool kRefIsDirect[] = { false, true };

  static size_t kNumberOfPermutations =
      arraysize(kRefSource) * arraysize(kRefTarget) * arraysize(kRefType) *
      arraysize(kRefSize) * arraysize(kRefIsDirect);

  // This is the short list of permutations that we expect to be valid. All
  // others should be false.
  const ReferrerConfiguration kValidConfigs[] = {
      // Self-references from code to code.
      { kSelfCode, kTopOfBlock, BlockGraph::PC_RELATIVE_REF, 1, true },
      { kSelfCode, kTopOfBlock, BlockGraph::PC_RELATIVE_REF, 4, true },
      { kSelfCode, kTopOfBlock, BlockGraph::ABSOLUTE_REF, 4, true },
      { kSelfCode, kInCode, BlockGraph::PC_RELATIVE_REF, 1, true },
      { kSelfCode, kInCode, BlockGraph::PC_RELATIVE_REF, 4, true },
      { kSelfCode, kInCode, BlockGraph::ABSOLUTE_REF, 4, true },

      // Self-references from code to data.
      { kSelfCode, kDataLabel, BlockGraph::ABSOLUTE_REF, 4, true },

      // Self-references from data to code.
      { kSelfData, kTopOfBlock, BlockGraph::ABSOLUTE_REF, 4, true },
      { kSelfData, kInCode, BlockGraph::ABSOLUTE_REF, 4, true },

      // External references from code to code.
      { kCodeBlock, kTopOfBlock, BlockGraph::PC_RELATIVE_REF, 4, true },
      { kCodeBlock, kTopOfBlock, BlockGraph::ABSOLUTE_REF, 4, true },

      // External references from data to code.
      { kDataBlock, kTopOfBlock, BlockGraph::ABSOLUTE_REF, 4, true },
      { kDataBlock, kTopOfBlock, BlockGraph::RELATIVE_REF, 4, true },
  };
  std::set<ReferrerConfiguration> valid_configs;
  for (size_t i = 0; i < arraysize(kValidConfigs); ++i) {
    ASSERT_TRUE(valid_configs.insert(kValidConfigs[i]).second);
  }

  // Walk through all possible permutations.
  for (size_t i = 0; i < kNumberOfPermutations; ++i) {
    size_t j = i;

    ReferenceSource ref_source = kRefSource[j % arraysize(kRefSource)];
    j /= arraysize(kRefSource);

    ReferenceTarget ref_target = kRefTarget[j % arraysize(kRefTarget)];
    j /= arraysize(kRefTarget);

    BlockGraph::ReferenceType ref_type = kRefType[j % arraysize(kRefType)];
    j /= arraysize(kRefType);

    size_t ref_size = kRefSize[j % arraysize(kRefSize)];
    j /= arraysize(kRefSize);

    bool ref_is_direct = kRefIsDirect[j % arraysize(kRefIsDirect)];

    // If the reference type and size is not valid, skip this test.
    if (!BlockGraph::Reference::IsValidTypeSize(ref_type, ref_size))
      continue;

    ReferrerConfiguration config = { ref_source, ref_target, ref_type,
        ref_size, ref_is_direct };

    bool expect_valid = valid_configs.count(config);
    ASSERT_NO_FATAL_FAILURE(TestCodeBlockReferrersAreClConsistent(
        config, expect_valid));
  }
}

TEST_F(BlockUtilTest, CodeBlockReferrersAreClConsistentUnreferencedData) {
  BlockGraph::Block* code = image_.AddBlock(BlockGraph::CODE_BLOCK, 40, "c");
  ASSERT_TRUE(code->SetLabel(20, BlockGraph::Label("data",
                                                   BlockGraph::DATA_LABEL)));
  ASSERT_FALSE(CodeBlockReferrersAreClConsistent(code));
}

TEST_F(BlockUtilTest, CodeBlockReferrersAreClConsistentCodeAfterData) {
  // We make a code block with a data label. We make sure the data label
  // is referenced. We expect thi to fail because the data comes before the
  // code, which is not consistent with CL.EXE output.
  BlockGraph::Block* code = image_.AddBlock(BlockGraph::CODE_BLOCK, 40, "c");
  ASSERT_TRUE(code->SetLabel(0, BlockGraph::Label("data",
                                                  BlockGraph::DATA_LABEL)));
  ASSERT_TRUE(code->SetLabel(20, BlockGraph::Label("code",
                                                   BlockGraph::CODE_LABEL)));
  ASSERT_TRUE(code->SetReference(20, BlockGraph::Reference(
      BlockGraph::ABSOLUTE_REF, 4, code, 0, 0)));
  ASSERT_FALSE(CodeBlockReferrersAreClConsistent(code));
}

TEST_F(BlockUtilTest, CodeBlockIsClConsistent) {
  // Each of the sub-functions has been tested in detail, so we simply do an
  // end-to-end test for coverage.
  BlockGraph::Block* code = image_.AddBlock(BlockGraph::CODE_BLOCK, 40, "c");
  ASSERT_TRUE(CodeBlockIsClConsistent(code));

  ASSERT_TRUE(code->SetLabel(20, BlockGraph::Label("data",
                                                   BlockGraph::DATA_LABEL)));
  ASSERT_FALSE(CodeBlockIsClConsistent(code));

  ASSERT_TRUE(code->SetReference(8, BlockGraph::Reference(
      BlockGraph::PC_RELATIVE_REF, 1, code, 0, 0)));
  ASSERT_FALSE(CodeBlockIsClConsistent(code));

  ASSERT_TRUE(code->SetReference(4, BlockGraph::Reference(
      BlockGraph::ABSOLUTE_REF, 4, code, 20, 20)));
  ASSERT_TRUE(CodeBlockIsClConsistent(code));
}

TEST_F(BlockUtilTest, CodeBlockIsBasicBlockDecomposableSimpleBlock) {
  BlockGraph::Block* code = image_.AddBlock(BlockGraph::CODE_BLOCK, 40, "c");
  ASSERT_TRUE(CodeBlockIsClConsistent(code));
}

TEST_F(BlockUtilTest, CodeBlockIsBasicBlockDecomposableBuiltBySyzygy) {
  BlockGraph::Block* code = image_.AddBlock(BlockGraph::CODE_BLOCK, 40, "c");
  code->set_attribute(BlockGraph::BUILT_BY_SYZYGY);
  ASSERT_TRUE(CodeBlockIsBasicBlockDecomposable(code));

  // Even if this block has unreferenced data, it should be fine.
  ASSERT_TRUE(code->SetLabel(20, BlockGraph::Label("data",
                                                   BlockGraph::DATA_LABEL)));
  ASSERT_TRUE(CodeBlockIsBasicBlockDecomposable(code));
}

}  // namespace pe
