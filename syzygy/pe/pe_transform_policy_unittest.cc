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

#include "syzygy/pe/pe_transform_policy.h"

#include "gtest/gtest.h"
#include "syzygy/block_graph/block_graph.h"

namespace pe {

namespace {

using block_graph::BlockGraph;

class TestPETransformPolicy : public PETransformPolicy {
 public:
  typedef PETransformPolicy::BlockResultCache BlockResultCache;

  using PETransformPolicy::block_result_cache_;
  using PETransformPolicy::allow_inline_assembly_;
};

class PETransformPolicyTest : public testing::Test {
 public:
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
    BlockGraph bg;
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
    ASSERT_TRUE(dst->SetLabel(20, BlockGraph::Label(
        "data", BlockGraph::DATA_LABEL)));

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
    TestPETransformPolicy policy;
    ASSERT_EQ(expect_valid, policy.CodeBlockReferrersAreClConsistent(dst));
  }

  void TestAttributes(BlockGraph::BlockAttributes attributes,
                      bool allow_inline_assembly,
                      bool result) {
    PETransformPolicy policy;
    BlockGraph bg;
    BlockGraph::Block* b = bg.AddBlock(BlockGraph::CODE_BLOCK, 1, "code");
    ASSERT_NE(reinterpret_cast<BlockGraph::Block*>(NULL), b);
    b->set_attributes(attributes);
    ASSERT_EQ(result, policy.CodeBlockAttributesAreBasicBlockSafe(
                          b, allow_inline_assembly));
  }

  BlockGraph image_;
};

}  // namespace

TEST_F(PETransformPolicyTest, AccessorsAndMutators) {
  TestPETransformPolicy policy;
  EXPECT_FALSE(policy.allow_inline_assembly());
  policy.set_allow_inline_assembly(true);
  EXPECT_TRUE(policy.allow_inline_assembly());
  policy.set_allow_inline_assembly(false);
  EXPECT_FALSE(policy.allow_inline_assembly());
}

TEST_F(PETransformPolicyTest,
       CodeBlockAttributesAreBasicBlockSafeGapBlock) {
  ASSERT_NO_FATAL_FAILURE(TestAttributes(BlockGraph::GAP_BLOCK, false, false));
  ASSERT_NO_FATAL_FAILURE(TestAttributes(BlockGraph::GAP_BLOCK, true, false));
}

TEST_F(PETransformPolicyTest,
       CodeBlockAttributesAreBasicBlockSafePaddingBlock) {
  ASSERT_NO_FATAL_FAILURE(TestAttributes(
      BlockGraph::PADDING_BLOCK, false, false));
  ASSERT_NO_FATAL_FAILURE(TestAttributes(
      BlockGraph::PADDING_BLOCK, true, false));
}

TEST_F(PETransformPolicyTest,
       CodeBlockAttributesAreBasicBlockSafeHasInlineAssembly) {
  ASSERT_NO_FATAL_FAILURE(TestAttributes(
      BlockGraph::HAS_INLINE_ASSEMBLY, false, false));
  ASSERT_NO_FATAL_FAILURE(TestAttributes(
      BlockGraph::HAS_INLINE_ASSEMBLY, true, true));
}

TEST_F(PETransformPolicyTest,
       CodeBlockAttributesAreBasicBlockSafeUnsupportedCompiler) {
  ASSERT_NO_FATAL_FAILURE(TestAttributes(
      BlockGraph::BUILT_BY_UNSUPPORTED_COMPILER, false, false));
  ASSERT_NO_FATAL_FAILURE(TestAttributes(
      BlockGraph::BUILT_BY_UNSUPPORTED_COMPILER, true, false));
}

TEST_F(PETransformPolicyTest,
       CodeBlockAttributesAreBasicBlockSafeErroredDisassembly) {
  ASSERT_NO_FATAL_FAILURE(TestAttributes(
      BlockGraph::ERRORED_DISASSEMBLY, false, false));
  ASSERT_NO_FATAL_FAILURE(TestAttributes(
      BlockGraph::ERRORED_DISASSEMBLY, true, false));
}

TEST_F(PETransformPolicyTest,
       CodeBlockAttributesAreBasicBlockSafeExceptionHandling) {
  ASSERT_NO_FATAL_FAILURE(TestAttributes(
      BlockGraph::HAS_EXCEPTION_HANDLING, false, false));
  ASSERT_NO_FATAL_FAILURE(TestAttributes(
      BlockGraph::HAS_EXCEPTION_HANDLING, true, false));
}

TEST_F(PETransformPolicyTest,
       CodeBlockAttributesAreBasicBlockSafeDisassembledPastEnd) {
  ASSERT_NO_FATAL_FAILURE(TestAttributes(
      BlockGraph::DISASSEMBLED_PAST_END, false, false));
  ASSERT_NO_FATAL_FAILURE(TestAttributes(
      BlockGraph::DISASSEMBLED_PAST_END, true, false));
}

TEST_F(PETransformPolicyTest,
       CodeBlockAttributesAreBasicBlockSafeBuiltBySyzygy) {
  ASSERT_NO_FATAL_FAILURE(TestAttributes(
      BlockGraph::BUILT_BY_UNSUPPORTED_COMPILER | BlockGraph::BUILT_BY_SYZYGY,
      false,
      true));
  ASSERT_NO_FATAL_FAILURE(TestAttributes(
      BlockGraph::BUILT_BY_UNSUPPORTED_COMPILER | BlockGraph::BUILT_BY_SYZYGY,
      true,
      true));
}

TEST_F(PETransformPolicyTest, NoLabelsHasInvalidLayout) {
  BlockGraph::Block* b = image_.AddBlock(BlockGraph::CODE_BLOCK, 1, "code");
  TestPETransformPolicy policy;
  EXPECT_FALSE(policy.CodeBlockLayoutIsClConsistent(b));
}

TEST_F(PETransformPolicyTest, CodeLabelPastEndHasInvalidLayout) {
  BlockGraph::Block* b = image_.AddBlock(BlockGraph::CODE_BLOCK, 2, "code");
  b->SetLabel(0, "code", BlockGraph::CODE_LABEL);
  b->SetLabel(2, "code", BlockGraph::CODE_LABEL);
  TestPETransformPolicy policy;
  EXPECT_FALSE(policy.CodeBlockLayoutIsClConsistent(b));
}

TEST_F(PETransformPolicyTest, DataLabelPastEndHasInvalidLayout) {
  BlockGraph::Block* b = image_.AddBlock(BlockGraph::CODE_BLOCK, 2, "code");
  b->SetLabel(0, "code", BlockGraph::CODE_LABEL);
  b->SetLabel(2, "data", BlockGraph::DATA_LABEL);
  TestPETransformPolicy policy;
  EXPECT_FALSE(policy.CodeBlockLayoutIsClConsistent(b));
}

TEST_F(PETransformPolicyTest, DebugEndInBlockAfterDataHasInvalidLayout) {
  BlockGraph::Block* b = image_.AddBlock(BlockGraph::CODE_BLOCK, 3, "code");
  b->SetLabel(0, "code", BlockGraph::CODE_LABEL);
  b->SetLabel(1, "data", BlockGraph::DATA_LABEL);
  b->SetLabel(2, "debug-end", BlockGraph::DEBUG_END_LABEL);
  TestPETransformPolicy policy;
  EXPECT_FALSE(policy.CodeBlockLayoutIsClConsistent(b));
}

TEST_F(PETransformPolicyTest, CodeAfterDataHasInvalidLayout) {
  BlockGraph::Block* b = image_.AddBlock(BlockGraph::CODE_BLOCK, 2, "code");
  b->SetLabel(0, "data", BlockGraph::DATA_LABEL);
  b->SetLabel(1, "code", BlockGraph::CODE_LABEL);
  TestPETransformPolicy policy;
  EXPECT_FALSE(policy.CodeBlockLayoutIsClConsistent(b));
}

TEST_F(PETransformPolicyTest, DataSurroundedByCodeHasInvalidLayout) {
  BlockGraph::Block* b = image_.AddBlock(BlockGraph::CODE_BLOCK, 3, "code");
  b->SetLabel(0, "data", BlockGraph::DATA_LABEL);
  b->SetLabel(1, "code", BlockGraph::CODE_LABEL);
  b->SetLabel(2, "data", BlockGraph::DATA_LABEL);
  TestPETransformPolicy policy;
  EXPECT_FALSE(policy.CodeBlockLayoutIsClConsistent(b));
}

TEST_F(PETransformPolicyTest, CodeOnlyHasValidLayout) {
  BlockGraph::Block* b = image_.AddBlock(BlockGraph::CODE_BLOCK, 1, "code");
  b->SetLabel(0, "code", BlockGraph::CODE_LABEL);
  TestPETransformPolicy policy;
  EXPECT_TRUE(policy.CodeBlockLayoutIsClConsistent(b));

  // This should still be true even with a debug-end label beyond the end.
  b->SetLabel(1, "debug-end", BlockGraph::DEBUG_END_LABEL);
  EXPECT_TRUE(policy.CodeBlockLayoutIsClConsistent(b));
}

TEST_F(PETransformPolicyTest, CodeFollowedByDataHasValidLayout) {
  BlockGraph::Block* b = image_.AddBlock(BlockGraph::CODE_BLOCK, 2, "code");
  b->SetLabel(0, "code", BlockGraph::CODE_LABEL);
  b->SetLabel(1, "data", BlockGraph::DATA_LABEL);

  TestPETransformPolicy policy;
  EXPECT_TRUE(policy.CodeBlockLayoutIsClConsistent(b));

  // This should still be true even with a debug-end label beyond the end.
  b->SetLabel(2, "debug-end", BlockGraph::DEBUG_END_LABEL);
  EXPECT_TRUE(policy.CodeBlockLayoutIsClConsistent(b));
}

TEST_F(PETransformPolicyTest, DirectReferencesFromCodeAreClConsistent) {
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

  TestPETransformPolicy policy;
  EXPECT_TRUE(policy.CodeBlockReferencesAreClConsistent(code1));
}

TEST_F(PETransformPolicyTest,
       IndirectReferencesFromCodeToCodeAreNotClConsistent) {
  BlockGraph::Block* code1 = image_.AddBlock(BlockGraph::CODE_BLOCK, 40, "c1");
  BlockGraph::Block* code2 = image_.AddBlock(BlockGraph::CODE_BLOCK, 40, "c2");

  // Indirect code reference.
  EXPECT_TRUE(code1->SetReference(
      0, BlockGraph::Reference(BlockGraph::RELATIVE_REF, 4, code2, 0, 4)));

  TestPETransformPolicy policy;
  EXPECT_FALSE(policy.CodeBlockReferencesAreClConsistent(code1));
}

TEST_F(PETransformPolicyTest, IndirectReferencesFromCodeToDataAreClConsistent) {
  BlockGraph::Block* code1 = image_.AddBlock(BlockGraph::CODE_BLOCK, 40, "c1");
  BlockGraph::Block* data1 = image_.AddBlock(BlockGraph::DATA_BLOCK, 40, "d1");

  // Indirect data reference.
  EXPECT_TRUE(code1->SetReference(
      0, BlockGraph::Reference(BlockGraph::RELATIVE_REF, 4, data1, 0, 4)));

  TestPETransformPolicy policy;
  EXPECT_TRUE(policy.CodeBlockReferencesAreClConsistent(code1));
}

TEST_F(PETransformPolicyTest,
       IndirectSelfReferencesFromCodeAreNotClConsistent) {
  BlockGraph::Block* code1 = image_.AddBlock(BlockGraph::CODE_BLOCK, 40, "c1");

  // Indirect self reference.
  EXPECT_TRUE(code1->SetReference(
      0, BlockGraph::Reference(BlockGraph::RELATIVE_REF, 4, code1, 4, 8)));

  TestPETransformPolicy policy;
  EXPECT_FALSE(policy.CodeBlockReferencesAreClConsistent(code1));
}

TEST_F(PETransformPolicyTest, CodeBlockReferrersAreClConsistent) {
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

      // Self-references from data to data.
      { kSelfData, kDataLabel, BlockGraph::ABSOLUTE_REF, 4, true },
      { kSelfData, kInData, BlockGraph::ABSOLUTE_REF, 4, true },

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

TEST_F(PETransformPolicyTest,
       CodeBlockReferrersAreClConsistentUnreferencedLabels) {
  BlockGraph::Block* code = image_.AddBlock(BlockGraph::CODE_BLOCK, 40, "c");
  const BlockGraph::Offset kDataLabelOffset = 0x10;
  code->SetLabel(kDataLabelOffset,
                 BlockGraph::Label("data", BlockGraph::DATA_LABEL));

  // We have a single unreferenced data label.
  TestPETransformPolicy policy;
  ASSERT_FALSE(policy.CodeBlockReferrersAreClConsistent(code));

  BlockGraph::Reference ref(BlockGraph::ABSOLUTE_REF,
                            sizeof(core::AbsoluteAddress),
                            code,
                            kDataLabelOffset,
                            kDataLabelOffset);
  // Add a reference from code to the data label.
  code->SetReference(kDataLabelOffset - 0x8, ref);

  // We're now consistent.
  ASSERT_TRUE(policy.CodeBlockReferrersAreClConsistent(code));

  // Remove the reference and move it into code.
  code->RemoveReference(kDataLabelOffset - 0x8);
  code->SetReference(kDataLabelOffset + 0x8, ref);

  // Consistent again.
  ASSERT_TRUE(policy.CodeBlockReferrersAreClConsistent(code));
}

TEST_F(PETransformPolicyTest,
       CodeBlockReferrersAreClConsistentUnreferencedData) {
  BlockGraph::Block* code = image_.AddBlock(BlockGraph::CODE_BLOCK, 40, "c");
  ASSERT_TRUE(code->SetLabel(20, BlockGraph::Label(
      "data", BlockGraph::DATA_LABEL)));
  TestPETransformPolicy policy;
  ASSERT_FALSE(policy.CodeBlockReferrersAreClConsistent(code));
}

TEST_F(PETransformPolicyTest,
       CodeBlockIsSafeToBasicBlockDecomposeableSimpleBlock) {
  BlockGraph::Block* code = image_.AddBlock(BlockGraph::CODE_BLOCK, 1, "code");
  code->SetLabel(0, "code", BlockGraph::CODE_LABEL);
  TestPETransformPolicy policy;
  ASSERT_TRUE(policy.CodeBlockIsSafeToBasicBlockDecompose(code));
}

TEST_F(PETransformPolicyTest,
       CodeBlockIsSafeToBasicBlockDecomposeBuiltBySyzygy) {
  BlockGraph::Block* code = image_.AddBlock(BlockGraph::CODE_BLOCK, 40, "c");
  code->set_attribute(BlockGraph::BUILT_BY_SYZYGY);
  TestPETransformPolicy policy;
  ASSERT_TRUE(policy.CodeBlockIsSafeToBasicBlockDecompose(code));

  // Even if this block has unreferenced data, it should be fine.
  ASSERT_TRUE(code->SetLabel(20, BlockGraph::Label(
      "data", BlockGraph::DATA_LABEL)));
  ASSERT_TRUE(policy.CodeBlockIsSafeToBasicBlockDecompose(code));
}

TEST_F(PETransformPolicyTest, DataBlockIsNotSafeToBasicBlockDecompose) {
  TestPETransformPolicy policy;

  BlockGraph::Block* data = image_.AddBlock(BlockGraph::DATA_BLOCK, 1, "d");
  ASSERT_FALSE(policy.BlockIsSafeToBasicBlockDecompose(data));
}

TEST_F(PETransformPolicyTest, CodeBlockIsSafeToBasicBlockDecomposeCache) {
  TestPETransformPolicy policy;
  EXPECT_EQ(0u, policy.block_result_cache_->size());

  BlockGraph::Block* code = image_.AddBlock(BlockGraph::CODE_BLOCK, 2, "c");
  code->SetLabel(0, "code", BlockGraph::CODE_LABEL);
  ASSERT_TRUE(policy.BlockIsSafeToBasicBlockDecompose(code));
  EXPECT_EQ(1u, policy.block_result_cache_->size());

  TestPETransformPolicy::BlockResultCache::const_iterator it =
      policy.block_result_cache_->find(code->id());
  ASSERT_NE(policy.block_result_cache_->end(), it);
  EXPECT_EQ(code->id(), it->first);
  EXPECT_TRUE(it->second);

  // Add an unreferenced data label. This should make the analysis fail.
  // However, it should be looked up in the cache and return true.
  ASSERT_TRUE(code->SetLabel(1, BlockGraph::Label(
      "data", BlockGraph::DATA_LABEL)));
  ASSERT_FALSE(policy.CodeBlockIsSafeToBasicBlockDecompose(code));
  ASSERT_TRUE(policy.BlockIsSafeToBasicBlockDecompose(code));
  EXPECT_EQ(1u, policy.block_result_cache_->size());
}

TEST_F(PETransformPolicyTest, ReferenceIsSafeToRedirect) {
  TestPETransformPolicy policy;
  BlockGraph bg;
  BlockGraph::Block* b = bg.AddBlock(BlockGraph::CODE_BLOCK, 1, "");
  BlockGraph::Reference ref(BlockGraph::ABSOLUTE_REF, 4, b, 0, 0);
  EXPECT_TRUE(policy.ReferenceIsSafeToRedirect(b, ref));
}

}  // namespace pe
