// Copyright 2014 Google Inc. All Rights Reserved.
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
//
// Allocation filter transform instrumentation unit-tests.

#include "syzygy/instrument/transforms/allocation_filter_transform.h"

#include "base/values.h"
#include "base/json/json_writer.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/basic_block_decomposer.h"
#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/instrument/transforms/unittest_util.h"

#include "mnemonics.h"  // NOLINT

namespace instrument {
namespace transforms {
namespace {

using base::DictionaryValue;
using base::ListValue;
using base::Value;

using block_graph::BasicBlock;
using block_graph::BasicBlockDecomposer;
using block_graph::BasicBlockSubGraph;
using block_graph::BasicCodeBlock;
using block_graph::BlockGraph;
using block_graph::Instruction;

typedef AllocationFilterTransform::Offset Offset;
typedef AllocationFilterTransform::OffsetSet OffsetSet;
typedef AllocationFilterTransform::FunctionNameOffsetMap
    FunctionNameOffsetMap;

static wchar_t kConfigBadPathDoesNotExist[] =
    L"syzygy/instrument/test_data/"
    L"allocation-filter-bad-path-does-not-exist.json";
static wchar_t kConfigBadInvalidkey[] =
    L"syzygy/instrument/test_data/allocation-filter-bad-invalid-key.json";
static wchar_t kConfigBadInvalidOffsetList[] =
    L"syzygy/instrument/test_data/"
    L"allocation-filter-bad-invalid-offset-list.json";
static wchar_t kConfigBadList[] =
    L"syzygy/instrument/test_data/allocation-filter-bad-list.json";
static wchar_t kConfigBadNegativeOffset[] =
    L"syzygy/instrument/test_data/allocation-filter-bad-negative-offset.json";
static wchar_t kConfigBadString[] =
    L"syzygy/instrument/test_data/allocation-filter-bad-string.json";
static wchar_t kConfigGoodEmpty[] =
    L"syzygy/instrument/test_data/allocation-filter-good-empty.json";
static wchar_t kConfigGoodFull[] =
    L"syzygy/instrument/test_data/allocation-filter-good-full.json";
static wchar_t kConfigGoodMinimal[] =
    L"syzygy/instrument/test_data/allocation-filter-good-minimal.json";

class TestAllocationFilterTransform : public AllocationFilterTransform {
 public:
  using AllocationFilterTransform::pre_call_hook_ref_;
  using AllocationFilterTransform::post_call_hook_ref_;
  using AllocationFilterTransform::targets_;
  using AllocationFilterTransform::instrumented_;

  TestAllocationFilterTransform()
      : AllocationFilterTransform(FunctionNameOffsetMap()) {
    // Disabling reporting to make the tests faster, as reporting is very slow
    // when there are many invalid targets. This only avoids logging;
    // instrumented calls are still tracked.
    set_enable_reporting(false);
    set_debug_friendly(true);
  }
};

class AllocationFilterTransformTest : public testing::TestDllTransformTest {
 public:
  // Collects all the valid call instructions of the target binary.
  FunctionNameOffsetMap CollectCalls();

  // Generates strictly invalid target addresses based on the target binary.
  // e.g. pointing to non-call instructions or invalid instruction offsets.
  // Non-existent function names are also included.
  FunctionNameOffsetMap GenerateInvalidTargets();

  // Ensures that the target binary is correctly instrumented.
  // Also checks that function names in |do_not_hook_| were not instrumented.
  void CheckInstrumentation();

  // Ensures that the basic block does not contains any hooked calls.
  void CheckBasicBlockIsClean(const BasicCodeBlock* bb_code_block);

  // Ensures that all calls in the basic block are correctly instrumented.
  void CheckBasicBlockIsInstrumented(const BasicCodeBlock* bb_code_block);

  // Dumps target call addresses which are represented by a function name and
  // an offset to a JSON string.
  // The resulting |json| string will follow the following format:
  // {
  //   "hooks": {
  //     "function_name1": [offset1_1, offset1_2, ...],
  //     "function_name2": [offset2_1, offset2_2, ...],
  //     "function_name3": [offset3_1, offset3_2, ...],
  //     ...
  //   }
  // }
  // All offsets are represented as integers.
  // @param pretty_print If true the JSON output will be pretty-printed.
  // @param targets Source map to be JSON-ified.
  // @param json Output parameter, a JSON string containing the call
  //     addresses in |targets| following the format described above.
  static void WriteToJSON(bool pretty_print,
                          const FunctionNameOffsetMap& targets,
                          std::string* json);

 protected:
  TestAllocationFilterTransform tx_;
  // Function names that won't be hooked.
  std::set<std::string> do_not_hook_;
};

// This function detects a hooked call, which consists of three contiguous
// instructions as follows:
//     CALL pre_call_hook
//     CALL some_address or [register]  // The original call
//     CALL post_call_hook
void AllocationFilterTransformTest::CheckBasicBlockIsClean(
    const BasicCodeBlock* bb_code_block) {
  BasicBlock::Instructions::const_iterator inst_iter =
    bb_code_block->instructions().begin();
  for (; inst_iter != bb_code_block->instructions().end(); ++inst_iter) {
    if (inst_iter->IsCall() && !inst_iter->CallsNonReturningFunction()) {
      BasicBlock::Instructions::const_iterator next_iter = inst_iter;
      // A call that contains a single reference to pre_call_hoook_.
      if (I_CALL != next_iter->representation().opcode)
        continue;
      if (1u != next_iter->references().size())
        continue;
      if (tx_.pre_call_hook_ref_.referenced() !=
          inst_iter->references().begin()->second.block())
        continue;

      // Original call.
      ++next_iter;
      if (next_iter == bb_code_block->instructions().end())
        continue;
      if (I_CALL != next_iter->representation().opcode)
        continue;

      // A call that contains a single reference to post_call_hoook_.
      ++next_iter;
      if (next_iter == bb_code_block->instructions().end())
        continue;
      if (I_CALL != next_iter->representation().opcode)
        continue;
      if (1u != next_iter->references().size())
        continue;
      if (tx_.post_call_hook_ref_.referenced() !=
        next_iter->references().begin()->second.block())
        continue;

      // If this point is reached it means that a hooked call was found.
      FAIL();
    }
  }
}

void AllocationFilterTransformTest::CheckBasicBlockIsInstrumented(
    const BasicCodeBlock* bb_code_block) {
  BasicBlock::Instructions::const_iterator inst_iter =
    bb_code_block->instructions().begin();
  for (; inst_iter != bb_code_block->instructions().end(); ++inst_iter) {
    if (inst_iter->IsCall() && !inst_iter->CallsNonReturningFunction()) {
      // Call to the enter hook.
      EXPECT_EQ(I_CALL, inst_iter->representation().opcode);
      EXPECT_EQ(1u, inst_iter->references().size());
      EXPECT_EQ(tx_.pre_call_hook_ref_.referenced(),
        inst_iter->references().begin()->second.block());

      // Original call.
      ++inst_iter;
      EXPECT_NE(bb_code_block->instructions().end(), inst_iter);
      EXPECT_EQ(I_CALL, inst_iter->representation().opcode);

      // Call to the exit hook.
      ++inst_iter;
      EXPECT_NE(bb_code_block->instructions().end(), inst_iter);
      EXPECT_EQ(I_CALL, inst_iter->representation().opcode);
      EXPECT_EQ(1u, inst_iter->references().size());
      EXPECT_EQ(tx_.post_call_hook_ref_.referenced(),
        inst_iter->references().begin()->second.block());
    }
  }
}

FunctionNameOffsetMap AllocationFilterTransformTest::CollectCalls() {
  FunctionNameOffsetMap call_addresses;
  // Let's examine each eligible block to collect 'call' instructions.
  BlockGraph::BlockMap::const_iterator block_iter =
    block_graph_.blocks().begin();
  for (; block_iter != block_graph_.blocks().end(); ++block_iter) {
    const BlockGraph::Block& block = block_iter->second;

    // Skip non-code blocks.
    if (block.type() != BlockGraph::CODE_BLOCK)
      continue;

    // Skip non-decomposable blocks.
    if (!policy_->BlockIsSafeToBasicBlockDecompose(&block))
      continue;

    // Decompose the block to basic-blocks.
    BasicBlockSubGraph subgraph;
    BasicBlockDecomposer bb_decomposer(&block, &subgraph);
    EXPECT_TRUE(bb_decomposer.Decompose());

    // Retrieve the first basic block.
    DCHECK_EQ(1U, subgraph.block_descriptions().size());

    const std::string function_name = block_iter->second.name();

    BasicBlockSubGraph::BBCollection::const_iterator bb_iter =
      subgraph.basic_blocks().begin();

    // For each valid block, collect the function name and offset for each call.
    for (; bb_iter != subgraph.basic_blocks().end(); ++bb_iter) {
      const BasicCodeBlock* bb = BasicCodeBlock::Cast(*bb_iter);
      if (bb == NULL || bb->is_padding() || !bb->IsValid())
        continue;
      BasicBlock::Instructions::const_iterator inst_iter =
          bb->instructions().begin();

      BasicBlock::Instructions::iterator next_iter;
      Instruction::Offset inst_offset = bb->offset();

      for (; inst_iter != bb->instructions().end();
          // Adjust the offset for next instruction.
          inst_offset += inst_iter->size(),
          ++inst_iter) {
        if (inst_iter->IsCall() && !inst_iter->CallsNonReturningFunction()) {
          EXPECT_EQ(I_CALL, inst_iter->representation().opcode);
          call_addresses[function_name].insert(inst_offset + inst_iter->size());
        }
      }
    }
  }

  return call_addresses;
}

FunctionNameOffsetMap AllocationFilterTransformTest::GenerateInvalidTargets() {
  FunctionNameOffsetMap invalid_targets;
  // Let's examine each eligible block to generate some invalid targets. So,
  // generated targets are not completely unrelated to the binary.
  BlockGraph::BlockMap::const_iterator block_iter =
    block_graph_.blocks().begin();
  for (; block_iter != block_graph_.blocks().end(); ++block_iter) {
    const BlockGraph::Block& block = block_iter->second;

    // Skip non-code blocks.
    if (block.type() != BlockGraph::CODE_BLOCK)
      continue;

    // Skip non-decomposable blocks.
    if (!policy_->BlockIsSafeToBasicBlockDecompose(&block))
      continue;

    // Decompose the block to basic-blocks.
    BasicBlockSubGraph subgraph;
    BasicBlockDecomposer bb_decomposer(&block, &subgraph);
    EXPECT_TRUE(bb_decomposer.Decompose());

    BasicBlockSubGraph::BBCollection::const_iterator bb_iter =
      subgraph.basic_blocks().begin();

    const std::string function_name = block_iter->second.name();

    // Add offsets for inexistent function names.
    for (Instruction::Offset offset = 0; offset < 0xFF; offset += 7) {
      const std::string unique_name = function_name + "180914_unique_suffix";
      invalid_targets[unique_name].insert(offset);
    }

    // For each valid block, collect the function name and offset for each call.
    for (; bb_iter != subgraph.basic_blocks().end(); ++bb_iter) {
      const BasicCodeBlock* bb = BasicCodeBlock::Cast(*bb_iter);
      if (bb == NULL || bb->is_padding() || !bb->IsValid())
        continue;
      BasicBlock::Instructions::const_iterator inst_iter =
        bb->instructions().begin();

      BasicBlock::Instructions::iterator next_iter;
      Instruction::Offset inst_offset = bb->offset();

      bool previous_inst_is_call = true;

      for (; inst_iter != bb->instructions().end();
        // Adjust the offset for next instruction.
        inst_offset += inst_iter->size(),
        ++inst_iter) {
        // Add non-call address.
        if (!previous_inst_is_call)
          invalid_targets[function_name].insert(inst_offset);

        // Add an offset out of the instruction boundary.
        if (inst_iter->size() > 1) {
          Instruction::Offset out_of_inst_boundary =
              inst_offset + inst_iter->size() - 1;
          invalid_targets[function_name].insert(out_of_inst_boundary);
        }
        previous_inst_is_call = inst_iter->IsCall();
      }
    }
  }

  return invalid_targets;
}

void AllocationFilterTransformTest::CheckInstrumentation() {
  // Let's examine each eligible block to verify that its basic blocks have been
  // instrumented (or not).
  BlockGraph::BlockMap::const_iterator block_iter =
      block_graph_.blocks().begin();
  for (; block_iter != block_graph_.blocks().end(); ++block_iter) {
    const BlockGraph::Block& block = block_iter->second;

    // Skip non-code blocks.
    if (block.type() != BlockGraph::CODE_BLOCK)
      continue;

    // Skip non-decomposable blocks.
    if (!policy_->BlockIsSafeToBasicBlockDecompose(&block))
      continue;

    // Decompose the block to basic-blocks.
    BasicBlockSubGraph subgraph;
    BasicBlockDecomposer bb_decomposer(&block, &subgraph);
    ASSERT_TRUE(bb_decomposer.Decompose());

    BasicBlockSubGraph::BBCollection::const_iterator bb_iter =
        subgraph.basic_blocks().begin();
    for (; bb_iter != subgraph.basic_blocks().end(); ++bb_iter) {
      const BasicCodeBlock* bb = BasicCodeBlock::Cast(*bb_iter);
      if (bb == NULL || bb->is_padding() || !bb->IsValid())
        continue;
      // Check that the functions in |do_not_hook_| are not instrumented.
      // The remaining functions should be instrumented.
      if (do_not_hook_.find(block_iter->second.name()) != do_not_hook_.end())
        ASSERT_NO_FATAL_FAILURE(CheckBasicBlockIsClean(bb));
      else
        ASSERT_NO_FATAL_FAILURE(CheckBasicBlockIsInstrumented(bb));
    }
  }
}


void AllocationFilterTransformTest::WriteToJSON(
    bool pretty_print,
    const AllocationFilterTransform::FunctionNameOffsetMap& targets,
    std::string* json) {
  DCHECK_NE(static_cast<std::string*>(NULL), json);
  DictionaryValue* hooks = new DictionaryValue();

  FunctionNameOffsetMap::const_iterator it = targets.begin();
  for (; it != targets.end(); ++it) {
    std::string function_name = it->first;

    // Build the list of offsets.
    ListValue * offset_list = new ListValue();
    OffsetSet::const_iterator offset_iter = it->second.begin();
    for (; offset_iter != it->second.end(); ++offset_iter) {
      int offset = static_cast<int>(*offset_iter);

      // Offsets shouldn't be too large to overflow an int.
      DCHECK_EQ(static_cast<Offset>(static_cast<int>(*offset_iter)),
                *offset_iter);

      offset_list->AppendInteger(offset);
    }

    // Store the function name associated with its offset list.
    hooks->SetWithoutPathExpansion(function_name, offset_list);
  }

  DictionaryValue outer_dict;
  outer_dict.SetWithoutPathExpansion("hooks", hooks);

  if (pretty_print) {
    base::JSONWriter::WriteWithOptions(
        outer_dict, base::JSONWriter::OPTIONS_PRETTY_PRINT, json);
  } else {
    base::JSONWriter::WriteWithOptions(outer_dict, 0, json);
  }
}

}  // namespace

TEST_F(AllocationFilterTransformTest, InstrumentAllCalls) {
  ASSERT_NO_FATAL_FAILURE(DecomposeTestDll());
  // Collect all the instrumentable calls.
  tx_.targets_ = CollectCalls();
  // Skip none.
  do_not_hook_.clear();
  ASSERT_TRUE(block_graph::ApplyBlockGraphTransform(
      &tx_, policy_, &block_graph_, header_block_));
  ASSERT_TRUE(tx_.pre_call_hook_ref_.IsValid());
  ASSERT_TRUE(tx_.post_call_hook_ref_.IsValid());

  // Validate that all basic blocks have been instrumented.
  ASSERT_NO_FATAL_FAILURE(CheckInstrumentation());
}

TEST_F(AllocationFilterTransformTest, InstrumentTargetedCallsOnly) {
  ASSERT_NO_FATAL_FAILURE(DecomposeTestDll());
  FunctionNameOffsetMap targets = CollectCalls();

  size_t index = 0;
  FunctionNameOffsetMap::const_iterator it = targets.begin();
  for (; it != targets.end(); it++, index++) {
    if (index % 2 == 0) {
      tx_.targets_.insert(*it);
    } else {
      do_not_hook_.insert(it->first);
    }
  }

  // Apply the allocation filter transform only to some specific functions.
  ASSERT_TRUE(block_graph::ApplyBlockGraphTransform(
      &tx_, policy_, &block_graph_, header_block_));
  EXPECT_TRUE(tx_.pre_call_hook_ref_.IsValid());
  EXPECT_TRUE(tx_.post_call_hook_ref_.IsValid());

  // Checks the instrumented and non-instrumented basic blocks.
  ASSERT_NO_FATAL_FAILURE(CheckInstrumentation());
}

TEST_F(AllocationFilterTransformTest, InvalidTargetsAreIgnored) {
  ASSERT_NO_FATAL_FAILURE(DecomposeTestDll());

  // Loads lots of strictly invalid target addresses, including non-call
  // instructions, invalid offsets, and non-existent function names.
  tx_.targets_ = GenerateInvalidTargets();

  // Apply the allocation filter transform with invalid targets.
  ASSERT_TRUE(block_graph::ApplyBlockGraphTransform(
      &tx_, policy_, &block_graph_, header_block_));
  EXPECT_TRUE(tx_.pre_call_hook_ref_.IsValid());
  EXPECT_TRUE(tx_.post_call_hook_ref_.IsValid());

  // Check that no invalid addresses were instrumented.
  EXPECT_TRUE(tx_.instrumented_.empty());
}

TEST_F(AllocationFilterTransformTest, JSONReadWrite) {
  ASSERT_NO_FATAL_FAILURE(DecomposeTestDll());
  // This test JSON-ifies a valid target address map, then loads a new map
  // from the produced JSON and ensures that both,
  // (the original and de-serialized) are equal.

  // Collect all call addresses.
  FunctionNameOffsetMap original = CollectCalls();

  std::string json;
  // Dump all the addresses to JSON.
  WriteToJSON(true, original, &json);

  // Loads from JSON.
  FunctionNameOffsetMap output;
  EXPECT_TRUE(AllocationFilterTransform::ReadFromJSON(json, &output));

  ASSERT_EQ(original, output);
}

TEST_F(AllocationFilterTransformTest, JSONFailsPathDoesNotExists) {
  base::FilePath config_file = testing::GetSrcRelativePath(
      kConfigBadPathDoesNotExist);
  FunctionNameOffsetMap output;
  EXPECT_FALSE(AllocationFilterTransform::ReadFromJSON(config_file, &output));
}

TEST_F(AllocationFilterTransformTest, JSONFailsInvalidkey) {
  base::FilePath config_file = testing::GetSrcRelativePath(
      kConfigBadInvalidkey);
  FunctionNameOffsetMap output;
  EXPECT_FALSE(AllocationFilterTransform::ReadFromJSON(config_file, &output));
}

TEST_F(AllocationFilterTransformTest, JSONFailsInvalidOffsetList) {
  base::FilePath config_file = testing::GetSrcRelativePath(
      kConfigBadInvalidOffsetList);
  FunctionNameOffsetMap output;
  EXPECT_FALSE(AllocationFilterTransform::ReadFromJSON(config_file, &output));
}

TEST_F(AllocationFilterTransformTest, JSONFailsList) {
  base::FilePath config_file = testing::GetSrcRelativePath(
      kConfigBadList);
  FunctionNameOffsetMap output;
  EXPECT_FALSE(AllocationFilterTransform::ReadFromJSON(config_file, &output));
}

TEST_F(AllocationFilterTransformTest, JSONFailsNegativeOffset) {
  base::FilePath config_file = testing::GetSrcRelativePath(
      kConfigBadNegativeOffset);
  FunctionNameOffsetMap output;
  EXPECT_FALSE(AllocationFilterTransform::ReadFromJSON(config_file, &output));
}

TEST_F(AllocationFilterTransformTest, JSONFailsString) {
  base::FilePath config_file = testing::GetSrcRelativePath(
      kConfigBadString);
  FunctionNameOffsetMap output;
  EXPECT_FALSE(AllocationFilterTransform::ReadFromJSON(config_file, &output));
}

TEST_F(AllocationFilterTransformTest, JSONLoadsEmpty) {
  base::FilePath config_file = testing::GetSrcRelativePath(
      kConfigGoodEmpty);
  FunctionNameOffsetMap output;
  EXPECT_TRUE(AllocationFilterTransform::ReadFromJSON(config_file, &output));
}

TEST_F(AllocationFilterTransformTest, JSONLoadsFull) {
  base::FilePath config_file = testing::GetSrcRelativePath(
      kConfigGoodFull);
  FunctionNameOffsetMap output;
  EXPECT_TRUE(AllocationFilterTransform::ReadFromJSON(config_file, &output));
}

TEST_F(AllocationFilterTransformTest, JSONLoadsMinimal) {
  base::FilePath config_file = testing::GetSrcRelativePath(
      kConfigGoodMinimal);
  FunctionNameOffsetMap output;
  EXPECT_TRUE(AllocationFilterTransform::ReadFromJSON(config_file, &output));
}

}  // namespace transforms
}  // namespace instrument
