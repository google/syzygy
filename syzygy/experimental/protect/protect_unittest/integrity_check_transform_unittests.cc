// Copyright 2015 Google Inc. All Rights Reserved.
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

#include "syzygy/experimental/protect/protect_lib/integrity_check_transform.h"

#include <sstream>
#include <map>

#include "gtest/gtest.h"
#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/basic_block_assembler.h"
#include "syzygy/block_graph/basic_block_decomposer.h"
#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/block_graph/block_util.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/common/indexed_frequency_data.h"
#include "syzygy/instrument/transforms/unittest_util.h"

namespace protect {
namespace {

//using base::DictionaryValue;
//using base::ListValue;
//using base::Value;

using block_graph::BasicBlock;
using block_graph::BasicBlockDecomposer;
using block_graph::BasicBlockSubGraph;
using block_graph::BasicCodeBlock;
using block_graph::BlockGraph;
using block_graph::Instruction;

//typedef AllocationFilterTransform::Offset Offset;
//typedef AllocationFilterTransform::OffsetSet OffsetSet;
//typedef AllocationFilterTransform::FunctionNameOffsetMap
//    FunctionNameOffsetMap;

static wchar_t kConfigBadPathDoesNotExist[] =
    L"syzygy/instrument/test_data/"
    L"allocation-filter-bad-path-does-not-exist.json";

class TestIntegrityCheckTransform : public IntegrityCheckTransform {
 public:
  //using IntegrityCheckTransform::pre_call_hook_ref_;
  //using AllocationFilterTransform::post_call_hook_ref_;
  using IntegrityCheckTransform::target_names_;
  using IntegrityCheckTransform::partition_unit_map_;
  using IntegrityCheckTransform::label_name_to_block_;
  using IntegrityCheckTransform::dll_id_to_block_reference_;
  using IntegrityCheckTransform::nr_pc_relative_refs_;
  using IntegrityCheckTransform::is_bb_checked_map_;
  using IntegrityCheckTransform::ic_block_chunk_index_map_;
  using IntegrityCheckTransform::ic_block_reference_free_chunks;
  using IntegrityCheckTransform::ic_chunk_checker_to_checkee_map_;
  using IntegrityCheckTransform::precomputed_hashes_;
  using IntegrityCheckTransform::checker_to_checkee_map_;
  using IntegrityCheckTransform::xhash_block_;
  using IntegrityCheckTransform::hash_block_;
  using IntegrityCheckTransform::response_block_;
  using IntegrityCheckTransform::id_to_label_;
  using IntegrityCheckTransform::basic_block_sizes_;
  using IntegrityCheckTransform::num_chunks_per_block;
  using IntegrityCheckTransform::GetHashBlock;//done mohsen
  using IntegrityCheckTransform::SetHashBlock;//done mohsen
  using IntegrityCheckTransform::CheckHash;//done mohsen
  using IntegrityCheckTransform::FixPrecomputedHashes;//done mohsen
  using IntegrityCheckTransform::PatchPrecomputedHashes;//mohsen
  using IntegrityCheckTransform::PatchBlockReference;//done mohsen
  using IntegrityCheckTransform::RecomputeXorChunks;//done mohsen
  using IntegrityCheckTransform::RecomputePivot;//done mohsen
  using IntegrityCheckTransform::ComputeAggregatedChunksHash;//done mohsen
  using IntegrityCheckTransform::ComputeAggregatedBlocksHash;//done mohsen
  using IntegrityCheckTransform::PatchPivot;//done mohsen
  using IntegrityCheckTransform::PatchBlockReferencesAndSizes;//done mohsen
  using IntegrityCheckTransform::AddChunkIntegrityCheckCode;//done mohsen
  using IntegrityCheckTransform::AddIntegrityCheckCode;//done mohsen
  using IntegrityCheckTransform::ComputeChunks;//done mohsen
  using IntegrityCheckTransform::AddChunkIntoIndexMap;//done mohsen
  using IntegrityCheckTransform::GenerateChunkCombinations;//mohsen
  using IntegrityCheckTransform::GetChunkUniqueKey;//done mohsen
  using IntegrityCheckTransform::PrecomputeHash;
  using IntegrityCheckTransform::IsIdInPartitionUnitMap;
  using IntegrityCheckTransform::GenerateLabelToBlockMap;
  using IntegrityCheckTransform::UpdateLabelToBlockMap;
  using IntegrityCheckTransform::PopulatePartitionKey;
  using IntegrityCheckTransform::AllBasicBlocksChecked;
  using IntegrityCheckTransform::IsBogusBlock;
  using IntegrityCheckTransform::PopulateCheckMaps;
  using IntegrityCheckTransform::RandomlySelectChecker;
  using IntegrityCheckTransform::AddReference;
  using IntegrityCheckTransform::GetBasicBlockIdByLabel;
  using IntegrityCheckTransform::TransformBasicBlockSubGraph;
  using IntegrityCheckTransform::ProcessAllBlocks;
  using IntegrityCheckTransform::GenerateBasicBlockCombinations;
  using IntegrityCheckTransform::ShouldProcessBlock;
  using IntegrityCheckTransform::TransformBlockGraph;

  TestIntegrityCheckTransform()
    : IntegrityCheckTransform(std::set<std::string>(),1.0f) {
  }

  void ResetTransform();

};




// Cleans state of the IntegrityCheckTransform
void TestIntegrityCheckTransform::ResetTransform() {
  this->hash_block_ = NULL;
  this->xhash_block_ = NULL;
  this->response_block_ = NULL;
  this->nr_hashes_patched_ = 0;
  this->nr_pc_relative_refs_ = 0;
  this->num_chunks_per_block = 0;
  this->chunk_checking_coverage = 0;
  this->label_name_to_block_.clear();
  this->dll_id_to_block_reference_.clear();
  this->adjust_label_by_offset_.clear();
  this->target_names_.clear();
  this->subgraph_vector_.clear();
  this->checker_to_checkee_map_.clear();
  this->is_bb_checked_map_.clear();
  this->basic_block_has_ref_.clear();
  this->basic_block_sizes_.clear();
  this->precomputed_hashes_.clear();
  this->partition_map_.clear();
  this->partition_unit_map_.clear();
  this->id_to_label_.clear();
  this->ic_block_reference_free_chunks.clear();
  this->ic_block_chunk_index_map_.clear();
  this->ic_chunk_checker_to_checkee_map_.clear();
}

class IntegrityCheckTransformTest : public testing::TestDllTransformTest {
 protected:
  TestIntegrityCheckTransform tx_;
  //static int *x;
  static void SetUpTestCase(){
    //x = new int[10];
  }
  static void TearDownTestCase(){
   // delete x;
  }
};

}  // namespace

TEST_F(IntegrityCheckTransformTest, CheckIsIdInParitionUnitMap) {
  ASSERT_FALSE(tx_.IsIdInPartitionUnitMap(0));
  ASSERT_FALSE(tx_.IsIdInPartitionUnitMap(125));

  std::set<uint64> st;
  st.insert(125);
  std::pair<int, std::set<uint64>> x(0, st);
  tx_.partition_unit_map_.insert(x);

  ASSERT_TRUE(tx_.IsIdInPartitionUnitMap(125));
  ASSERT_FALSE(tx_.IsIdInPartitionUnitMap(123));

  tx_.partition_unit_map_.erase(tx_.partition_unit_map_.find(0));
  ASSERT_FALSE(tx_.IsIdInPartitionUnitMap(125));

  tx_.ResetTransform();
}


TEST_F(IntegrityCheckTransformTest, CheckGenerateLabelToBlockMap) {
  BlockGraph *bgraph = NULL;
  BlockGraph::Block *test_block_a = NULL;
  BlockGraph::Block *test_block_b = NULL;
  BlockGraph::Block *test_block_c = NULL;

  bgraph = new BlockGraph();
  test_block_a = bgraph->AddBlock(BlockGraph::CODE_BLOCK, 1000, "sample a");
  test_block_b = bgraph->AddBlock(BlockGraph::CODE_BLOCK, 1000, "sample b");
  test_block_c = bgraph->AddBlock(BlockGraph::CODE_BLOCK, 1000, "sample c");
  test_block_a->SetLabel(10, BlockGraph::Label("test a", BlockGraph::CODE_LABEL));
  test_block_b->SetLabel(20, BlockGraph::Label("test b", BlockGraph::CODE_LABEL));
  test_block_c->SetLabel(500, BlockGraph::Label("test c", BlockGraph::CODE_LABEL));

  tx_.GenerateLabelToBlockMap(bgraph);
  // Check for presence and value
  auto res = tx_.label_name_to_block_.find("test a");
  ASSERT_TRUE(res != tx_.label_name_to_block_.end());
  ASSERT_TRUE(res->second.first == test_block_a);
  res = tx_.label_name_to_block_.find("test b");
  ASSERT_TRUE(res != tx_.label_name_to_block_.end());
  ASSERT_TRUE(res->second.first == test_block_b);
  res = tx_.label_name_to_block_.find("test c");
  ASSERT_TRUE(res != tx_.label_name_to_block_.end());
  ASSERT_TRUE(res->second.first == test_block_c);

  res = tx_.label_name_to_block_.find("test d");
  ASSERT_TRUE(res == tx_.label_name_to_block_.end());

  tx_.ResetTransform();
  delete bgraph;
}

TEST_F(IntegrityCheckTransformTest, CheckUpdateLabelToBlockMap) {
  BlockGraph *bgraph = NULL;
  BlockGraph::Block *test_block = NULL;

  bgraph = new BlockGraph();
  test_block = bgraph->AddBlock(BlockGraph::CODE_BLOCK, 1000, "sample");
  test_block->SetLabel(10, BlockGraph::Label("test a", BlockGraph::CODE_LABEL));
  test_block->SetLabel(20, BlockGraph::Label("test b", BlockGraph::CODE_LABEL));
  test_block->SetLabel(500, BlockGraph::Label("test c", BlockGraph::CODE_LABEL));

  tx_.UpdateLabelToBlockMap(test_block);

  // Check for presence and value
  auto res = tx_.label_name_to_block_.find("test a");
  ASSERT_TRUE(res != tx_.label_name_to_block_.end());
  ASSERT_TRUE(res->second.first == test_block);
  res = tx_.label_name_to_block_.find("test b");
  ASSERT_TRUE(res != tx_.label_name_to_block_.end());
  ASSERT_TRUE(res->second.first == test_block);
  res = tx_.label_name_to_block_.find("test c");
  ASSERT_TRUE(res != tx_.label_name_to_block_.end());
  ASSERT_TRUE(res->second.first == test_block);

  res = tx_.label_name_to_block_.find("test d");
  ASSERT_TRUE(res == tx_.label_name_to_block_.end());

  tx_.ResetTransform();
  delete bgraph;
}

TEST_F(IntegrityCheckTransformTest, CheckAllBasicBlocksChecked) {
  std::set<uint64> test_set;
  test_set.insert(0);

  std::map<std::set<uint64>, int> check_order;
  check_order.insert(std::pair<std::set<uint64>, int>(test_set, 0));

  ASSERT_TRUE(tx_.is_bb_checked_map_[0] == 0);
  ASSERT_TRUE(tx_.AllBasicBlocksChecked(check_order) == false);

  tx_.is_bb_checked_map_.insert(std::pair<uint64, int > (0, 1));
  ASSERT_FALSE(tx_.AllBasicBlocksChecked(check_order) == true);

  tx_.ResetTransform();
}

TEST_F(IntegrityCheckTransformTest, CheckPopulateCheckMaps) {
  // TODO: Understand how it works
}

TEST_F(IntegrityCheckTransformTest, CheckIsBogusBlock) {
  BlockGraph *bgraph = new BlockGraph();
  BlockGraph::Block *test_block = NULL;
  test_block = bgraph->AddBlock(BlockGraph::CODE_BLOCK, 1000, "sample a");

  ASSERT_FALSE(tx_.IsBogusBlock(test_block));

  std::set<uint64> test_set;
  test_set.insert(test_block->id());
  std::pair<int, std::set<uint64>> x(0, test_set);
  tx_.partition_unit_map_.insert(x);

  ASSERT_TRUE(tx_.IsBogusBlock(test_block));

  tx_.ResetTransform();
  delete bgraph;
}

TEST_F(IntegrityCheckTransformTest, CheckPatchBlockReference) {
  BlockGraph *bgraph = NULL;
  BlockGraph::Block *test_block_a = NULL;
  BlockGraph::Block *test_block_b = NULL;
  BlockGraph::Block *test_block_c = NULL;

  bgraph = new BlockGraph();
  test_block_a = bgraph->AddBlock(BlockGraph::CODE_BLOCK, 1000, "dest_a");
  test_block_b = bgraph->AddBlock(BlockGraph::CODE_BLOCK, 1000, "dest_b");
  test_block_c = bgraph->AddBlock(BlockGraph::CODE_BLOCK, 1000, "code_block");

  BasicBlockSubGraph* subgraph = new BasicBlockSubGraph();
  subgraph->set_original_block(test_block_c);
  BlockGraph::Section* code_section = bgraph->FindOrAddSection(".text",
    0x60000000);

  subgraph->AddBlockDescription("test_subgraph", code_section->name(),
    BlockGraph::CODE_BLOCK,
    code_section->id(), 1, 0);

  BasicCodeBlock* bb = subgraph->AddBasicCodeBlock("basic_code_block");
  auto inst_iter = bb->instructions().begin();
  block_graph::BasicBlockAssembler assm(inst_iter,
    &bb->instructions());

  int original_offset = 100;
  int label_offset = 10;
  assm.push(block_graph::Operand(block_graph::Displacement(test_block_a,
                                                           original_offset)));

  // Insert the label and update label_name_to_block_
  test_block_b->SetLabel(label_offset,
                         BlockGraph::Label("Test Label",
                                           BlockGraph::CODE_LABEL));
  auto lab_it(test_block_b->labels().begin());
  tx_.label_name_to_block_[lab_it->second.name()] =
    std::make_pair(test_block_b, lab_it->first);

  // Prepare parameters for calling PatchBlockReference
  auto label_to_block_it = tx_.label_name_to_block_.find(lab_it->second.name());
  CHECK(label_to_block_it != tx_.label_name_to_block_.end());
  auto reference_free_block = label_to_block_it->second.first;
  uint32 new_bb_ref_offset = label_to_block_it->second.second;
  int intermediate_offset = 150;

  // Check initial offset and reference
  inst_iter = bb->instructions().begin();
  Instruction::BasicBlockReferenceMap &ref_block_map =
    inst_iter->references();
  auto instruction_references_it = ref_block_map.begin();
  BlockGraph::Offset reference_offset =
    instruction_references_it->first;
  block_graph::BasicBlockReference old_bb_ref =
      instruction_references_it->second;
  ASSERT_TRUE(old_bb_ref.block() == test_block_a);
  ASSERT_TRUE(old_bb_ref.offset() == original_offset);

  // Patch the instruction without changing the block
  tx_.PatchBlockReference(inst_iter, reference_free_block,
    intermediate_offset, false);

  // Check the modifications
  instruction_references_it = inst_iter->references().begin();
  reference_offset = instruction_references_it->first;
  block_graph::BasicBlockReference new_bb_ref =
      instruction_references_it->second;

  ASSERT_TRUE(new_bb_ref.block() == test_block_a);
  ASSERT_TRUE(new_bb_ref.offset() == intermediate_offset);

  // Patch the instruction including changing the block
  tx_.PatchBlockReference(inst_iter, reference_free_block,
    new_bb_ref_offset, true);

  instruction_references_it = inst_iter->references().begin();
  reference_offset = instruction_references_it->first;
  new_bb_ref = instruction_references_it->second;

  ASSERT_TRUE(new_bb_ref.block() == test_block_b);
  ASSERT_TRUE((uint32)new_bb_ref.offset() == new_bb_ref_offset);

  tx_.ResetTransform();
  delete bgraph;
  delete subgraph;
}

TEST_F(IntegrityCheckTransformTest, CheckCheckHash) {
  BlockGraph *bgraph = new BlockGraph();
  BlockGraph::Block *test_block_b = NULL;
  test_block_b = bgraph->AddBlock(BlockGraph::CODE_BLOCK, 2000, "sample b");
  base::StringPiece test_block_tag = "1";
  auto test_block_label = block_graph::BlockGraph::Label(
      test_block_tag,
      BlockGraph::CODE_LABEL);
  uint64 test_block_id = 1;
  uint32 test_block_size = 1;
  // push eax equals to 0x50
  uint8 test_block_value = 0x50;
  //prepare id to label map
  tx_.id_to_label_[test_block_id] = test_block_label;
  //set the size
  tx_.basic_block_sizes_[test_block_id] = test_block_size;

  BasicBlockSubGraph* subgraph = new BasicBlockSubGraph();
  subgraph->set_original_block(test_block_b);
  BlockGraph::Section* code_section = bgraph->FindOrAddSection(".text",
    0x60000000);

  subgraph->AddBlockDescription("sample c", code_section->name(),
    BlockGraph::CODE_BLOCK,
    code_section->id(), 1, 0);

  BasicCodeBlock* bb = subgraph->AddBasicCodeBlock("sample b");

  auto inst_iter = bb->instructions().begin();
  block_graph::BasicBlockAssembler assm(inst_iter,
    &bb->instructions());

  assm.push(assm::eax);
  //add label to the block
  auto instr = bb->instructions().begin();
  instr->set_label(test_block_label);


  std::vector<uint8> test_buffer;
  test_buffer.insert(test_buffer.begin(), test_block_value);
  //offset in the test buffer
  bb->set_offset(0);
  tx_.CheckHash(bb, test_buffer);

  //we should have a hash computed for this block
  ASSERT_TRUE(tx_.precomputed_hashes_[test_block_id] == test_block_value);

  tx_.ResetTransform();
  delete bgraph;
  delete subgraph;
}

TEST_F(IntegrityCheckTransformTest, CheckFixPrecomputedHashes) {
          //what the hell to test here!
}

TEST_F(IntegrityCheckTransformTest, CheckRecomputeXorChunks){
  uint64 test_block_id = 1;
  uint8 test_old_size[1] = { 1 };
  uint8 test_new_size[1] = { 2 };
  uint64 test_chunk_bb_id = 1;
  uint32 test_chunk_index = 0;
  uint32 test_chunk_size = 1;
  uint8 test_chunk_hash = 0x50;
  //new hash = old hash ^ old_size ^ new_size
  uint8 test_chunk_new_hash = 0x53;

  uint64 test_vector_index = 0;
  tx_.ic_block_chunk_index_map_[tx_.GetChunkUniqueKey(test_chunk_bb_id,
                                                      test_chunk_index)] =
      test_vector_index;

  ChunkInfo test_chunk(test_chunk_bb_id,test_chunk_size,
                       test_chunk_hash, test_chunk_index,0);
  tx_.ic_block_reference_free_chunks.insert(
      tx_.ic_block_reference_free_chunks.begin(), test_chunk);

  tx_.RecomputeXorChunks(test_block_id, test_old_size, test_new_size,
                         test_chunk_bb_id, test_chunk_index);

  //we should have a hash computed for this block
  auto updated_chunk = tx_.ic_block_reference_free_chunks[test_vector_index];

  ASSERT_EQ(updated_chunk.hash_,test_chunk_new_hash);

  tx_.ResetTransform();
}
TEST_F(IntegrityCheckTransformTest, CheckGetHashBlock) {
  ASSERT_TRUE(tx_.GetHashBlock()==NULL);
}
TEST_F(IntegrityCheckTransformTest, CheckSetHashBlock) {
  BlockGraph *bgraph = NULL;
  BlockGraph::Block *test_block_a = NULL;

  bgraph = new BlockGraph();
  test_block_a = bgraph->AddBlock(BlockGraph::CODE_BLOCK, 1000, "dest_a");

  tx_.SetHashBlock(test_block_a);
  auto ret_block = tx_.GetHashBlock();
  ASSERT_TRUE(ret_block == test_block_a);
  tx_.ResetTransform();
  delete bgraph;
}


TEST_F(IntegrityCheckTransformTest, CheckRecomputePivot){
  BlockGraph *bgraph = new BlockGraph();
  BlockGraph::Block *test_block_b = NULL;
  test_block_b = bgraph->AddBlock(BlockGraph::CODE_BLOCK, 2000, "sample b");
  uint8 old_hash = 0x1;
  // push eax, pivot, sub al, old hash
  uint8 test_block_data[5] = { 0x50, 0x0, 0x2c, old_hash };

  test_block_b->SetData(test_block_data, sizeof(test_block_data));


  uint64 test_block_id = 1;
  uint8 test_precomputed_hash = 0x7c;
  uint8 test_precomputed_xor = 1;
  uint32 test_pivot_offset = 1;
  uint32 test_sub_offset = 2;
  tx_.RecomputePivot(test_block_id, test_precomputed_hash, test_precomputed_xor,
                     test_pivot_offset, test_sub_offset, test_block_b);
  // pivot + new hash = old hash
  uint8 hash_diff = test_block_b->data()[test_pivot_offset] +
                    test_block_b->data()[test_sub_offset + 1];
  bool is_pivot_correct = hash_diff == old_hash;

  ASSERT_TRUE(is_pivot_correct);
  delete bgraph;

}

TEST_F(IntegrityCheckTransformTest, CheckComputeAggregatedBlocksHash){
  uint64 test_bb_id = 1;
  std::map<uint64, int> test_checkee_map;
  test_checkee_map[2] = 1;
  test_checkee_map[3] = -1;
  tx_.checker_to_checkee_map_[test_bb_id] = test_checkee_map;
  tx_.precomputed_hashes_[2] = 0x20;
  tx_.precomputed_hashes_[3] = 0x10;
  uint8 computed_hash = tx_.ComputeAggregatedBlocksHash(test_bb_id);
  ASSERT_EQ(0x10, computed_hash);

  tx_.ResetTransform();
}
TEST_F(IntegrityCheckTransformTest, CheckComputeAggregatedChunksHash){
  uint8 hash1 = 0x1;
  uint8 hash2 = 0x2;
  tx_.ic_block_reference_free_chunks.insert(
    tx_.ic_block_reference_free_chunks.begin(), ChunkInfo(1, 1, hash1, 0, 0));
  tx_.ic_block_reference_free_chunks.insert(
    tx_.ic_block_reference_free_chunks.begin(), ChunkInfo(1, 1, hash2, 0, 0));
  std::set<uint32> test_chunk_index_set;
  test_chunk_index_set.insert(0);
  test_chunk_index_set.insert(1);
  uint8 computed_hash = tx_.ComputeAggregatedChunksHash(test_chunk_index_set);
  ASSERT_EQ(0x3, computed_hash);

  tx_.ResetTransform();
}

TEST_F(IntegrityCheckTransformTest, CheckPatchPivot){
  BlockGraph *bgraph = new BlockGraph();
  BlockGraph::Block *test_block_b = NULL;
  test_block_b = bgraph->AddBlock(BlockGraph::CODE_BLOCK, 2000, "sample b");
  base::StringPiece test_block_tag = "1";
  auto test_block_label = block_graph::BlockGraph::Label(
      test_block_tag,
      BlockGraph::CODE_LABEL);
  uint64 test_block_id = 1;
  uint32 test_block_size = 1;
  //prepare id to label map
  tx_.id_to_label_[test_block_id] = test_block_label;
  //set the size
  tx_.basic_block_sizes_[test_block_id] = test_block_size;

  BasicBlockSubGraph* subgraph = new BasicBlockSubGraph();
  subgraph->set_original_block(test_block_b);
  BlockGraph::Section* code_section = bgraph->FindOrAddSection(".text",
                                                               0x60000000);

  subgraph->AddBlockDescription("sample c", code_section->name(),
                                BlockGraph::CODE_BLOCK,
                                code_section->id(), 1, 0);

  BasicCodeBlock* bb = subgraph->AddBasicCodeBlock("sample b");

  auto inst_iter = bb->instructions().begin();
  block_graph::BasicBlockAssembler assm(inst_iter,
                                        &bb->instructions());

  uint8 old_hash = 0x1;

  assm.push(assm::eax);
  assm.data(0);
  assm.sub(assm::al,block_graph::Immediate(old_hash,
                                           assm::ValueSize::kSize8Bit));
  //add labels to the block
  auto instr = bb->instructions().begin();
  instr->set_label(test_block_label);
  uint32 test_pivot_offset = 1;
  uint32 test_sub_offset = 2;
  uint32 test_hash_offset = 3;
  tx_.label_name_to_block_["Pivot:1"] = std::make_pair(test_block_b,
                                                       test_pivot_offset);
  tx_.label_name_to_block_["sub 1"] = std::make_pair(test_block_b,
                                                     test_sub_offset);

  uint64 test_bb_id = 1;
  std::map<uint64, int> test_checkee_map;
  test_checkee_map[2] = 1;
  test_checkee_map[3] = -1;
  tx_.checker_to_checkee_map_[test_bb_id] = test_checkee_map;
  tx_.precomputed_hashes_[2] = 0x20;
  tx_.precomputed_hashes_[3] = 0x10;


  uint8 hash1 = 0x1;
  uint8 hash2 = 0x2;
  tx_.ic_block_reference_free_chunks.insert(
    tx_.ic_block_reference_free_chunks.begin(), ChunkInfo(1, 1, hash1, 0, 0));
  tx_.ic_block_reference_free_chunks.insert(
    tx_.ic_block_reference_free_chunks.begin(), ChunkInfo(1, 1, hash2, 0, 0));
  std::set<uint32> test_chunk_index_set;
  test_chunk_index_set.insert(0);
  test_chunk_index_set.insert(1);
  tx_.ic_chunk_checker_to_checkee_map_[test_bb_id] = test_chunk_index_set;


  // push eax, pivot, sub al, old hash
  uint8 test_block_data[5] = { 0x50, 0x0, 0x2c, old_hash };

  test_block_b->SetData(test_block_data, sizeof(test_block_data));


  FILE *file=NULL;
  tx_.PatchPivot(bb, subgraph, bgraph, file);

  //hash = precomputed sum + precomputed xor
  //hash = 0x10 + 0x3
  ASSERT_EQ(test_block_b->data()[test_hash_offset], 0x13);

  uint8 hash_diff = test_block_b->data()[test_pivot_offset] +
      test_block_b->data()[test_hash_offset];
  bool is_pivot_correct = hash_diff == old_hash;

  ASSERT_TRUE(is_pivot_correct);

  tx_.ResetTransform();

  delete bgraph;
  delete subgraph;
}

TEST_F(IntegrityCheckTransformTest, CheckPatchSizesByLabel){
  BlockGraph *bgraph = new BlockGraph();
  BlockGraph::Block *test_block_b = NULL;
  test_block_b = bgraph->AddBlock(BlockGraph::CODE_BLOCK, 2000, "sample b");
  base::StringPiece test_block_tag = "1";
  auto test_block_label = block_graph::BlockGraph::Label(
      test_block_tag,
      BlockGraph::CODE_LABEL);
  uint64 test_block_id = 1;
  uint32 test_block_size = 1;
  //prepare id to label map
  tx_.id_to_label_[test_block_id] = test_block_label;
  //set the size
  tx_.basic_block_sizes_[test_block_id] = test_block_size;

  BasicBlockSubGraph* subgraph = new BasicBlockSubGraph();
  subgraph->set_original_block(test_block_b);
  BlockGraph::Section* code_section = bgraph->FindOrAddSection(".text",
                                                               0x60000000);

  subgraph->AddBlockDescription("sample c", code_section->name(),
                                BlockGraph::CODE_BLOCK,
                                code_section->id(), 1, 0);

  BasicCodeBlock* bb = subgraph->AddBasicCodeBlock("sample b");

  auto inst_iter = bb->instructions().begin();
  block_graph::BasicBlockAssembler assm(inst_iter,
                                        &bb->instructions());

  uint32 test_old_block_size = 0x10;
  uint32 test_new_block_size = 0x11;
  uint64 test_reference_block_id = 2;
  assm.push(assm::eax);
  assm.push(block_graph::Immediate(test_old_block_size, assm::kSize32Bit));


  inst_iter = bb->instructions().begin();
  //set chunk finger label
  inst_iter->set_label(block_graph::BlockGraph::Label("n 1 0",
                                                      BlockGraph::CODE_LABEL));
  ++inst_iter;
  inst_iter->set_label(block_graph::BlockGraph::Label("size 2 1",
                                                      BlockGraph::CODE_LABEL));
  tx_.basic_block_sizes_[test_reference_block_id] = test_new_block_size;

  uint64 test_chunk_bb_id = 1;
  uint32 test_chunk_index = 0;
  uint32 test_chunk_size = 1;
  uint8 test_chunk_hash = 0x50;


  uint64 test_vector_index = 0;
  tx_.ic_block_chunk_index_map_[tx_.GetChunkUniqueKey(test_chunk_bb_id,
    test_chunk_index)] =
    test_vector_index;

  ChunkInfo test_chunk(test_chunk_bb_id, test_chunk_size,
                       test_chunk_hash, test_chunk_index, 0);
  tx_.ic_block_reference_free_chunks.insert(
    tx_.ic_block_reference_free_chunks.begin(), test_chunk);

  tx_.PatchBlockReferencesAndSizes(bb, subgraph, bgraph);
  ASSERT_EQ(inst_iter->data()[1], test_new_block_size);

  tx_.ResetTransform();
  delete bgraph;
  delete subgraph;

}

TEST_F(IntegrityCheckTransformTest, CheckPatchBlockReferenceByLabel) {
  BlockGraph *bgraph = NULL;
  BlockGraph::Block *test_block_a = NULL;

  bgraph = new BlockGraph();
  test_block_a = bgraph->AddBlock(BlockGraph::CODE_BLOCK, 1000, "dest_a");

  BasicBlockSubGraph* subgraph = new BasicBlockSubGraph();
  subgraph->set_original_block(test_block_a);
  BlockGraph::Section* code_section = bgraph->FindOrAddSection(".text",
                                                               0x60000000);

  subgraph->AddBlockDescription("test_subgraph", code_section->name(),
                                BlockGraph::CODE_BLOCK,
                                code_section->id(), 1, 0);

  BasicCodeBlock* bb = subgraph->AddBasicCodeBlock("basic_code_block");
  auto inst_iter = bb->instructions().begin();
  block_graph::BasicBlockAssembler assm(inst_iter,
                                        &bb->instructions());

  int original_offset = 100;
  assm.push(block_graph::Immediate(test_block_a, original_offset));
  inst_iter = bb->instructions().begin();
  inst_iter->set_label(BlockGraph::Label("block 2",
                       BlockGraph::CODE_LABEL));
  int intermediate_offset = 150;

  //move block offset
  tx_.label_name_to_block_["2"] =
      std::make_pair(test_block_a, intermediate_offset);

  // Check initial offset and reference
  inst_iter = bb->instructions().begin();
  Instruction::BasicBlockReferenceMap &ref_block_map =
      inst_iter->references();
  auto instruction_references_it = ref_block_map.begin();
  BlockGraph::Offset reference_offset = instruction_references_it->first;
  block_graph::BasicBlockReference old_bb_ref =
      instruction_references_it->second;
  ASSERT_TRUE(old_bb_ref.block() == test_block_a);
  ASSERT_TRUE(old_bb_ref.offset() == original_offset);



  tx_.PatchBlockReferencesAndSizes(bb, subgraph, bgraph);

  inst_iter = bb->instructions().begin();
  // Check the modifications
  instruction_references_it = inst_iter->references().begin();
  reference_offset = instruction_references_it->first;
  block_graph::BasicBlockReference new_bb_ref =
      instruction_references_it->second;

  ASSERT_TRUE(new_bb_ref.block() == test_block_a);
  ASSERT_TRUE(new_bb_ref.offset() == intermediate_offset);
}

TEST_F(IntegrityCheckTransformTest, CheckPatchChunkReferenceByLabel) {
  BlockGraph *bgraph = NULL;
  BlockGraph::Block *test_block_a = NULL;

  bgraph = new BlockGraph();
  test_block_a = bgraph->AddBlock(BlockGraph::CODE_BLOCK, 1000, "dest_a");

  BasicBlockSubGraph* subgraph = new BasicBlockSubGraph();
  subgraph->set_original_block(test_block_a);
  BlockGraph::Section* code_section = bgraph->FindOrAddSection(".text",
                                                               0x60000000);

  subgraph->AddBlockDescription("test_subgraph", code_section->name(),
                                BlockGraph::CODE_BLOCK,
                                code_section->id(), 1, 0);

  BasicCodeBlock* bb = subgraph->AddBasicCodeBlock("basic_code_block");
  auto inst_iter = bb->instructions().begin();
  block_graph::BasicBlockAssembler assm(inst_iter,
                                        &bb->instructions());

  int original_offset = 100;
  assm.push(block_graph::Immediate(test_block_a, original_offset));
  inst_iter = bb->instructions().begin();
  inst_iter->set_label(BlockGraph::Label("nrc 2 0",
                       BlockGraph::CODE_LABEL));
  int intermediate_offset = 150;

  //move block offset
  tx_.label_name_to_block_["n 2 0"] =
      std::make_pair(test_block_a, intermediate_offset);

  // Check initial offset and reference
  inst_iter = bb->instructions().begin();
  Instruction::BasicBlockReferenceMap &ref_block_map =
      inst_iter->references();
  auto instruction_references_it = ref_block_map.begin();
  BlockGraph::Offset reference_offset = instruction_references_it->first;
  block_graph::BasicBlockReference old_bb_ref =
      instruction_references_it->second;
  ASSERT_TRUE(old_bb_ref.block() == test_block_a);
  ASSERT_TRUE(old_bb_ref.offset() == original_offset);



  tx_.PatchBlockReferencesAndSizes(bb, subgraph, bgraph);

  inst_iter = bb->instructions().begin();
  // Check the modifications
  instruction_references_it = inst_iter->references().begin();
  reference_offset = instruction_references_it->first;
  block_graph::BasicBlockReference new_bb_ref =
      instruction_references_it->second;

  ASSERT_TRUE(new_bb_ref.block() == test_block_a);
  ASSERT_TRUE(new_bb_ref.offset() == intermediate_offset);
}
TEST_F(IntegrityCheckTransformTest, CheckAddChunkIntegrityCheckCode) {

  uint64 test_bb_id = 1;
  //set total chunks
  tx_.num_chunks_per_block = 10;

  BlockGraph *bgraph = NULL;
  BlockGraph::Block *test_block_a = NULL;

  bgraph = new BlockGraph();
  test_block_a = bgraph->AddBlock(BlockGraph::CODE_BLOCK, 1000, "dest_a");

  BasicBlockSubGraph* subgraph = new BasicBlockSubGraph();
  subgraph->set_original_block(test_block_a);
  BlockGraph::Section* code_section = bgraph->FindOrAddSection(".text",
                                                               0x60000000);

  subgraph->AddBlockDescription("test_subgraph", code_section->name(),
                                BlockGraph::CODE_BLOCK,
                                code_section->id(), 1, 0);

  BasicCodeBlock* bb = subgraph->AddBasicCodeBlock("basic_code_block");
  auto inst_iter = bb->instructions().begin();
  block_graph::BasicBlockAssembler assm(inst_iter,
                                        &bb->instructions());

  assm.push(assm::eax);
  inst_iter = bb->instructions().begin();
  //set block id label
  auto test_block_label = BlockGraph::Label(std::to_string(test_bb_id),
    BlockGraph::CODE_LABEL);
  inst_iter->set_label(test_block_label);
  //set a dummy hash block
  tx_.xhash_block_ = test_block_a;

  //prepare id to label map
  tx_.id_to_label_[test_bb_id] = test_block_label;
  //set block size
  uint32 old_size = inst_iter->size();
  tx_.basic_block_sizes_[test_bb_id] = old_size;

  //set checker checkee map

  std::map<uint64, int> test_checkee_map;
  test_checkee_map[2] = 1;
  test_checkee_map[3] = -1;
  tx_.checker_to_checkee_map_[test_bb_id] = test_checkee_map;
  tx_.precomputed_hashes_[2] = 0x20;
  tx_.precomputed_hashes_[3] = 0x10;

  //set chunk checker map
  uint8 hash1 = 0x1;
  std::set<uint32> test_chunk_index_set;
  for (uint32 i = 0; i < tx_.num_chunks_per_block; ++i){
    tx_.ic_block_reference_free_chunks.insert(
        tx_.ic_block_reference_free_chunks.begin(), ChunkInfo(1, 1, hash1, i,0));
    test_chunk_index_set.insert(i);
    char *buffersearch = new char[50];
    sprintf_s(buffersearch, 50, "n %llu %lu", test_bb_id, i);
    tx_.label_name_to_block_[buffersearch] = std::make_pair(test_block_a, 0);
    delete[] buffersearch;
  }
  tx_.ic_chunk_checker_to_checkee_map_[test_bb_id] = test_chunk_index_set;


  tx_.AddChunkIntegrityCheckCode(bb, subgraph, bgraph);

  //Ensure basic_block_sizes_[bb_id] is larger than before
  ASSERT_GT(tx_.basic_block_sizes_[test_bb_id], old_size);
  //Check there are equal number of chunks and nrc labels
  inst_iter = bb->instructions().begin();
  uint32 nr_added_labels = 0;
  std::string chunk_pointerlabel = "nrc";
  for (; inst_iter != bb->instructions().end(); ++inst_iter){
    if (inst_iter->label().name()
        .compare(0, chunk_pointerlabel.length(), chunk_pointerlabel) == 0){
      ++nr_added_labels;
    }
  }

  //Ensure kNumChunksPerBlock == #chunks
  ASSERT_EQ(tx_.num_chunks_per_block, nr_added_labels);

  tx_.ResetTransform();
  delete bgraph;
  delete subgraph;
}

TEST_F(IntegrityCheckTransformTest, CheckAddIntegrityCheckCode) {
//check labels block, pivot, size, sub instruction
  uint64 test_bb_id = 1;
  uint64 test_checkee1_id = 2;
  uint64 test_checkee2_id = 3;
  BlockGraph *bgraph = NULL;
  BlockGraph::Block *test_block_a = NULL;
  BlockGraph::Block *test_block_b = NULL;

  bgraph = new BlockGraph();
  test_block_a = bgraph->AddBlock(BlockGraph::CODE_BLOCK, 1000, "dest_a");
  test_block_b = bgraph->AddBlock(BlockGraph::CODE_BLOCK, 1000, "dest_b");

  BasicBlockSubGraph* subgraph = new BasicBlockSubGraph();
  subgraph->set_original_block(test_block_a);
  BlockGraph::Section* code_section = bgraph->FindOrAddSection(".text",
                                                               0x60000000);

  subgraph->AddBlockDescription("test_subgraph", code_section->name(),
                                BlockGraph::CODE_BLOCK,
                                code_section->id(), 1, 0);

  BasicBlockSubGraph* subgraph_b = new BasicBlockSubGraph();
  subgraph_b->set_original_block(test_block_b);

  subgraph_b->AddBlockDescription("test_subgraph", code_section->name(),
                                  BlockGraph::CODE_BLOCK,
                                  code_section->id(), 1, 0);


  BasicCodeBlock* bb = subgraph->AddBasicCodeBlock("basic_code_block");
  auto inst_iter = bb->instructions().begin();
  block_graph::BasicBlockAssembler assm(inst_iter,
                                        &bb->instructions());

  assm.push(assm::eax);
  inst_iter = bb->instructions().begin();
  //set block id label
  auto test_block_label = BlockGraph::Label(std::to_string(test_bb_id),
                                            BlockGraph::CODE_LABEL);
  inst_iter->set_label(test_block_label);
  //prepare id to label map
  tx_.id_to_label_[test_bb_id] = test_block_label;
  //set block id label
  auto test_checkee1_label = BlockGraph::Label(std::to_string(test_checkee1_id),
                                               BlockGraph::CODE_LABEL);
  tx_.id_to_label_[test_checkee1_id] = test_checkee1_label;
  tx_.label_name_to_block_[std::to_string(test_checkee1_id)] =
      std::make_pair(test_block_b, 0);
  auto test_checkee2_label = BlockGraph::Label(std::to_string(test_checkee2_id),
                                               BlockGraph::CODE_LABEL);
  tx_.id_to_label_[test_checkee2_id] = test_checkee2_label;

  tx_.label_name_to_block_[std::to_string(test_checkee2_id)] =
      std::make_pair(test_block_b, 0);
  //set a dummy hash block
  tx_.hash_block_ = test_block_a;
  //set dummy response block
  tx_.response_block_ = test_block_a;
  //set block size
  uint32 old_size = inst_iter->size();
  tx_.basic_block_sizes_[test_bb_id] = old_size;
  tx_.basic_block_sizes_[test_checkee1_id] = 1;
  tx_.basic_block_sizes_[test_checkee2_id] = 1;
  //set checker checkee map

  std::map<uint64, int> test_checkee_map;
  test_checkee_map[test_checkee1_id] = 1;
  test_checkee_map[test_checkee2_id] = -1;
  tx_.checker_to_checkee_map_[test_bb_id] = test_checkee_map;
  tx_.precomputed_hashes_[test_checkee1_id] = 0x20;
  tx_.precomputed_hashes_[test_checkee2_id] = 0x10;

  tx_.AddIntegrityCheckCode(bb, subgraph, bgraph);

  //Ensure basic_block_sizes_[bb_id] is larger than before
  ASSERT_GT(tx_.basic_block_sizes_[test_bb_id], old_size);
  //Check there are equal number of chunks and nrc labels
  inst_iter = bb->instructions().begin();
  uint32 nr_added_block_labels = 0;
  std::string block_pointerlabel = "block";
  uint32 nr_added_size_labels = 0;
  std::string size_pointerlabel = "size";
  uint32 nr_added_pivot_labels = 0;
  std::string pivot_pointerlabel = "Pivot";
  uint32 nr_added_sub_labels = 0;
  std::string sub_pointerlabel = "sub";
  for (; inst_iter != bb->instructions().end(); ++inst_iter){
    if (inst_iter->label().name()
        .compare(0, block_pointerlabel.length(), block_pointerlabel) == 0){
      ++nr_added_block_labels;
    } else if (inst_iter->label().name()
      .compare(0, size_pointerlabel.length(), size_pointerlabel) == 0){
      ++nr_added_size_labels;
    }
    else if (inst_iter->label().name().compare(0, pivot_pointerlabel.length(),
                                               pivot_pointerlabel) == 0){
        ++nr_added_pivot_labels;
    } else if (inst_iter->label().name().compare(0, sub_pointerlabel.length(),
                                                 sub_pointerlabel) == 0){
        ++nr_added_sub_labels;
    }

  }

  //Ensure kNumChunksPerBlock == #chunks
  ASSERT_EQ(test_checkee_map.size(), nr_added_block_labels);
  ASSERT_EQ(test_checkee_map.size(), nr_added_size_labels);
  ASSERT_EQ(1, nr_added_pivot_labels);
  ASSERT_EQ(1, nr_added_sub_labels);

  tx_.ResetTransform();
  delete bgraph;
  delete subgraph;
  delete subgraph_b;
}

TEST_F(IntegrityCheckTransformTest, CheckComputeChunksWhenInstructionHasLabel) {
  uint64 test_bb_id = 1;
  BlockGraph *bgraph = NULL;
  BlockGraph::Block *test_block_a = NULL;

  bgraph = new BlockGraph();
  test_block_a = bgraph->AddBlock(BlockGraph::CODE_BLOCK, 1000, "dest_a");

  BasicBlockSubGraph* subgraph = new BasicBlockSubGraph();
  subgraph->set_original_block(test_block_a);
  BlockGraph::Section* code_section = bgraph->FindOrAddSection(".text",
                                                               0x60000000);

  subgraph->AddBlockDescription("test_subgraph", code_section->name(),
                                BlockGraph::CODE_BLOCK,
                                code_section->id(), 1, 0);

  BasicCodeBlock* bb = subgraph->AddBasicCodeBlock("basic_code_block");
  auto inst_iter = bb->instructions().begin();
  block_graph::BasicBlockAssembler assm(inst_iter,
                                        &bb->instructions());

  assm.push(assm::eax);
  assm.data(0);

  auto test_label = BlockGraph::Label(std::to_string(test_bb_id),
                                      BlockGraph::CODE_LABEL);
  inst_iter = bb->instructions().begin();
  inst_iter->set_label(test_label);
  //Every checker comes with a pivot
  ++inst_iter;
  inst_iter->set_label(BlockGraph::Label("Pivot:",
                                         BlockGraph::CODE_LABEL));

  tx_.id_to_label_[test_bb_id] = test_label;

  //make the block a checker

  uint64 test_checkee1_id = 2;
  uint64 test_checkee2_id = 3;
  std::map<uint64, int> test_checkee_map;
  test_checkee_map[test_checkee1_id] = 1;
  test_checkee_map[test_checkee2_id] = -1;
  tx_.checker_to_checkee_map_[test_bb_id] = test_checkee_map;
  tx_.precomputed_hashes_[test_checkee1_id] = 0x20;
  tx_.precomputed_hashes_[test_checkee2_id] = 0x10;


  tx_.ComputeChunks(bb);

  //on instructions with label don't set chunk label
  ASSERT_EQ(0, tx_.ic_block_reference_free_chunks.size());

  tx_.ResetTransform();
  delete bgraph;
  delete subgraph;
}
TEST_F(IntegrityCheckTransformTest, CheckComputeChunksWhenLastInstruction) {
  uint64 test_bb_id = 1;
  BlockGraph *bgraph = NULL;
  BlockGraph::Block *test_block_a = NULL;

  bgraph = new BlockGraph();
  test_block_a = bgraph->AddBlock(BlockGraph::CODE_BLOCK, 1000, "dest_a");

  BasicBlockSubGraph* subgraph = new BasicBlockSubGraph();
  subgraph->set_original_block(test_block_a);
  BlockGraph::Section* code_section = bgraph->FindOrAddSection(".text",
                                                               0x60000000);

  subgraph->AddBlockDescription("test_subgraph", code_section->name(),
                                BlockGraph::CODE_BLOCK,
                                code_section->id(), 1, 0);

  BasicCodeBlock* bb = subgraph->AddBasicCodeBlock("basic_code_block");
  auto inst_iter = bb->instructions().begin();
  block_graph::BasicBlockAssembler assm(inst_iter,
                                        &bb->instructions());

  assm.push(assm::eax);
  assm.data(0);
  assm.push(assm::ebx);

  auto test_label = BlockGraph::Label(std::to_string(test_bb_id),
                                      BlockGraph::CODE_LABEL);
  inst_iter = bb->instructions().begin();
  inst_iter->set_label(test_label);
  //Every checker comes with a pivot
  ++inst_iter;
  inst_iter->set_label(BlockGraph::Label("Pivot:",
                                         BlockGraph::CODE_LABEL));

  tx_.id_to_label_[test_bb_id] = test_label;

  //make the block a checker

  uint64 test_checkee1_id = 2;
  uint64 test_checkee2_id = 3;
  std::map<uint64, int> test_checkee_map;
  test_checkee_map[test_checkee1_id] = 1;
  test_checkee_map[test_checkee2_id] = -1;
  tx_.checker_to_checkee_map_[test_bb_id] = test_checkee_map;
  tx_.precomputed_hashes_[test_checkee1_id] = 0x20;
  tx_.precomputed_hashes_[test_checkee2_id] = 0x10;


  tx_.ComputeChunks(bb);

  //last push ebx should be recognized as a chunk
  ASSERT_EQ(1, tx_.ic_block_reference_free_chunks.size());

  tx_.ResetTransform();
  delete bgraph;
  delete subgraph;
}

TEST_F(IntegrityCheckTransformTest, CheckComputeChunksWhenAbsReferenceBetween) {
  uint64 test_bb_id = 1;
  BlockGraph *bgraph = NULL;
  BlockGraph::Block *test_block_a = NULL;

  bgraph = new BlockGraph();
  test_block_a = bgraph->AddBlock(BlockGraph::CODE_BLOCK, 1000, "dest_a");

  BasicBlockSubGraph* subgraph = new BasicBlockSubGraph();
  subgraph->set_original_block(test_block_a);
  BlockGraph::Section* code_section = bgraph->FindOrAddSection(".text",
                                                               0x60000000);

  subgraph->AddBlockDescription("test_subgraph", code_section->name(),
                                BlockGraph::CODE_BLOCK,
                                code_section->id(), 1, 0);

  BasicCodeBlock* bb = subgraph->AddBasicCodeBlock("basic_code_block");
  auto inst_iter = bb->instructions().begin();
  block_graph::BasicBlockAssembler assm(inst_iter,
                                        &bb->instructions());

  assm.push(assm::eax);
  assm.data(0);
  assm.push(assm::ebx);
  assm.push(block_graph::Immediate(test_block_a, 0));
  assm.add(assm::eax, assm::ebx);

  auto test_label = BlockGraph::Label(std::to_string(test_bb_id),
                                      BlockGraph::CODE_LABEL);
  inst_iter = bb->instructions().begin();
  inst_iter->set_label(test_label);
  //Every checker comes with a pivot
  ++inst_iter;
  inst_iter->set_label(BlockGraph::Label("Pivot:",
                                         BlockGraph::CODE_LABEL));

  tx_.id_to_label_[test_bb_id] = test_label;

  //make the block a checker

  uint64 test_checkee1_id = 2;
  uint64 test_checkee2_id = 3;
  std::map<uint64, int> test_checkee_map;
  test_checkee_map[test_checkee1_id] = 1;
  test_checkee_map[test_checkee2_id] = -1;
  tx_.checker_to_checkee_map_[test_bb_id] = test_checkee_map;
  tx_.precomputed_hashes_[test_checkee1_id] = 0x20;
  tx_.precomputed_hashes_[test_checkee2_id] = 0x10;


  tx_.ComputeChunks(bb);

  //push ebx and add eax,ebx are two chunks spearated by an abs reference
  ASSERT_EQ(2, tx_.ic_block_reference_free_chunks.size());

  //push ebx is one byte
  ASSERT_EQ(1, tx_.ic_block_reference_free_chunks[0].size_);
  //add eax,ebx is two bytes
  ASSERT_EQ(2, tx_.ic_block_reference_free_chunks[1].size_);

  tx_.ResetTransform();
  delete bgraph;
  delete subgraph;
}

TEST_F(IntegrityCheckTransformTest, CheckAddChunkIntoIndexMap) {
  uint64 test_chunk_bb_id = 1;
  uint32 test_chunk_index = 0;
  uint32 test_vector_index = 0;
  tx_.AddChunkIntoIndexMap(test_chunk_bb_id,
                           test_chunk_index,
                           test_vector_index);
  ASSERT_EQ(test_vector_index, tx_.ic_block_chunk_index_map_[
      tx_.GetChunkUniqueKey(test_chunk_bb_id, test_chunk_index)]);

  tx_.ResetTransform();
}

TEST_F(IntegrityCheckTransformTest, CheckGetChunkUniqueKey) {
  uint64 test_chunk_bb_id = 1;
  uint32 test_chunk_index = 0;
  uint64 unique_id = tx_.GetChunkUniqueKey(test_chunk_bb_id, test_chunk_index);

  ASSERT_NE(static_cast<uint64>(0), unique_id);
  tx_.ResetTransform();
}

TEST_F(IntegrityCheckTransformTest, CheckGenerateChunkCombinations) {
  //build 2 checkers in two subgraphs because chunks are assigned to different
  //subgraphs
  BlockGraph *bgraph = NULL;
  BlockGraph::Block *test_block_a = NULL;
  BlockGraph::Block *test_block_b = NULL;
  uint64 test_bb1_id = 1;
  uint64 test_bb2_id = 4;
  std::vector<ChunkInfo> test_chunks;

  bgraph = new BlockGraph();
  test_block_a = bgraph->AddBlock(BlockGraph::CODE_BLOCK, 1000, "dest_a");
  test_block_b = bgraph->AddBlock(BlockGraph::CODE_BLOCK, 1000, "dest_b");

  BasicBlockSubGraph* subgraph = new BasicBlockSubGraph();
  subgraph->set_original_block(test_block_a);
  BlockGraph::Section* code_section = bgraph->FindOrAddSection(".text",
                                                               0x60000000);

  subgraph->AddBlockDescription("test_subgraph", code_section->name(),
                                BlockGraph::CODE_BLOCK,
                                code_section->id(), 1, 0);

  BasicBlockSubGraph* subgraph_b = new BasicBlockSubGraph();
  subgraph_b->set_original_block(test_block_b);

  subgraph_b->AddBlockDescription("test_subgraph", code_section->name(),
                                  BlockGraph::CODE_BLOCK,
                                  code_section->id(), 1, 0);



  //set block id label
  auto test_block1_label = BlockGraph::Label(std::to_string(test_bb1_id),
                                            BlockGraph::CODE_LABEL);
  auto test_block2_label = BlockGraph::Label(std::to_string(test_bb2_id),
                                            BlockGraph::CODE_LABEL);
  //prepare id to label map
  tx_.id_to_label_[test_bb1_id] = test_block1_label;
  tx_.id_to_label_[test_bb2_id] = test_block2_label;


  //add chunks label
  for (uint32 i = 0; i< tx_.num_chunks_per_block; ++i) {
    std::string label = "n " + std::to_string(test_bb1_id)
        + " " + std::to_string(i);
    tx_.label_name_to_block_[label] = std::make_pair(test_block_a, 0);
    test_chunks.insert(test_chunks.begin(), ChunkInfo(test_bb1_id, 1, 1, i,0));
  }
  for (uint32 i = 0; i< tx_.num_chunks_per_block; ++i) {
    std::string label = "n " + std::to_string(test_bb2_id)
        + " " + std::to_string(i);
    tx_.label_name_to_block_[label] = std::make_pair(test_block_b, 0);
    test_chunks.insert(test_chunks.begin(), ChunkInfo(test_bb2_id, 1, 1, i,0));
  }

  tx_.label_name_to_block_[std::to_string(test_bb1_id)] =
      std::make_pair(test_block_a, 0);
  tx_.label_name_to_block_[std::to_string(test_bb2_id)] =
      std::make_pair(test_block_b, 0);

  uint64 test_checkee1_id = 2;
  uint64 test_checkee2_id = 3;
  std::map<uint64, int> test_checkee_map;
  test_checkee_map[test_checkee1_id] = 1;
  test_checkee_map[test_checkee2_id] = -1;
  tx_.checker_to_checkee_map_[test_bb1_id] = test_checkee_map;
  tx_.checker_to_checkee_map_[test_bb2_id] = test_checkee_map;

  //prepare 20 chunks from these two checkers
  //20 n labels
  float test_chunk_coverage = 0.5;
  bool test_force_all = false;
  uint32 chunk_per_block = 0;
  auto chunk_map = tx_.GenerateChunkCombinations(test_chunks,
                                                 test_chunk_coverage,
                                                 test_force_all,
                                                 &chunk_per_block
                                                 );


  ASSERT_EQ(2, chunk_map.size());
  ASSERT_EQ(5, chunk_map[test_bb1_id].size());
  ASSERT_EQ(5, chunk_map[test_bb2_id].size());
  ASSERT_EQ(5, chunk_per_block);

  //strictly picking all blocks
  test_chunk_coverage = 1;
  test_force_all = true;
  chunk_per_block = 0;
  chunk_map = tx_.GenerateChunkCombinations(test_chunks,
                                                 test_chunk_coverage,
                                                 test_force_all,
                                                 &chunk_per_block);

  ASSERT_EQ(2, chunk_map.size());
  ASSERT_EQ(10, chunk_map[test_bb1_id].size());
  ASSERT_EQ(10, chunk_map[test_bb2_id].size());
  ASSERT_EQ(10, chunk_per_block);

  tx_.ResetTransform();
  delete bgraph;
  delete subgraph;
  delete subgraph_b;
}

TEST_F(IntegrityCheckTransformTest, CheckRandomlySelectChecker) {

}

TEST_F(IntegrityCheckTransformTest, CheckIsIdInPartitionUnitMap) {

}

TEST_F(IntegrityCheckTransformTest, CheckFixAllCheckeesOfBasicBlock) {

}

TEST_F(IntegrityCheckTransformTest, CheckPatchInterBlockReferences) {

}

TEST_F(IntegrityCheckTransformTest, CheckPrecomputeHash) {

}

TEST_F(IntegrityCheckTransformTest, CheckAddReference) {

}

TEST_F(IntegrityCheckTransformTest, CheckGetBasicBlockIdByLabel) {

}

TEST_F(IntegrityCheckTransformTest, CheckTransformBasicBlockSubGraph) {

}


TEST_F(IntegrityCheckTransformTest, CheckShouldProcessBlock) {

}

TEST_F(IntegrityCheckTransformTest, CheckProcessAllBlocks) {

}

TEST_F(IntegrityCheckTransformTest, CheckGenerateBasicBlockCombinations) {

}

TEST_F(IntegrityCheckTransformTest, CheckTransformBlockGraph) {

}
}