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
#include "syzygy/experimental/protect/protect_lib/integrity_check_layout_transform.h"

//TODO: remove this include
#include <inttypes.h>

#include "syzygy/core/address.h"
#include "syzygy/experimental/protect/protect_lib/protect_utils.h"
#include "syzygy/pe/pe_file_writer.h"
#include "syzygy/pe/pe_utils.h"

namespace protect {

uint8_t IntegrityCheckLayoutTransform::ComputeAggregatedChunksHash(
  const std::set<uint32_t> chunk_indexes){
  uint8_t precomputed_xor = 0;
  for (auto chunk_it = chunk_indexes.rbegin();
       chunk_it != chunk_indexes.rend();
       ++chunk_it) {
    auto chunk_info = (*ic_block_reference_free_chunks)[*chunk_it];
    precomputed_xor += chunk_info.hash_ + chunk_info.hash_of_next_instruction_;
    precomputed_xor = -precomputed_xor;
  }
  return precomputed_xor;
}

uint8_t
IntegrityCheckLayoutTransform::ComputeAggregatedBlocksHash(uint64_t bb_id){
  uint8_t precomputed_hash = 0;
  auto checkee_iter = (*this->checker_to_checkee_map_)[bb_id].begin();
  for (; checkee_iter != (*this->checker_to_checkee_map_)[bb_id].end();
       ++checkee_iter){
    precomputed_hash += (*this->precomputed_hashes_)[checkee_iter->first] *
      checkee_iter->second;
  }
  return precomputed_hash;
}

bool IntegrityCheckLayoutTransform::RecomputePivot(
  const uint64_t bb_id,
  const uint8_t precomputed_hash,
  const uint8_t precomputed_xor,
  const size_t pivot_offset,
  const size_t sub_offset,
  block_graph::BlockGraph::Block *block){

  const uint8_t *pivot_byte = block->data() + pivot_offset;
  DCHECK(*pivot_byte == 0x00);

  const uint8_t *sub_opcode = block->data() + sub_offset;
  DCHECK(*sub_opcode == 0x2c);

  const uint8_t *hash_byte = sub_opcode + 1;
  //+1 is the sub hash value
  uint8_t new_bytes[3];
  new_bytes[0] = *pivot_byte;
  new_bytes[1] = *sub_opcode;
  new_bytes[2] = *hash_byte;

  uint8_t old_hash = *hash_byte;
  new_bytes[2] = precomputed_hash + precomputed_xor; // new hash
  const uint8_t* data = block->data();
  size_t data_size = block->data_size();
  uint8_t* new_data = new uint8_t[data_size];
  memcpy(new_data, data, data_size);

  // Set new pivot byte. Starts at offset 0
  uint8_t new_pivot = old_hash - new_bytes[2];
  new_bytes[0] = new_pivot;

  DCHECK_EQ((uint8_t)(new_pivot + precomputed_hash + precomputed_xor),
            old_hash);
  new_data[pivot_offset] = new_bytes[0];
  new_data[sub_offset + 1] = new_bytes[2];

  block->CopyData(data_size, new_data);
  delete[] new_data;

  return true;
}

bool IntegrityCheckLayoutTransform::PatchPivot(BlockGraph::Label label) {
  uint64_t bb_id = GetBasicBlockIdByLabel(label, this->id_to_label_);

  if (bb_id == -1)
    return true;

  if ((*this->checker_to_checkee_map_)[bb_id].size() < 1)
    return true;

  uint8_t precomputed_hash = ComputeAggregatedBlocksHash(bb_id);
  uint8_t precomputed_xor = 0;
  if (*perform_chunk_checks_) {
    //recompute xor hash
    auto checkee_chunks_it = ic_chunk_checker_to_checkee_map_->find(bb_id);
    DCHECK(checkee_chunks_it != ic_chunk_checker_to_checkee_map_->end());

    DCHECK_NE(checkee_chunks_it->second.size(), static_cast<uint32_t>(0));
    precomputed_xor = ComputeAggregatedChunksHash(checkee_chunks_it->second);
  }
  char  *buffer = new char[50];
  sprintf_s(buffer, 50, "Pivot:%llu", bb_id);
  // offset of sub instruction after returning from hash function
  size_t pivot_offset = (*label_name_to_block_)[buffer].second;
  auto block = (*label_name_to_block_)[buffer].first;

  sprintf_s(buffer, 50, "sub %llu", bb_id);
  // offset of sub instruction after returning from hash function
  auto sub_instr_block = label_name_to_block_->find(buffer);
  DCHECK(sub_instr_block != label_name_to_block_->end());
  size_t sub_offset = sub_instr_block->second.second;
  delete[] buffer;
  if (RecomputePivot(bb_id, precomputed_hash, precomputed_xor,
    pivot_offset, sub_offset, block)){
    this->nr_hashes_patched_++;
  }
  return true;
}

int IntegrityCheckLayoutTransform::PatchPrecomputedHashes(
    const TransformPolicyInterface* policy,
    BlockGraph::Block* block) {
  if (!ShouldPostProcessBlock(block, this->id_to_label_))
    return 0;

  // Iterate over every label in the block and patch the pivot
  auto it = block->labels().begin();
  for (; it != block->labels().end(); ++it) {
    if (!PatchPivot(it->second))
      return 0;
  }

  return 0;
}
// This function adjusts the inter-block references that have shifted after
// code was inserted
bool IntegrityCheckLayoutTransform::CheckHash(
  BasicCodeBlock* bb,
  std::vector<uint8_t> new_block_buffer,
  const core::AbsoluteAddress image_base) {
  auto inst_iter = bb->instructions().begin();
  uint64_t bb_id = (uint64_t)-1;
  if ((inst_iter != bb->instructions().end()) && (inst_iter->has_label())) {
    bb_id = GetBasicBlockIdByLabel(inst_iter->label(), this->id_to_label_);
    if (bb_id != -1) {
      auto buf_it = new_block_buffer.begin();
      std::advance(buf_it, bb->offset());

      uint8_t hash = 0;
      uint32_t block_size = (*this->basic_block_sizes_)[bb_id];
      for (uint32_t i = 0; i < block_size; ++i) {
        hash += *buf_it;
        if (i % 16 == 0)
          fprintf(phash, "\n");
        else if (i % 8 == 0)
          fprintf(phash, " ");
        fprintf(phash, "%02X ", *buf_it);
        ++buf_it;
      }
      // Compute hash of image_base.
      uint8_t hash_image_base = 0;
      for (uint8_t i = 0; i < 4; i++) {
        hash_image_base += image_base.value() >> (i*8);
      }

      // For each chunk or checkee subtract hash of image base.
      uint8_t nr_checkees = (*this->checker_to_checkee_map_)[bb_id].size() +
        (*ic_chunk_checker_to_checkee_map_)[bb_id].size();
      hash -= hash_image_base * nr_checkees;

      uint8_t precompute_hash = (*this->precomputed_hashes_)[bb_id];
      if (precompute_hash != hash) {
        (*this->precomputed_hashes_)[bb_id] = hash;
      }

      fprintf(phash, "\n%s,", bb->subgraph()->original_block()->name().c_str());
      fprintf(phash, "%" PRIx64 ",", bb_id);
      fprintf(phash, "%" PRIx32 ",",
	          bb->subgraph()->original_block()->addr().value() + bb->offset());
      fprintf(phash, "%" PRIx8 "\n", hash);
    } //end if
  } //end if

  //We need to compute hash of the chunks whose last instruction has absolute
  // address. If there is no chunk checking this step is not needed.
  if (!*perform_chunk_checks_) return true;

  std::string chunk_pointerlabel = "n ";
  auto end_block = bb->instructions().end();
  uint64_t chunk_bb_id;
  uint32_t chunk_index;
  uint32_t offset = bb->offset();
  for (; inst_iter != end_block; ++inst_iter)
  {
    offset += inst_iter->size();
    if (!inst_iter->has_label())  continue;

    if (inst_iter->label().name()
        .compare(0, chunk_pointerlabel.length(), chunk_pointerlabel) == 0){
      // update last visited chunk index
      GetChunkTokensFromlabel(inst_iter->label().name(),
                              &chunk_bb_id,
                              &chunk_index);

      size_t unique_key = GetChunkUniqueKey(chunk_bb_id, chunk_index);

      uint32_t vector_index = (*ic_block_chunk_index_map_)[unique_key];

      DCHECK_GE(vector_index, static_cast<uint32_t>(0));
      DCHECK_LT(vector_index, ic_block_reference_free_chunks->size());

      auto chunk = (*ic_block_reference_free_chunks)[vector_index];
      DCHECK(chunk.block_id_ == chunk_bb_id);
      DCHECK(chunk.chunk_index_ == chunk_index);
      //we need to recompute chunks whose last instruction has absoloute address
      if (chunk.next_instruction_size_ == 0) continue;

      uint32_t chunk_offset = offset + chunk.size_ - inst_iter->size();

      auto buf_it = new_block_buffer.begin();
      std::advance(buf_it, chunk_offset);

      uint8_t hash = 0;
      for (uint32_t i = 0; i < chunk.next_instruction_size_; ++i) {
        hash += *buf_it;
        ++buf_it;
      }

      chunk.hash_of_next_instruction_ = hash;
      (*ic_block_reference_free_chunks)[vector_index] = chunk;
    }
  }

  return true;
}

bool IntegrityCheckLayoutTransform::FixPrecomputedHashes(
    const TransformPolicyInterface* policy,
    const core::AbsoluteAddress image_base,
    BlockGraph::Block* block,
    std::vector<uint8_t> new_block_buffer) {

  if (!ShouldPostProcessBlock(block, this->id_to_label_))
    return false;

  // Use the decomposition policy to skip blocks that aren't eligible for
  // basic-block decomposition.
  if (!policy->BlockIsSafeToBasicBlockDecompose(block))
    return false;

  // Decompose block to basic blocks.
  BasicBlockSubGraph *subgraph = new BasicBlockSubGraph();
  BasicBlockDecomposer bb_decomposer(block, subgraph);
  if (!bb_decomposer.Decompose())
    return false;

  BasicBlockSubGraph::BBCollection& basic_blocks =
    subgraph->basic_blocks(); // set of BB to protect

  // Iterate over every basic block and recompute the hash
  for (auto it = basic_blocks.begin(); it != basic_blocks.end(); ++it) {
    BasicCodeBlock* bb = BasicCodeBlock::Cast(*it);

    if (bb == NULL)
      continue;

    CheckHash(bb, new_block_buffer, image_base);
  }

  return true;
}

bool IntegrityCheckLayoutTransform::TransformImageLayout(
    const TransformPolicyInterface* policy,
    const pe::ImageLayout* image_layout,
    const OrderedBlockGraph* ordered_block_graph) {
  pe::PEFileWriter writer(*image_layout);

  if (!writer.ValidateHeaders())
    return false;

  if (!writer.CalculateSectionRanges())
    return false;

  core::AbsoluteAddress* image_base = writer.GetImageBase();

  // Create the output buffer, reserving enough room for the whole file.
  DCHECK(!image_layout->sections.empty());
  size_t image_size = writer.GetImageSize();
  std::vector<uint8_t> buffer;
  buffer.reserve(image_size);

  // Iterate through all blocks in the address space writing them as we go.
  BlockGraph::AddressSpace::RangeMap::const_iterator block_it2(
    image_layout->blocks.address_space_impl().ranges().begin());
  BlockGraph::AddressSpace::RangeMap::const_iterator block_end(
    image_layout->blocks.address_space_impl().ranges().end());

  BlockGraph::AddressSpace::RangeMap::const_iterator block_it(
    image_layout->blocks.address_space_impl().ranges().begin());

  BlockGraph::SectionId section_id = BlockGraph::kInvalidSectionId;
  size_t section_index = BlockGraph::kInvalidSectionId;

  // TODO: remove file
  phash = fopen("phash.txt", "w");
  fprintf(phash, "Block name, BBid, Address, hash\n");

  for (; block_it != block_end; ++block_it) {
    BlockGraph::Block* block =
      const_cast<BlockGraph::Block*>(block_it->second);

    // If we're jumping to a new section output the necessary padding.
    if (block->section() != section_id) {
      writer.FlushSection(section_index, &buffer);
      section_id = block->section();
      section_index++;
      DCHECK_GT(image_layout->sections.size(), section_index);
    }

    core::FileOffsetAddress size_before(buffer.size());

    if (!writer.WriteOneBlock(*image_base, section_index, block,
      &buffer, &size_before)) {
      LOG(ERROR) << "Failed to write block \"" << block->name() << "\".";
      return false;
    }

    // compute new hash value of block
    auto buf_it = buffer.begin();
    std::advance(buf_it, size_before.value());
    std::vector<uint8_t> new_block_buffer(buf_it, buffer.end());

    // Compute the new hash values inside buffer
    FixPrecomputedHashes(policy, *image_base, block, new_block_buffer);
  } // end for

  fclose(phash);

  block_it = image_layout->blocks.address_space_impl().ranges().begin();
  for (; block_it != block_end; ++block_it) {
    BlockGraph::Block* block =
      const_cast<BlockGraph::Block*>(block_it->second);
    // patch the hash values in-place
    PatchPrecomputedHashes(policy, block);
  }

  return true;
}

// static vars
const char IntegrityCheckLayoutTransform::kTransformName[] =
  "IntegrityCheckLayoutTransform";
} // namespace protect