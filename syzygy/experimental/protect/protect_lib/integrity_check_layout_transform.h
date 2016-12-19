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

#ifndef SYZYGY_PROTECT_PROTECT_LIB_INTEGRITY_CHECK_LAYOUT_TRANSFORM_H_
#define SYZYGY_PROTECT_PROTECT_LIB_INTEGRITY_CHECK_LAYOUT_TRANSFORM_H_

#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/basic_block_decomposer.h"
#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/block_graph/ordered_block_graph.h"
#include "syzygy/block_graph/transforms/named_transform.h"
#include "syzygy/experimental/protect/protect_lib/protect_utils.h"

namespace protect {

class IntegrityCheckLayoutTransform
  : public block_graph::transforms::
  NamedImageLayoutTransformImpl<IntegrityCheckLayoutTransform> {
 public:
  typedef block_graph::BasicBlockDecomposer BasicBlockDecomposer;
  typedef block_graph::BasicBlockSubGraph BasicBlockSubGraph;
  typedef block_graph::BasicCodeBlock BasicCodeBlock;
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::OrderedBlockGraph OrderedBlockGraph;
  typedef block_graph::TransformPolicyInterface TransformPolicyInterface;

  // The transform name.
  static const char kTransformName[];

  // Constructor.
  explicit IntegrityCheckLayoutTransform(FlummoxConfig* config)
  {
    for (const std::string& target : config->target_set())
      target_names_[target] = false;

    this->chunk_checking_coverage =config->chunk_checking_coverage();
    if (chunk_checking_coverage == 0.0f){
      bool *pcc = config->perform_chunk_checks();
      *pcc = false;
    }
    this->basic_block_sizes_ = config->basic_block_sizes();
    this->checker_to_checkee_map_ = config->checker_to_checkee_map();
    this->ic_block_chunk_index_map_ = config->ic_block_chunk_index_map();
    this->ic_block_reference_free_chunks =
	  config->ic_block_reference_free_chunks();
    this->ic_chunk_checker_to_checkee_map_ =
	  config->ic_chunk_checker_to_checkee_map();
    this->id_to_label_ = config->id_to_label();
    this->label_name_to_block_ = config->label_name_to_block();
    this->nr_hashes_patched_ = config->nr_hashes_patched();
    this->perform_chunk_checks_ = config->perform_chunk_checks();
    this->precomputed_hashes_ = config->precomputed_hashes();
  }

  //
  virtual bool TransformImageLayout(
    const TransformPolicyInterface* policy,
    const pe::ImageLayout* image_layout,
    const OrderedBlockGraph* ordered_block_graph);

 private:
  uint8_t ComputeAggregatedChunksHash(const std::set<uint32_t> chunk_indexes);
  uint8_t ComputeAggregatedBlocksHash(uint64_t bb_id);

  bool IntegrityCheckLayoutTransform::RecomputePivot(
    const uint64_t bb_id,
    const uint8_t precomputed_hash,
    const uint8_t precomputed_xor,
    const size_t pivot_offset,
    const size_t sub_offset,
    block_graph::BlockGraph::Block *block);

  // Patches pivot byte within the integrity checker assembly code
  // this will maintain the cylcic relations, e.g. A->B,B->A
  // (-> stands for checking) given some value changes in block A,
  // the precomputed hash by B becomes invalid recomputation of which makes A's
  // precomputed hash invalid. Therefore, it's impossible to maintain both
  // hashes valid. We use a pivot to preserve the previously computed hash by
  // checker blocks. Precomputed hash + pivot = Initially precomputed hash
  // @param bb - the basic block where the patching will be done
  // @param subgraph - subgraph containing basic blocks we want to transform
  bool PatchPivot(BlockGraph::Label label);
  //
  virtual int PatchPrecomputedHashes(
    const TransformPolicyInterface* policy,
    BlockGraph::Block* block);

  //
  virtual bool FixPrecomputedHashes(const TransformPolicyInterface* policy,
                                    const core::AbsoluteAddress image_base,
                                    BlockGraph::Block* block,
                                    std::vector<uint8_t> new_block_buffer);

  //
  bool CheckHash(block_graph::BasicCodeBlock* bb,
                 std::vector<uint8_t> new_block_buffer,
                 const core::AbsoluteAddress image_base);

  //TODO: remove file
  FILE* phash;

  // This attribute keeps track of the address range that should be protected
  // by integrity-checks
  std::map<std::string, bool> target_names_;

  // Map indicating which BBs will be hashed by the checker
  std::map<uint64_t, std::map<uint64_t, int>> *checker_to_checkee_map_;

  // Vector indicating chunks within Integrity checker block without absolute
  //  references
  std::vector<ChunkInfo> *ic_block_reference_free_chunks;
  // Map for retrieveing chunk id(unit32) from  bb_id + chunk_index
  // useful in patching bb chunks
  std::map<uint64_t, uint32_t> *ic_block_chunk_index_map_;

  // Map< CheckerId, set < Chunk indexes > >
  std::map<uint64_t, std::set<uint32_t>> *ic_chunk_checker_to_checkee_map_;

  // Map holding precomputed hashes of original BB
  std::map<uint64_t, uint32_t> *precomputed_hashes_;

  // Map from BB address to its size
  std::map<uint64_t, uint32_t> *basic_block_sizes_;

  //
  std::map<std::string, std::pair<BlockGraph::Block*, uint32_t>>
    *label_name_to_block_;

  // Map of original custom basic block ID to a label
  std::map<uint64_t, BlockGraph::Label> *id_to_label_;

  //
  bool *perform_chunk_checks_;
  float chunk_checking_coverage = 1.0f;

  // Number of precomputed hash values which were patched
  int *nr_hashes_patched_;

  DISALLOW_COPY_AND_ASSIGN(IntegrityCheckLayoutTransform);
};

}// namespace protect

#endif// SYZYGY_PROTECT_PROTECT_LIB_INTEGRITY_CHECK_LAYOUT_TRANSFORM_H_