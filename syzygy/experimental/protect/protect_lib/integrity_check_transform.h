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

#ifndef SYZYGY_PROTECT_PROTECT_LIB_INTEGRITY_CHECK_TRANSFORM_H_
#define SYZYGY_PROTECT_PROTECT_LIB_INTEGRITY_CHECK_TRANSFORM_H_

#define _SILENCE_STDEXT_HASH_DEPRECATION_WARNINGS 1

#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/block_graph/transforms/named_transform.h"
#include "syzygy/experimental/protect/protect_lib/protect_utils.h"

namespace protect {

class IntegrityCheckTransform
  : public block_graph::transforms::
  NamedBlockGraphTransformImpl<IntegrityCheckTransform> {
 public:
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::BasicCodeBlock BasicCodeBlock;
  typedef block_graph::BasicBlockSubGraph BasicBlockSubGraph;
  typedef block_graph::TransformPolicyInterface TransformPolicyInterface;

  enum ProcessingType {
   ADD_HASH_AND_RESPONSE,
   PRECOMPUTE_HASHES,
   INSERT_CHECKS,
   COMPUTE_CHUNKS,
   INSERT_CHUNK_CHECKS,
   PATCH_REFERENCES_SIZES,
   PATCH_PIVOT
  };

  enum ReferenceLabelType {
   Original_Block_Chunk,
 //Refers to a placeholder label that only after adding all integrity checks
 //it will be determined
   Integrity_Block_Chunk
  };

// The transform name.
  static const char kTransformName[];

// Constructor.
  explicit IntegrityCheckTransform(FlummoxConfig* config) {
    for (const std::string& target : config->target_set())
      target_names_[target] = false;

    this->chunk_checking_coverage = config->chunk_checking_coverage();
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
    this->chunk_checking_coverage = config->chunk_checking_coverage();
  }

// This is the main body of the transform. The transform decomposes each
// block into a subgraph, applies the series of transform and rebuilds the
// subgraph into a block.
//
// @param policy The policy object restricting how the transform is applied.
// @param block_graph the block graph being transformed.
// @param header_block the block to process.
// @returns true on success, false otherwise.
  virtual bool TransformBlockGraph(const TransformPolicyInterface* policy,
                                   BlockGraph* block_graph,
                                   BlockGraph::Block* header_block) override;

  ~IntegrityCheckTransform();

 protected:
  // Replaces the first basic block reference inside an instruction @p with a
  // reference to a new block.
  // @param inst_itr the instruction that contains the basic block reference.
  // @param new_block the block to which the new reference should point to.
  // @param new_offset the offset to which the new reference should have.
  // @param use_new_block flag indicating whether the new_block should be used.
  void PatchBlockReference(
    block_graph::BasicBlock::Instructions::iterator inst_itr,
    block_graph::BlockGraph::Block* new_block,
    block_graph::BlockGraph::Offset new_offset,
    bool use_new_block);

// Constant value defining unique chunks should be selected in the chunk
// combinator function
  const bool kForceUniqueChunks = true;

// Constant value defining the number of chunks within original block
// that each checker must check
  uint32_t num_chunks_per_block = 0;

  bool* perform_chunk_checks_;
  float chunk_checking_coverage =1.0f;

  // Creates a label to block map for all blocks in block graph @p.
  void GenerateLabelToBlockMap(BlockGraph *bgraph);

// Update label to block map only with changes in the given block @p.
  void UpdateLabelToBlockMap(BlockGraph::Block *block);

// Computes and writes the Q matrix to an output file. Also generates
// combinations of basic blocks such that references to absolute addresses
// cancel out. Finally it picks a random basic block to dynamically check
// if the combination of precomputed hashes matches the runtime hashes.
  void GenerateBasicBlockCombinations();

// Assigns random chunks(without absolute references) to basic blocks
//@chunks_vector - input proccessed chunks for assignment
//@assignment_map - output assigned chunks per basic block
//@no_chunks_per_checker - defines the number of chunks
// that being assigned to a checker
//@force_all_chunk_checks - This removes selected chunks from the random list
//so they cannot be picked more than once
  std::map<uint64_t, std::set<uint32_t>> GenerateChunkCombinations(
      const std::vector<ChunkInfo> chunks_vector,
      const float chunk_coverage, const bool enforce_unique_chunks,
      uint32_t *no_chunks_per_block);

// Iterates over all blocks of the block graph and decomposes them into
// basic block subgraphs, which are then processed individually according
// to the step parameter. The file parameter is optionally used to store
// results of the processing.
  bool IntegrityCheckTransform::ProcessAllBlocks(
   const TransformPolicyInterface* policy,
   BlockGraph* block_graph,
   IntegrityCheckTransform::ProcessingType step);


// Adds the assembly code which performs the integrity check
// @param bb - the basic block where the integrity check will be inserted
// @param checked_bb - the basic block that is actually checked
// @param offset_sizes a list of (offset, size) pairs that indicate at which
//        offset from the beginning of the BB and how many bytes to hash
// @param hash the value of the precomputed code hash
// @param placeholder_flag a flag indicating if we need to insert
//        a placeholder in this basic block or not
  void AddIntegrityCheckCode(BasicCodeBlock* bb,
                             BasicBlockSubGraph* subgraph,
                             BlockGraph *block_graph);


// Process the basic block subgraph inserting the hash function and the
// integrity-checks
// @param bgraph - block graph from where the subgraph was taken
// @param subgraph - subgraph containing basic blocks we want to transform
// @param modifyCode - flag that indicates whether the PE should be modified
// @return - true if the transformation was successfull, false otherwise
  bool TransformBasicBlockSubGraph(
      BlockGraph* bgraph,
      BasicBlockSubGraph* subgraph,
      IntegrityCheckTransform::ProcessingType step);

// Adds reference to address
// @param bgraph - the block graph from where the subgraph was taken
// @param block - block where to make the reference
// @param offset - offset of reference in block
// @return the block containing the response function
  BlockGraph::Block* AddReference(BlockGraph* bgraph, int dll_id);

// Adds vector index of a chunk into the chunk index map
// this index map is useful in chunk patching, basically O(n) to O(log(n))
// @param bb_id - basic block id where the chunk is located
// @param chunk_index - index of the chunk within the basic block
// @param vector_index - index of the chunk within the full chunks vector
  void  IntegrityCheckTransform::AddChunkIntoIndexMap(
      const uint64_t bb_id,
      const uint32_t chunk_index,
      const uint32_t vector_index);

// Iterates over instructions and places label over reference free
// chunks. Appends discovered chunks references to
// ic_block_reference_free_chunks
// @bb_id - integrity checker block id
// @bb_instruction - reference to basic block instruction set
  void ComputeChunks(BasicCodeBlock* bb);
// Retrieves the original block id that chunk is located in, this function
// relies on the label_name_to_block_ map
// @chunk - instruction chunk info to find its original block
  uint64_t GetChunkOriginalBlockId(const ChunkInfo *chunk);

// Selects chunks from the provided partition index from blocks different from
// the checker block. It tries to use unique chunks, but if not enough chunks to
// pick, it reuses the used chunks
// @chunks_vector - vector of all chunks
// @partition_indexes - the indexes that chunk can be selected from
//                     (partitioning)
// @num_picks - number of chunks to be picked
// @checker_block_id - original block of the checker
// @used - map of the used chunks
  std::set<uint32_t> IntegrityCheckTransform:: PickChunks(
      const std::vector<ChunkInfo> chunks_vector,
      const std::vector<uint32_t> partition_indexes,
      const uint32_t num_picks,
      const uint64_t checker_block_id,
      const std::vector<uint32_t>::iterator end_chunk_it,
      std::vector<uint32_t>::iterator last_visited_chunk,
      std::set<uint32_t> *unused_chunks);
// Computes the hash that will be hard coded in the binary
// @param bb - basic block for which we want to compute the hash
// @param offset_sizes - list containing pairs of offsets and number of bytes
//   to hash by the hash function in order to obtain the same hash at runtime
// @return - the hash value of the code
  uint8_t PrecomputeHash(BasicCodeBlock* bb,
                         std::list<uint32_t> *offset_sizes,
                         BasicBlockSubGraph* subgraph);

  // Retrieves the number of absolute references in the basic block indicated
  // by @p. This coincides with its index in the partition map.
  uint8_t IntegrityCheckTransform::GetPartitionKey(uint64_t bb_id);

// Adds the assembly code which performs the chunk integrity check
// @param bb - the basic block where the integrity check will be inserted
// @param bgraph - block graph from where the subgraph was taken
// @param subgraph - subgraph containing basic blocks we want to transform
  bool AddChunkIntegrityCheckCode(
      BasicCodeBlock* bb,
      BasicBlockSubGraph* subgraph,
      BlockGraph *block_graph);

// Patches block references and sizes within the integrity checker assembly code
// @param bb - the basic block where the patching will be done
// @param bgraph - block graph from where the subgraph was taken
// @param subgraph - subgraph containing basic blocks we want to transform
  bool PatchBlockReferencesAndSizes(
      BasicCodeBlock* bb,
      BasicBlockSubGraph* subgraph,
      BlockGraph *block_graph);

// Updates the chunk's hash corresponding to the given inputs
// with the value changes
// @param bb - the basic block where the patching will be done
// @param old_size - previous size value in included in the chunk
// @param new_size - replacement size value for the chunk
// @param chunk_bb_id - bb_id of the chunk
// @param chunk_index - index of the chunk within the basic block
  bool RecomputeXorChunks(
      const uint64_t bb_id, const uint8_t old_size[], const uint8_t new_size[],
      const uint64_t chunk_bb_id, const uint32_t chunk_index);

// Randomly picks a basic block to check-the given tuple of basic blocks.
// Outputs the id of the basic block that was picked.
  bool RandomlySelectChecker(std::list<uint32_t> tuple_blocks,
                             uint64_t *checker_id);

// Randomly assigns checkers to checkee tuples
  void PopulateCheckMaps(std::set<uint64_t> part_block);

// Checks if all basic blocks in the given map are protected by integrity
// checks
  bool AllBasicBlocksChecked(std::map<std::set<uint64_t>, int> checkOrder);

// Fills in the partition key multiset with names of the references.
// @param instr assembly instruction references to basic blocks.
// @param partitionKey set to fill out.
// @return true if the instruction has references, false otherwise.
  bool PopulatePartitionKey(const block_graph::Instruction instr,
                            uint8_t *num_abs_references);

// Reference to the block that begins the computation of code hashes
  block_graph::BlockGraph::Block *hash_block_;

// Reference to the block that begins the computation of code xor hashes
  block_graph::BlockGraph::Block *xhash_block_;

// Reference to the block where the call to the reponse function is
  block_graph::BlockGraph::Block *response_block_;

// Map of original custom basic block ID to a label
  std::map<uint64_t, BlockGraph::Label>* id_to_label_;

// Map holding partition of relocation affected blocks
  std::map<uint8_t, std::set<uint64_t>> partition_map_;

// Map holding precomputed hashes of original BB
  std::map<uint64_t, uint32_t>* precomputed_hashes_;

// Map from BB address to its size
  std::map<uint64_t, uint32_t>* basic_block_sizes_;

// Map containing the offset of the call to the hash function in the bb
  std::map<uint64_t, uint32_t> basic_block_hash_call_offset_;

// Map containing true if basic block has a refenrece to another block
  std::map<uint64_t, bool> basic_block_has_ref_;

// Map indicating which BB is checked by which other BBs
  std::map<uint64_t, uint32_t> is_bb_checked_map_;

// Map indicating which BBs will be hashed by the checker
  std::map<uint64_t, std::map<uint64_t, int>>* checker_to_checkee_map_;

// Vector indicating chunks within Integrity checker block without absolute
// references
  std::vector<ChunkInfo>* ic_block_reference_free_chunks;
// Map for retrieveing chunk id(unit32) from  bb_id + chunk_index
// useful in patching bb chunks
  std::map<uint64_t, uint32_t>* ic_block_chunk_index_map_;

// Map< CheckerId, set < Chunk indexes > >
  std::map<uint64_t, std::set<uint32_t>>* ic_chunk_checker_to_checkee_map_;

// File where to put the Q matrix
  FILE *prefile_;
  FILE *pfile_;
  FILE *insert_file_= NULL;
  FILE *fix_file_;

// TODO: remove vector of BBSGs
  std::vector<block_graph::BasicBlockSubGraph*> subgraph_vector_;

// Map of label name to the number of bytes all references to it should be
// adjusted
  std::map<BlockGraph::Label, uint32_t> adjust_label_by_offset_;

// This attribute keeps track of the address range that should be protected
// by integrity-checks
  std::map<std::string, bool> target_names_;


// Number of precomputed hash values which were patched
  int* nr_hashes_patched_;

  uint32_t num_no_chunk_patched_labels = 0;
  uint32_t num_no_chunk_labels = 0;
  uint32_t num_chunk_reference_labels = 0;
  uint32_t num_chunk_reference_patched_labels = 0;

  uint32_t num_xor_labels = 0;
  uint32_t num_xor_patched_labels = 0;

  uint32_t num_size_reference_labels = 0;
  uint32_t num_size_reference_patched_labels = 0;

  double elapsed_secs_in_patching_chunks = 0;

// Map from ID of DLL to BlockReference
  std::map<int, std::pair<uint32_t, size_t>> dll_id_to_block_reference_;

  std::map<std::string, std::pair<BlockGraph::Block*, uint32_t>>*
   label_name_to_block_;
 private:
  DISALLOW_COPY_AND_ASSIGN(IntegrityCheckTransform);
 };

}// namespace protect

#endif// SYZYGY_PROTECT_PROTECT_LIB_INTEGRITY_CHECK_TRANSFORM_H_