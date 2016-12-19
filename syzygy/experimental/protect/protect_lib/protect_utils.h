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

#ifndef SYZYGY_PROTECT_PROTECT_LIB_PROTECT_UTILS_H_
#define SYZYGY_PROTECT_PROTECT_LIB_PROTECT_UTILS_H_

#include "syzygy/block_graph/block_graph.h"

namespace protect {

typedef block_graph::BlockGraph BlockGraph;

// TODO: private members and public getters / setters
struct ChunkInfo {

  ChunkInfo(uint64_t block_id, uint32_t size, uint8_t hash,
            uint32_t chunk_index, uint32_t next_instruction_size) :
            block_id_(block_id), size_(size), hash_(hash),
            chunk_index_(chunk_index), next_instruction_size_(next_instruction_size),
            hash_of_next_instruction_(0),
            original_block_id_(0){};

  bool operator< (const ChunkInfo& e) const {
    if (this->block_id_ < e.block_id_) {
      return true;

    }
    else if (this->block_id_ == e.block_id_) {
      if (this->size_ < e.size_) {
        return true;

      }
      else if (this->size_ == e.size_) {
        if (this->hash_ < e.hash_) {
          return true;

        }
        else if (this->hash_ == e.hash_) {
          if (this->chunk_index_ < e.chunk_index_)
            return true;
        }
      }
    }

    return false;
  }

  uint64_t block_id_;
  uint32_t size_;
  uint32_t chunk_index_;
  mutable uint8_t hash_;
  uint32_t next_instruction_size_;
  uint8_t hash_of_next_instruction_;
  mutable uint64_t original_block_id_;
}; // struct ChunkInfo

// Checks if the block @p is in the map @p and if its entry is set to true.
// @param block the block that is to be checked.
// @param target_names a map of block names to a boolean value indicating if
//                     this block should be process or not.
// @return true if this block @p is in map @p, false otherwise.
bool ShouldProcessBlock(const BlockGraph::Block* block,
                        const std::map<std::string, bool> target_names);

bool ShouldPostProcessBlock(
    const BlockGraph::Block* block,
    const std::map<uint64_t, BlockGraph::Label> *id_to_label);

// Retrieves a unique ID for a BB, which is marked with label @p
// @param label to search for
// @param a map of BB IDs to labels
// @return a unique ID for the basic block, -1 if not found
uint64_t GetBasicBlockIdByLabel(
    const BlockGraph::Label label,
    const std::map<uint64_t, BlockGraph::Label> *id_to_label);

//
void GetChunkTokensFromlabel(const std::string label,
                             uint64_t *chunk_bb_id,
                             uint32_t *chunk_index);

//
uint64_t GetChunkUniqueKey(const uint64_t bb_id, const uint32_t chunk_index);

class FlummoxConfig {
public:
  FlummoxConfig() : add_copy_(false) { }
  ~FlummoxConfig() { }

  // Loads (from a JSON string) configurations for the flummox instrumenter.
  // The contents of the 'json' string should follow the format below:
  // {
  //   "targets": {
  //     "function_name1": [],
  //     "function_name2": [],
  //     ...
  //   },
  //   "add_copy": true|false
  // }
  // @param json A JSON string containing the configuration following the
  //     format described above.
  // @param path Path to a JSON file, to use a file instead of a string.
  // @returns True if the operation succeeded, false otherwise.
  // @{
  bool ReadFromJSON(const std::string& json);
  bool ReadFromJSONPath(const base::FilePath& path);
  // @}

  // Accessors
  // @{
  const std::set<std::string>& target_set() const { return target_set_; }

  bool add_copy() const { return add_copy_; }

  const float chunk_checking_coverage() const {
    return chunk_checking_coverage_;
  }

  std::map<uint64_t, std::map<uint64_t, int>>* checker_to_checkee_map() {
    return &checker_to_checkee_map_;
  }

  std::vector<protect::ChunkInfo>* ic_block_reference_free_chunks() {
    return &ic_block_reference_free_chunks_;
  }

  std::map<uint64_t, uint32_t>* ic_block_chunk_index_map() {
    return &ic_block_chunk_index_map_;
  }

  std::map<uint64_t, std::set<uint32_t>>* ic_chunk_checker_to_checkee_map() {
    return &ic_chunk_checker_to_checkee_map_;
  }

  std::map<uint64_t, uint32_t>* precomputed_hashes() {
    return &precomputed_hashes_;
  }

  std::map<uint64_t, uint32_t>* basic_block_sizes() {
    return &basic_block_sizes_;
  }

  std::map<std::string, std::pair<BlockGraph::Block*, uint32_t>>*
    label_name_to_block() {
    return &label_name_to_block_;
  }

  std::map<uint64_t, BlockGraph::Label>* id_to_label() {
    return &id_to_label_;
  }

  bool* perform_chunk_checks() {
    return &perform_chunk_checks_;
  }

  int* nr_hashes_patched() {
    return &nr_hashes_patched_;
  }
  // @}


protected:
  std::set<std::string> target_set_;
  bool add_copy_;
  float chunk_checking_coverage_ = 1.0f;
  // Map indicating which BBs will be hashed by the checker
  std::map<uint64_t, std::map<uint64_t, int>> checker_to_checkee_map_;

  // Vector indicating chunks within Integrity checker block without absolute references
  std::vector<protect::ChunkInfo> ic_block_reference_free_chunks_;
  // Map for retrieveing chunk id(unit32) from  bb_id + chunk_index
  // useful in patching bb chunks
  std::map<uint64_t, uint32_t> ic_block_chunk_index_map_;

  // Map< CheckerId, set < Chunk indexes > >
  std::map<uint64_t, std::set<uint32_t>> ic_chunk_checker_to_checkee_map_;

  // Map holding precomputed hashes of original BB
  std::map<uint64_t, uint32_t> precomputed_hashes_;

  // Map from BB address to its size
  std::map<uint64_t, uint32_t> basic_block_sizes_;

  //
  std::map<std::string, std::pair<BlockGraph::Block*, uint32_t>>
    label_name_to_block_;

  // Map of original custom basic block ID to a label
  std::map<uint64_t, BlockGraph::Label> id_to_label_;

  //
  bool perform_chunk_checks_ = true;

  // Number of precomputed hash values which were patched
  int nr_hashes_patched_;
private:
  DISALLOW_COPY_AND_ASSIGN(FlummoxConfig);
};

} // namespace protect
#endif // SYZYGY_PROTECT_PROTECT_LIB_PROTECT_UTILS_H_