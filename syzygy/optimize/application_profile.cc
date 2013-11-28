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

#include "syzygy/optimize/application_profile.h"

#include <map>
#include <queue>

#include "syzygy/grinder/basic_block_util.h"

namespace optimize {

namespace {

using block_graph::BlockGraph;
using block_graph::BasicBlockSubGraph;
using grinder::basic_block_util::IndexedFrequencyMap;
using grinder::basic_block_util::IndexedFrequencyOffset;

typedef ApplicationProfile::BlockProfile BlockProfile;
typedef BasicBlockSubGraph::BasicBlockOrdering BasicBlockOrdering;
typedef BasicBlockSubGraph::BasicCodeBlock BasicCodeBlock;
typedef BasicBlockSubGraph::BlockDescriptionList BlockDescriptionList;
typedef BasicBlockSubGraph::BasicBlock::Successors Successors;
typedef BlockGraph::Offset Offset;
typedef core::RelativeAddress RelativeAddress;
typedef grinder::basic_block_util::EntryCountType EntryCountType;
typedef pe::ImageLayout ImageLayout;
typedef SubGraphProfile::BasicBlockProfile BasicBlockProfile;

const size_t kEntryCountColumn = 0;
const size_t kBranchTakenColumn = 1;
const size_t kMissPredColumn = 2;

// Compare two profiles. Used by STL containers.
struct BlockProfileCompare {
  bool operator()(const BlockProfile* a, const BlockProfile* b) const {
    DCHECK_NE(reinterpret_cast<const BlockProfile*>(NULL), a);
    DCHECK_NE(reinterpret_cast<const BlockProfile*>(NULL), b);

    if (a->temperature() < b->temperature())
      return true;
    if (a->temperature() > b->temperature())
      return false;
    return a->count() < b->count();
  }
};

// Retrieve a frequency in the IndexedFrequencyMap for |rva + offset, column|.
bool GetFrequencyByOffset(const IndexedFrequencyMap& frequencies,
                          const RelativeAddress& base_rva,
                          Offset offset,
                          size_t column,
                          EntryCountType* entry_count) {
  DCHECK_LE(0, offset);
  DCHECK_NE(reinterpret_cast<EntryCountType*>(NULL), entry_count);

  *entry_count = 0;
  IndexedFrequencyOffset key = std::make_pair(base_rva + offset, column);
  IndexedFrequencyMap::const_iterator it = frequencies.find(key);
  if (it != frequencies.end()) {
    *entry_count = it->second;
    return true;
  }
  return false;
}

// Retrieve the RVA of a block by looking in the image layout.
bool GetAddressOfBlock(const BlockGraph::Block* block,
                       const ImageLayout& image_layout,
                       RelativeAddress* addr) {
  DCHECK_NE(reinterpret_cast<RelativeAddress*>(NULL), addr);

  // Find the start address of the block.
  if (!image_layout.blocks.GetAddressOf(block, addr)) {
    LOG(ERROR) << "Failed to find " << block->name() << " in image layout.";
    return false;
  }

  return true;
}

}  // namespace

ApplicationProfile::ApplicationProfile(const ImageLayout* image_layout)
    : image_layout_(image_layout), global_temperature_(0.0) {
  empty_profile_.reset(new BlockProfile());
}

const BlockProfile* ApplicationProfile::GetBlockProfile(
    const BlockGraph::Block* block) const {
  ProfileMap::const_iterator it = profiles_.find(block->id());
  if (it != profiles_.end())
    return &it->second;

  return empty_profile_.get();
}

bool ApplicationProfile::ComputeGlobalProfile() {
  DCHECK_NE(reinterpret_cast<const ImageLayout*>(NULL), image_layout_);
  const BlockGraph* graph = image_layout_->blocks.graph();
  DCHECK_NE(reinterpret_cast<const BlockGraph*>(NULL), graph);

  // Compute global temperature.
  IndexedFrequencyMap::const_iterator freq = frequencies_.begin();
  for (; freq != frequencies_.end(); ++freq) {
    if (freq->first.second == kEntryCountColumn)
      global_temperature_ += freq->second;
  }

  // Compute profile for each block.
  const BlockGraph::BlockMap& blocks = graph->blocks();
  BlockGraph::BlockMap::const_iterator it = blocks.begin();
  for (; it != blocks.end(); ++it) {
    BlockGraph::BlockId id = it->first;
    const BlockGraph::Block* block = &it->second;
    bool valid = true;

    // Get the current block address.
    RelativeAddress addr;
    valid = GetAddressOfBlock(block, *image_layout_, &addr);
    DCHECK(valid);

    // Retrieve the execution count of this function.
    EntryCountType entry_count = 0;
    valid = GetFrequencyByOffset(frequencies_, addr, 0, kEntryCountColumn,
                                 &entry_count);

    // Function is never executed.
    if (!valid)
      continue;

    // Compute the block temperature.
    double temperature = 0;
    IndexedFrequencyOffset key = std::make_pair(addr, kEntryCountColumn);
    IndexedFrequencyMap::const_iterator it = frequencies_.find(key);
    for (; it != frequencies_.end(); ++it) {
      if (addr + block->size() <= it->first.first)
        break;
      if (it->first.second == kEntryCountColumn)
        temperature += it->second;
    }

    // An executed function must have a temperature higher than zero.
    DCHECK_LT(0.0, temperature);

    // Insert the block profile into the profile map.
    BlockProfile block_profile(entry_count, temperature);

    std::pair<ProfileMap::iterator, bool> result =
        profiles_.insert(std::make_pair(block->id(), block_profile));
    DCHECK(result.second);
  }

  // Build a heap of profiles ordered by temperature.
  typedef std::priority_queue<BlockProfile*,
                              std::vector<BlockProfile*>,
                              BlockProfileCompare> ProfileQueue;
  ProfileQueue queue;
  ProfileMap::iterator profile = profiles_.begin();
  for (; profile != profiles_.end(); ++profile)
    queue.push(&profile->second);

  // Update the percentile by temperature order.
  double sum = 0;
  while (!queue.empty()) {
    BlockProfile* top = queue.top();
    queue.pop();
    DCHECK_NE(reinterpret_cast<const BlockProfile*>(NULL), top);

    top->set_percentile(sum / global_temperature_);
    sum += top->temperature();
  }

  // Force block never executed to be at the last percentile.
  empty_profile_->set_percentile(1.0);

  return true;
}

bool ApplicationProfile::ImportFrequencies(
    const IndexedFrequencyMap& frequencies) {
  // TODO(etienneb): Support importing multiple sets.
  frequencies_ = frequencies;
  return true;
}

void ApplicationProfile::ComputeSubGraphProfile(
    const BasicBlockSubGraph* subgraph,
    scoped_ptr<SubGraphProfile>* profile) {
  DCHECK_NE(reinterpret_cast<const BasicBlockSubGraph*>(NULL), subgraph);
  DCHECK_NE(reinterpret_cast<scoped_ptr<SubGraphProfile>*>(NULL), profile);

  // Create the resulting subgraph profile.
  profile->reset(new SubGraphProfile());

  // Retrieve the original block.
  const BlockGraph::Block* block = subgraph->original_block();
  DCHECK_NE(reinterpret_cast<const BlockGraph::Block*>(NULL), block);

  // Get the current block address.
  RelativeAddress addr;
  bool valid = GetAddressOfBlock(block, *image_layout_, &addr);
  DCHECK(valid);

  const BlockDescriptionList& descriptions = subgraph->block_descriptions();
  BlockDescriptionList::const_iterator descr_iter = descriptions.begin();
  for (; descr_iter != descriptions.end(); ++descr_iter) {
    const BasicBlockOrdering& original_order = descr_iter->basic_block_order;
    BasicBlockOrdering::const_iterator order = original_order.begin();
    for (; order != original_order.end(); ++order) {
      // Get the basic block.
      const BasicCodeBlock* bb = BasicCodeBlock::Cast(*order);
      if (bb == NULL)
        continue;

      // Retrieve basic block information.
      Offset offset = bb->offset();
      EntryCountType count = 0;
      EntryCountType taken = 0;
      EntryCountType mispredicted = 0;
      GetFrequencyByOffset(frequencies_, addr, offset, kEntryCountColumn,
                           &count);
      GetFrequencyByOffset(frequencies_, addr, offset, kBranchTakenColumn,
                           &taken);
      GetFrequencyByOffset(frequencies_, addr, offset, kMissPredColumn,
                           &mispredicted);

      DCHECK_GE(count, taken);
      EntryCountType untaken = (count - taken);

      // Fill the basic block profile with the information.
      BasicBlockProfile& bb_profile = (*profile)->basic_blocks_[bb];
      bb_profile.count_ = count;
      bb_profile.mispredicted_ = mispredicted;

      // Fill successors information.
      BasicBlockOrdering::const_iterator next_order = order;
      ++next_order;
      const Successors& successors = bb->successors();
      Successors::const_iterator succ = successors.begin();
      for (; succ != successors.end(); ++succ) {
        const BasicCodeBlock* next_bb =
            BasicCodeBlock::Cast(succ->reference().basic_block());
        bool is_untaken = (next_order != original_order.end() &&
                           BasicCodeBlock::Cast(*next_order) == next_bb);
        bb_profile.successors_[next_bb] = (is_untaken ? untaken : taken);
      }
    }
  }
}

const BasicBlockProfile* SubGraphProfile::GetBasicBlockProfile(
    const BasicCodeBlock* block) const {
  DCHECK_NE(reinterpret_cast<const BasicCodeBlock*>(NULL), block);
  BasicBlockProfileMap::const_iterator look = basic_blocks_.find(block);
  if (look == basic_blocks_.end())
    empty_profile_.get();
  return &look->second;
}

double SubGraphProfile::BasicBlockProfile::GetMispredictedRatio() const {
  return ((double)mispredicted_) / count_;
}

EntryCountType SubGraphProfile::BasicBlockProfile::GetSuccessorCount(
    const BasicCodeBlock* successor) const {
  DCHECK_NE(reinterpret_cast<const BasicCodeBlock*>(NULL), successor);
  SuccessorsCountMap::const_iterator look = successors_.find(successor);
  if (look != successors_.end())
    return look->second;
  return 0;
}

double SubGraphProfile::BasicBlockProfile::GetSuccessorRatio(
    const BasicCodeBlock* successor) const {
  DCHECK_NE(reinterpret_cast<const BasicCodeBlock*>(NULL), successor);
  return ((double)GetSuccessorCount(successor)) / count_;
}

}  // namespace optimize
