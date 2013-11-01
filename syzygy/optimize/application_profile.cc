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
using grinder::basic_block_util::IndexedFrequencyMap;
using grinder::basic_block_util::IndexedFrequencyOffset;

typedef ApplicationProfile::BlockProfile BlockProfile;
typedef BlockGraph::Offset Offset;
typedef core::RelativeAddress RelativeAddress;
typedef grinder::basic_block_util::EntryCountType EntryCountType;
typedef pe::ImageLayout ImageLayout;

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
                          size_t column,
                          Offset offset,
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

const BlockProfile* ApplicationProfile::GetBlockProfile(
    const BlockGraph::Block* block) const {
  ProfileMap::const_iterator it = profiles_.find(block->id());
  if (it != profiles_.end())
    return &it->second;

  return NULL;
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
    valid = GetFrequencyByOffset(frequencies_, addr, kEntryCountColumn, 0,
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

  return true;
}

bool ApplicationProfile::ImportFrequencies(
    const IndexedFrequencyMap& frequencies) {
  // TODO(etienneb): Support importing multiple sets.
  frequencies_ = frequencies;
  return true;
}

}  // namespace optimize
