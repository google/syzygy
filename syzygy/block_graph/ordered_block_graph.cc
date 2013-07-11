// Copyright 2012 Google Inc. All Rights Reserved.
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

#include "syzygy/block_graph/ordered_block_graph.h"

namespace block_graph {

namespace {

// Produces a copy of an object.
template<typename T> T Copy(const T& t) { return T(t); }

}  // namespace

// This is used for sorting and searching through the section index.
struct OrderedBlockGraph::CompareSectionInfo {
  bool operator()(const SectionInfo& s1, const SectionInfo& s2) const {
    return s1.ordered_section.section() < s2.ordered_section.section();
  }
  bool operator()(const SectionInfo& s1, const Section* s2) const {
    return s1.ordered_section.section() < s2;
  }
  bool operator()(const Section* s1, const SectionInfo& s2) const {
    return s1 < s2.ordered_section.section();
  }
};

// This is used for sorting and searching through the block index.
struct OrderedBlockGraph::CompareBlockInfo {
  bool operator()(const BlockInfo& b1, const BlockInfo& b2) const {
    return *b1.it < *b2.it;
  }
  bool operator()(const BlockInfo& b1, const Block* b2) const {
    return *b1.it < b2;
  }
  bool operator()(const Block* b1, const BlockInfo& b2) const {
    return b1 < *b2.it;
  }
};

OrderedBlockGraph::OrderedBlockGraph(BlockGraph* block_graph)
    : block_graph_(block_graph) {
  DCHECK(block_graph != NULL);

  // Create the section infos. There is an extra one which catches all blocks
  // not belonging to an explicit section. This ensures that all blocks belong
  // to exactly one BlockList (and OrderedSection) at all times.
  section_infos_.resize(block_graph_->sections().size() + 1);
  // We don't add this special section to the list of ordered sections.
  section_infos_[0].ordered_section.section_ = NULL;
  BlockGraph::SectionMap::iterator section_it =
      block_graph_->sections_mutable().begin();
  BlockGraph::SectionMap::iterator section_end =
      block_graph_->sections_mutable().end();
  for (size_t i = 1; section_it != section_end; ++section_it, ++i) {
    DCHECK_LT(i, section_infos_.size());
    section_infos_[i].ordered_section.section_ = &section_it->second;
  }

  // Sort these based on Section* values, except for the first one which we
  // leave in its place.
  std::sort(section_infos_.begin() + 1, section_infos_.end(),
            CompareSectionInfo());

  // Now that the ordered sections have been sorted we can get stable pointers
  // to them. We get them in the order they appear in the original block graph.
  section_it = block_graph_->sections_mutable().begin();
  for (; section_it != section_end; ++section_it) {
    SectionInfo* section_info = GetSectionInfo(&section_it->second);
    section_info->it = ordered_sections_.insert(
        ordered_sections_.end(), &section_info->ordered_section);
  }
  DCHECK_EQ(ordered_sections_.size(), block_graph_->sections().size());

  // Iterate through the blocks and place them into the appropriate BlockLists.
  // Each sections BlockList will contain the blocks in the order of their
  // block graph ID.
  block_infos_.resize(block_graph_->blocks().size());
  BlockGraph::BlockMap::iterator block_it =
      block_graph_->blocks_mutable().begin();
  BlockGraph::BlockMap::iterator block_end =
      block_graph_->blocks_mutable().end();
  for (size_t i = 0; block_it != block_end; ++block_it, ++i) {
    DCHECK_LT(i, block_infos_.size());
    // Get the SectionInfo for the section containing the block.
    BlockGraph::SectionId section_id = block_it->second.section();
    const Section* section = block_graph_->GetSectionById(section_id);
    SectionInfo* section_info = GetSectionInfo(section);
    DCHECK(section_info != NULL);

    Block* block = &block_it->second;

    OrderedSection* ordered_section = &section_info->ordered_section;
    block_infos_[i].ordered_section = ordered_section;
    block_infos_[i].it = ordered_section->ordered_blocks_.insert(
        ordered_section->ordered_blocks_.end(), block);
  }

  // Sort the BlockInfos so that we can use GetBlockInfo.
  std::sort(block_infos_.begin(), block_infos_.end(), CompareBlockInfo());
}

const OrderedBlockGraph::OrderedSection& OrderedBlockGraph::ordered_section(
    const Section* section) const {
  const SectionInfo* section_info = GetSectionInfo(section);
  DCHECK(section_info != NULL);
  return section_info->ordered_section;
}

OrderedBlockGraph::BlockList::const_iterator OrderedBlockGraph::begin(
    const Section* section) const {
  return ordered_section(section).ordered_blocks().begin();
}

OrderedBlockGraph::BlockList::const_iterator OrderedBlockGraph::end(
    const Section* section) const {
  return ordered_section(section).ordered_blocks().end();
}

void OrderedBlockGraph::PlaceAtHead(const Section* section) {
  DCHECK(section != NULL);

  SectionInfo* section_info = GetSectionInfo(section);
  DCHECK(section_info != NULL);

  // Already there? Do nothing!
  if (section_info->it == ordered_sections_.begin())
    return;

  // We use splice to avoid an allocation.
  ordered_sections_.splice(ordered_sections_.begin(),
                           ordered_sections_,
                           section_info->it);

  // Splice invalidates the iterator.
  section_info->it = ordered_sections_.begin();
  DCHECK_EQ(*(section_info->it), &section_info->ordered_section);
}

void OrderedBlockGraph::PlaceAtTail(const Section* section) {
  DCHECK(section != NULL);

  SectionInfo* section_info = GetSectionInfo(section);
  DCHECK(section_info != NULL);

  // Already there? Do nothing!
  if (section_info->it == --ordered_sections_.end())
    return;

  // We use splice to avoid an allocation.
  ordered_sections_.splice(ordered_sections_.end(),
                           ordered_sections_,
                           section_info->it);

  // Splice invalidates the iterator.
  --(section_info->it = ordered_sections_.end());
  DCHECK_EQ(*(section_info->it), &section_info->ordered_section);
}

void OrderedBlockGraph::PlaceBefore(const Section* anchored_section,
                                    const Section* moved_section) {
  DCHECK(anchored_section != NULL);
  DCHECK(moved_section != NULL);
  DCHECK_NE(anchored_section, moved_section);

  SectionInfo* anchored = GetSectionInfo(anchored_section);
  SectionInfo* moved = GetSectionInfo(moved_section);
  DCHECK(anchored != NULL);
  DCHECK(moved != NULL);
  DCHECK_NE(anchored, moved);

  // Already there? Do nothing!
  if (++Copy(moved->it) == anchored->it)
    return;

  ordered_sections_.splice(anchored->it,
                           ordered_sections_,
                           moved->it);
  --(moved->it = anchored->it);
  DCHECK_EQ(*(moved->it), &moved->ordered_section);
}

void OrderedBlockGraph::PlaceAfter(const Section* anchored_section,
                                   const Section* moved_section) {
  DCHECK(anchored_section != NULL);
  DCHECK(moved_section != NULL);
  DCHECK_NE(anchored_section, moved_section);

  SectionInfo* anchored = GetSectionInfo(anchored_section);
  SectionInfo* moved = GetSectionInfo(moved_section);
  DCHECK(anchored != NULL);
  DCHECK(moved != NULL);
  DCHECK_NE(anchored, moved);

  SectionList::iterator anchor_it = anchored->it;
  ++anchor_it;

  // Already there? Do nothing!
  if (moved->it == anchor_it)
    return;

  ordered_sections_.splice(anchor_it,
                           ordered_sections_,
                           moved->it);
  --(moved->it = anchor_it);
  DCHECK_EQ(*(moved->it), &moved->ordered_section);
}

void OrderedBlockGraph::PlaceAtHead(const Section* section,
                                    BlockGraph::Block* block) {
  DCHECK(block != NULL);

  SectionInfo* section_info = GetSectionInfo(section);
  BlockInfo* block_info = GetBlockInfo(block);
  DCHECK(section_info != NULL);
  DCHECK(block_info != NULL);

  BlockList& blocks(section_info->ordered_section.ordered_blocks_);

  // Already there? Do nothing!
  if (&blocks == &block_info->ordered_section->ordered_blocks_ &&
      block_info->it == blocks.begin()) {
    return;
  }

  blocks.splice(blocks.begin(),
                block_info->ordered_section->ordered_blocks_,
                block_info->it);
  block_info->it = blocks.begin();
  block_info->ordered_section = &section_info->ordered_section;
  block->set_section(section_info->id());
  DCHECK_EQ(*(block_info->it), block);
}

void OrderedBlockGraph::PlaceAtTail(const Section* section,
                                    BlockGraph::Block* block) {
  DCHECK(block != NULL);

  SectionInfo* section_info = GetSectionInfo(section);
  BlockInfo* block_info = GetBlockInfo(block);
  DCHECK(section_info != NULL);
  DCHECK(block_info != NULL);

  BlockList& blocks(section_info->ordered_section.ordered_blocks_);

  // Already there? Do nothing!
  if (&blocks == &block_info->ordered_section->ordered_blocks_ &&
      block_info->it == --blocks.end()) {
    return;
  }

  blocks.splice(blocks.end(),
                block_info->ordered_section->ordered_blocks_,
                block_info->it);
  --(block_info->it = blocks.end());
  block_info->ordered_section = &section_info->ordered_section;
  block->set_section(section_info->id());
  DCHECK_EQ(*(block_info->it), block);
}

void OrderedBlockGraph::PlaceBefore(const BlockGraph::Block* anchored_block,
                                    BlockGraph::Block* moved_block) {
  DCHECK(anchored_block != NULL);
  DCHECK(moved_block != NULL);
  DCHECK_NE(anchored_block, moved_block);

  BlockInfo* anchored = GetBlockInfo(anchored_block);
  BlockInfo* moved = GetBlockInfo(moved_block);
  DCHECK(anchored != NULL);
  DCHECK(moved != NULL);
  DCHECK_NE(anchored, moved);

  BlockList& ablocks(anchored->ordered_section->ordered_blocks_);
  BlockList& mblocks(moved->ordered_section->ordered_blocks_);

  // Already there? Do nothing!
  if (&ablocks == &mblocks && ++Copy(moved->it) == anchored->it)
    return;

  ablocks.splice(anchored->it, mblocks, moved->it);
  --(moved->it = anchored->it);
  moved->ordered_section = anchored->ordered_section;
  moved_block->set_section(anchored->ordered_section->id());
  DCHECK_EQ(*(moved->it), moved_block);
}

void OrderedBlockGraph::PlaceAfter(const BlockGraph::Block* anchored_block,
                                   BlockGraph::Block* moved_block) {
  DCHECK(anchored_block != NULL);
  DCHECK(moved_block != NULL);
  DCHECK_NE(anchored_block, moved_block);

  BlockInfo* anchored = GetBlockInfo(anchored_block);
  BlockInfo* moved = GetBlockInfo(moved_block);
  DCHECK(anchored != NULL);
  DCHECK(moved != NULL);
  DCHECK_NE(anchored, moved);

  BlockList& ablocks(anchored->ordered_section->ordered_blocks_);
  BlockList& mblocks(moved->ordered_section->ordered_blocks_);

  BlockList::iterator anchored_it = anchored->it;
  ++anchored_it;

  // Already there? Do nothing!
  if (&ablocks == &mblocks && moved->it == anchored_it)
    return;

  ablocks.splice(anchored_it, mblocks, moved->it);
  --(moved->it = anchored_it);
  moved->ordered_section = anchored->ordered_section;
  moved_block->set_section(anchored->ordered_section->id());
  DCHECK_EQ(*(moved->it), moved_block);
}

const OrderedBlockGraph::SectionInfo* OrderedBlockGraph::GetSectionInfo(
    const Section* section) const {
  // Special case: the catch all section, which actually does not correspond
  // to any section in the block-graph.
  if (section == NULL) {
    DCHECK(section_infos_[0].ordered_section.section_ == NULL);
    return &section_infos_[0];
  }

  std::vector<SectionInfo>::const_iterator it =
      std::lower_bound(section_infos_.begin() + 1,
                       section_infos_.end(),
                       section,
                       CompareSectionInfo());
  DCHECK(it != section_infos_.end());
  DCHECK_EQ(section, it->ordered_section.section_);
  return &(*it);
}

OrderedBlockGraph::SectionInfo* OrderedBlockGraph::GetSectionInfo(
    const Section* section) {
  // We use the const version, and cast away constness.
  return const_cast<SectionInfo*>(
      const_cast<const OrderedBlockGraph*>(this)->GetSectionInfo(section));
}

const OrderedBlockGraph::BlockInfo* OrderedBlockGraph::GetBlockInfo(
    const Block* block) const {
  std::vector<BlockInfo>::const_iterator it =
      std::lower_bound(block_infos_.begin(),
                       block_infos_.end(),
                       block,
                       CompareBlockInfo());
  DCHECK(it != block_infos_.end());
  DCHECK_EQ(block, *(it->it));
  return &(*it);
}

OrderedBlockGraph::BlockInfo* OrderedBlockGraph::GetBlockInfo(
    const Block* block) {
  // We use the const version, and cast away constness.
  return const_cast<BlockInfo*>(
      const_cast<const OrderedBlockGraph*>(this)->GetBlockInfo(block));
}

void OrderedBlockGraph::RebuildSectionIndex() {
  SectionList::iterator it = ordered_sections_.begin();
  for (; it != ordered_sections_.end(); ++it) {
    SectionInfo* info = GetSectionInfo((*it)->section_);
    DCHECK(info != NULL);
    info->it = it;
  }
}

BlockGraph::SectionId OrderedBlockGraph::OrderedSection::id() const {
  if (section_ == NULL)
    return BlockGraph::kInvalidSectionId;
  return section_->id();
}

}  // namespace block_graph
