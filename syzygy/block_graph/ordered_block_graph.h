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
//
// Declares a data structure that can be used to impose an order on a block
// graph. This is an 'elastic' data structure in that its intent is to make
// reordering blocks cheap and efficient. It is to be used as an intermediate
// representation prior to image-format-specific layout generation.
//
// The structure maintains all sections in a list, and for each section
// maintains a list of blocks within that section. Utility functions are
// provided that allow for sections and blocks to be moved individually, or for
// all sections/all blocks in a section to be sorted wholesale.
//
// In general, it is intended to be used as follows:
//
//   OrderedBlockGraph ordered(some_block_graph);
//
//   // Ensure that .rsrc and .reloc are the last two sections.
//   ordered.PlaceAtTail(some_block_graph->FindSection(".rsrc"));
//   ordered.PlaceAtTail(some_block_graph->FindSection(".reloc"));
//
//   // Make sure that .text comes first.
//   ordered.PlaceAtHead(some_block_graph->FindSection(".text"));
//
//   // Sort the text blocks according to some functor.
//   ordered.Sort(some_block_graph->FindSection(".text"),
//                some_sort_functor);
//
//   ... etc ...
//
//   // Dump the contents of the ordered block-graph.
//   OrderedBlockGraph::SectionList::const_iterator section_it =
//       ordered.begin();
//   for (; section_it != ordered.end(); ++section_it) {
//     const BlockGraph::Section* section = *section_it;
//     ... do something with section ...
//     OrderedBlockGraph::BlockList::const_iterator block_it =
//         ordered.begin(section);
//     for (; block_it != ordered.end(section); ++block_it) {
//       const BlockGraph::Block* block = *block_it;
//       ... do something with block ...
//     }
//   }

#ifndef SYZYGY_BLOCK_GRAPH_ORDERED_BLOCK_GRAPH_H_
#define SYZYGY_BLOCK_GRAPH_ORDERED_BLOCK_GRAPH_H_

#include <list>
#include <vector>

#include "syzygy/block_graph/block_graph.h"

namespace block_graph {

// An ordered block-graph is a thin layer on top of a BlockGraph that imposes
// a complete ordering on it. A few notes on working with OrderedBlockGraphs:
//
// - A BlockGraph is only intended to be used by a single OrderedBlockGraph at a
//   time as the OrderedBlockGraph makes changes to the underlying BlockGraph to
//   ensure consistency.
// - It is invalid to add or delete blocks from a BlockGraph while it is being
//   referenced by an OrderedBlockGraph. This can cause NULL dereferences.
class OrderedBlockGraph {
 public:
  class OrderedSection;

  // For convenience.
  typedef BlockGraph::Block Block;
  typedef BlockGraph::Section Section;

  // The type of the ordered list of blocks that is maintained for each section.
  typedef std::list<Block*> BlockList;
  // The type of the ordered list of sections that is maintained for the whole
  // block graph.
  typedef std::list<OrderedSection*> SectionList;

  // Constructs an OrderedBlockGraph over the provided BlockGraph. The sections
  // are initially ordered by increasing ID, with a special section (not ordered
  // in the list of sections) housing all of the blocks that are not associated
  // a particular section (section_id == kInvalidSectionId). Within each section
  // the blocks are initially ordered by increasing block ID.
  //
  // @param block_graph the BlockGraph to be ordered. This must outlive the
  //     OrderedBlockGraph.
  explicit OrderedBlockGraph(BlockGraph* block_graph);

  // @{
  // Accesses the BlockGraph that we are ordering.
  // @returns a pointer to underlying BlockGraph.
  BlockGraph* block_graph() { return block_graph_; }
  const BlockGraph* block_graph() const { return block_graph_; }
  // @}

  // @returns the ordered list of sections. May be used for traversing the
  //     order.
  const SectionList& ordered_sections() const { return ordered_sections_; }

  // Looks up an ordered section.
  //
  // @param section the section to lookup. This may be NULL to get a list of the
  //     blocks that are not in any explicit section.
  // @returns the ordered section for the given section.
  const OrderedSection& ordered_section(const Section* section) const;

  // @{
  // Iterator access for SectionList.
  SectionList::const_iterator begin() const {
    return ordered_sections_.begin();
  }
  SectionList::const_iterator end() const { return ordered_sections_.end(); }
  // @}

  // @{
  // Iterator access for BlockLists.
  // @param section the section to whose BlockList is to be returned. This may
  //     be NULL to iterate over those blocks not in any explicit section.
  BlockList::const_iterator begin(const Section* section) const;
  BlockList::const_iterator end(const Section* section) const;
  // @}

  // Moves the given section to the head of the list of sections.
  //
  // @param section the section to be moved to the head.
  void PlaceAtHead(const Section* section);

  // Moves the given section to the tail of the list of sections.
  //
  // @param section the section to be moved to the tail.
  void PlaceAtTail(const Section* section);

  // Moves a section immediately before another section.
  //
  // @param anchored_section the section to be used as a reference.
  // @param moved_section the section to be moved.
  // @pre anchored_section != moved_section.
  void PlaceBefore(const Section* anchored_section,
                   const Section* moved_section);

  // Moves a section immediately after another section.
  //
  // @param anchored_section the section to be used as a reference.
  // @param moved_section the section to be moved.
  // @pre anchored_section != moved_section.
  void PlaceAfter(const Section* anchored_section,
                  const Section* moved_section);

  // Allows for a direct sorting of all sections using a provided comparison
  // functor. The comparison functor must have a function with the following
  // signature:
  //
  //   bool operator()(const BlockGraph::Section*,
  //                   const BlockGraph::Section*) const;
  //
  // @param section_compare_functor the compare functor to use.
  template<typename SectionCompareFunctor>
  void Sort(SectionCompareFunctor section_compare_functor);

  // Moves the given block to the head of the given section. If the block does
  // not belong to that section it will have its section_id updated.
  //
  // @param section the section into which the block should be placed. May be
  //     NULL, indicating that the block lies outside of all known sections.
  // @param block the block to be moved.
  void PlaceAtHead(const Section* section, Block* block);

  // Moves the given block to the tail of the given section. If the block does
  // not belong to that section it will have its section_id updated.
  //
  // @param section the section into which the block should be placed. May be
  //     NULL, indicating that the block lies outside of all known sections.
  // @param block the block to be moved.
  void PlaceAtTail(const Section* section, Block* block);

  // Moves @p moved_block so that it lies immediately before @p anchored_block.
  // If @p moved_block does not belong to the same section it will have its
  // section attribute updated.
  //
  // @param anchored_block the block to be used as a reference point.
  // @param moved_block the block to be moved.
  // @pre anchored_block != moved_block.
  void PlaceBefore(const Block* anchored_block, Block* moved_block);

  // Moves @p moved_block so that it lies immediately after @p anchored_block.
  // If @p moved_block does not belong to the same section it will have its
  // section attribute updated.
  //
  // @param anchored_block the block to be used as a reference point.
  // @param moved_block the block to be moved.
  // @pre anchored_block != moved_block.
  void PlaceAfter(const Block* anchored_block, Block* moved_block);

  // Allows for a direct sorting of the blocks in a section using the provided
  // comparison functor. The comparison functor must have a function with the
  // following signature:
  //
  //   bool operator()(const BlockGraph::Block*,
  //                   const BlockGraph::Block*) const;
  //
  // @param block_compare_functor the compare functor to use.
  template<typename BlockCompareFunctor>
  void Sort(const Section* section, BlockCompareFunctor block_compare_functor);

 protected:
  // Forward declarations.
  struct SectionInfo;
  struct BlockInfo;
  struct CompareSectionInfo;
  struct CompareBlockInfo;

  // @{
  // @returns the SectionInfo representing the given Section*.
  const SectionInfo* GetSectionInfo(const Section* section) const;
  SectionInfo* GetSectionInfo(const Section* section);
  // @}

  // @{
  // @returns the BlockInfo representing the given Block*.
  const BlockInfo* GetBlockInfo(const Block* block) const;
  BlockInfo* GetBlockInfo(const Block* block);
  // @}

  // Rebuilds the section iterator index.
  void RebuildSectionIndex();

  // The block graph on which we impose an order.
  BlockGraph* block_graph_;

  // Stores the ordered list of sections.
  SectionList ordered_sections_;
  // Stores the ordered sections themselves. This is sorted based on the
  // underlying Section* so that we can quickly map from a Section* to the
  // OrderedSection and its entry in the SectionList.
  std::vector<SectionInfo> section_infos_;
  // Stores a full set of iterators pointing to all of the blocks in the various
  // OrderedSection BlockLists. This is allocated once and reused. The entries
  // are sorted based on the block pointers referred to by the iterators. In
  // this way we can do a fast lookup from Block* to the BlockList containing
  // it, as well as the iterator to it.
  std::vector<BlockInfo> block_infos_;

  DISALLOW_COPY_AND_ASSIGN(OrderedBlockGraph);
};

// The ordered block graph consists of an ordered list of sections. Each
// section is itself an ordered list of blocks. This object is exposed to the
// user, hence the private data members. OrderedBlockGraph is made a friend
// so as to be able to manage it directly.
class OrderedBlockGraph::OrderedSection {
 public:
  // @returns the section represented by this ordered section.
  Section* section() const { return section_; }

  // @returns the id associated with this section.
  BlockGraph::SectionId id() const;

  // @returns the ordered list of blocks belonging to this section.
  const BlockList& ordered_blocks() const { return ordered_blocks_; }

 private:
  friend OrderedBlockGraph;

  // The section itself.
  Section* section_;
  // The blocks belonging to this section, in order.
  BlockList ordered_blocks_;
};

}  // namespace block_graph

#include "syzygy/block_graph/ordered_block_graph_internal.h"

#endif  // SYZYGY_BLOCK_GRAPH_ORDERED_BLOCK_GRAPH_H_
