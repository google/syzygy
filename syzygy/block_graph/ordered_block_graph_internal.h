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
// Internal implementation details for OrderedBlockGraph. This is meant to be
// included from ordered_block_graph.h only.

#ifndef SYZYGY_BLOCK_GRAPH_ORDERED_BLOCK_GRAPH_INTERNAL_H_
#define SYZYGY_BLOCK_GRAPH_ORDERED_BLOCK_GRAPH_INTERNAL_H_

#include <utility>
#include <vector>

namespace block_graph {

struct OrderedBlockGraph::SectionInfo {
  // The ordered section itself.
  OrderedSection ordered_section;
  // The iterator pointing to the SectionList node storing a pointer to
  // |ordered_section|.
  SectionList::iterator it;

  // A convenience function for getting the id associated with the enclosed
  // section.
  BlockGraph::SectionId id() const { return ordered_section.id(); }
};

struct OrderedBlockGraph::BlockInfo {
  // The iterator pointing to the list node storing a block.
  BlockList::iterator it;
  // The ordered section owning the list to which the iterator belongs.
  OrderedSection* ordered_section;
};

namespace internal {

// Sorts a linked list using the provided sort-functor, which must operate
// on the iterators of the list.
template<typename ListType, typename CompareFunctor>
void SortList(CompareFunctor compare_functor, size_t size_hint,
              ListType* list) {
  DCHECK(list != NULL);

  // If the list is empty sort will complete, but --list->end() will blow up
  // below. Thus an early termination.
  if (list->begin() == list->end())
    return;

  typedef typename ListType::iterator Iterator;
  std::vector<Iterator> its;
  its.reserve(size_hint);

  for (Iterator it = list->begin(); it != list->end(); ++it)
    its.push_back(it);

  std::sort(its.begin(), its.end(), compare_functor);

  // Relink the list in the same order. We use splice so that no reallocations
  // are performed.
  if (its[0] != --list->end())
    list->splice(list->end(), *list, its[0]);
  for (size_t i = 1; i < its.size(); ++i)
    list->splice(list->end(), *list, its[i]);
}

// An adapter for comparing Sectionlist::iterator objects via the underlying
// Section pointers.
template<typename CompareFunctor>
struct SectionListSortAdapter {
  explicit SectionListSortAdapter(CompareFunctor compare_functor)
      : compare_functor_(compare_functor) { }

  bool operator()(OrderedBlockGraph::SectionList::iterator it1,
                  OrderedBlockGraph::SectionList::iterator it2) {
    return compare_functor_((*it1)->section(), (*it2)->section());
  }

  CompareFunctor compare_functor_;
};

// An adapter for comparing BlockList::iterator objects via the underlying
// Block pointers.
template<typename CompareFunctor>
struct BlockListSortAdapter {
  explicit BlockListSortAdapter(CompareFunctor compare_functor)
      : compare_functor_(compare_functor) {
  }

  bool operator()(OrderedBlockGraph::BlockList::iterator it1,
                  OrderedBlockGraph::BlockList::iterator it2) {
    return compare_functor_(*it1, *it2);
  }

  CompareFunctor compare_functor_;
};

}  // namespace internal

template<typename SectionCompareFunctor>
void OrderedBlockGraph::Sort(SectionCompareFunctor section_compare_functor) {
  typedef internal::SectionListSortAdapter<SectionCompareFunctor> Adapter;
  internal::SortList(Adapter(section_compare_functor),
                     section_infos_.size() - 1,
                     &ordered_sections_);
  RebuildSectionIndex();
}

template<typename BlockCompareFunctor>
void OrderedBlockGraph::Sort(const Section* section,
                             BlockCompareFunctor block_compare_functor) {
  SectionInfo* section_info = GetSectionInfo(section);
  DCHECK(section_info != NULL);

  // Build an index which can be used to find the BlockInfo index from a
  // Block*.
  typedef std::vector<std::pair<Block*, size_t>> ReverseIndex;
  ReverseIndex rindex;
  BlockList& blocks(section_info->ordered_section.ordered_blocks_);
  rindex.reserve(blocks.size());
  BlockList::iterator it = blocks.begin();
  for (; it != blocks.end(); ++it) {
    Block* block = *it;
    DCHECK(block != NULL);

    BlockInfo* block_info = GetBlockInfo(block);
    DCHECK(block_info != NULL);

    size_t index = block_info - &block_infos_[0];
    rindex.push_back(std::make_pair(block, index));
  }
  // Sort this based on Block*, which std::pair does for us by default.
  std::sort(rindex.begin(), rindex.end());

  typedef internal::BlockListSortAdapter<BlockCompareFunctor> Adapter;
  internal::SortList(Adapter(block_compare_functor),
                     rindex.size(),
                     &blocks);

  // Rebuild the block index using the index to find the affected BlockInfo
  // entries.
  for (it = blocks.begin(); it != blocks.end(); ++it) {
    Block* block = *it;
    DCHECK(block != NULL);

    ReverseIndex::const_iterator rindex_it = std::lower_bound(
        rindex.begin(), rindex.end(),
        std::make_pair(block, static_cast<size_t>(0)));
    DCHECK(rindex_it != rindex.end());
    DCHECK_EQ(rindex_it->first, block);

    block_infos_[rindex_it->second].it = it;
  }
}

}  // namespace block_graph

#endif  // SYZYGY_BLOCK_GRAPH_ORDERED_BLOCK_GRAPH_INTERNAL_H_
