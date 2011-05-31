// Copyright 2010 Google Inc.
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
#include "syzygy/core/block_graph.h"

#include "base/logging.h"

namespace core {

const RelativeAddress kInvalidAddress(0xFFFFFFFF);
const size_t kInvalidSection = -1;

BlockGraph::BlockGraph() : next_block_id_(0) {
}

BlockGraph::~BlockGraph() {
}

BlockGraph::Block* BlockGraph::AddBlock(BlockType type,
                                        Size size,
                                        const char* name) {
  BlockId id = ++next_block_id_;
  BlockMap::iterator it = blocks_.insert(
      std::make_pair(id, Block(id, type, size, name))).first;

  return &it->second;
}

BlockGraph::Block* BlockGraph::GetBlockById(BlockId id) {
  BlockMap::iterator it(blocks_.find(id));

  if (it == blocks_.end())
    return NULL;

  return &it->second;
}

BlockGraph::AddressSpace::AddressSpace(BlockGraph* graph)
    : graph_(graph) {
  DCHECK(graph != NULL);
}

BlockGraph::Block* BlockGraph::AddressSpace::AddBlock(BlockType type,
                                                      RelativeAddress addr,
                                                      Size size,
                                                      const char* name) {
  // First check to see that the range is clear.
  AddressSpaceImpl::Range range(addr, size);
  AddressSpaceImpl::RangeMap::iterator it =
      address_space_.FindFirstIntersection(range);
  if (it != address_space_.ranges().end())
    return NULL;

  BlockGraph::Block* block = graph_->AddBlock(type, size, name);
  DCHECK(block != NULL);
  bool inserted = InsertImpl(addr, block);
  DCHECK(inserted);

  return block;
}

bool BlockGraph::AddressSpace::InsertBlock(RelativeAddress addr, Block* block) {
  return InsertImpl(addr, block);
}

// TODO(siggi): Remove this method?
BlockGraph::Block* BlockGraph::AddressSpace::GetBlockByAddress(
    RelativeAddress addr) const {
  return GetContainingBlock(addr, 1);
}

BlockGraph::Block* BlockGraph::AddressSpace::GetContainingBlock(
    RelativeAddress addr, Size size) const {
  AddressSpaceImpl::Range range(addr, size);
  AddressSpaceImpl::RangeMap::const_iterator it =
      address_space_.FindFirstIntersection(range);
  if (it == address_space_.ranges().end())
    return NULL;

  return it->second;
}

BlockGraph::Block* BlockGraph::AddressSpace::GetFirstIntersectingBlock(
    RelativeAddress addr, Size size) {
  AddressSpaceImpl::Range range(addr, size);
  AddressSpaceImpl::RangeMap::iterator it =
      address_space_.FindFirstIntersection(range);
  if (it == address_space_.ranges().end())
    return NULL;

  return it->second;
}

BlockGraph::AddressSpace::RangeMapConstIterPair
BlockGraph::AddressSpace::GetIntersectingBlocks(RelativeAddress address,
                                                Size size) const {
  return address_space_.FindIntersecting(Range(address, size));
}

BlockGraph::AddressSpace::RangeMapIterPair
BlockGraph::AddressSpace::GetIntersectingBlocks(RelativeAddress address,
                                                Size size) {
  return address_space_.FindIntersecting(Range(address, size));
}

bool BlockGraph::AddressSpace::GetAddressOf(const Block* block,
                                            RelativeAddress* addr) const {
  DCHECK(block != NULL);
  DCHECK(addr != NULL);

  BlockAddressMap::const_iterator it(block_addresses_.find(block));
  if (it == block_addresses_.end())
    return false;

  *addr = it->second;
  return true;
}

bool BlockGraph::AddressSpace::InsertImpl(RelativeAddress addr, Block* block) {
  Range range(addr, block->size());
  bool inserted = address_space_.Insert(range, block);
  if (!inserted)
    return false;

  inserted = block_addresses_.insert(std::make_pair(block, addr)).second;
  DCHECK(inserted);
  // Update the address stored in the block.
  block->set_addr(addr);

  // And set the original address if it hasn't already been set.
  if (block->original_addr() == kInvalidAddress)
    block->set_original_addr(addr);

  return true;
}

BlockGraph::Block* BlockGraph::AddressSpace::MergeIntersectingBlocks(
    const Range& range) {
  typedef std::vector<std::pair<RelativeAddress, BlockGraph::Block*>>
      BlockAddressVector;

  // Find all the blocks that intersect the range, keep them and their
  // addresses. Start by finding the first intersection, then iterate
  // from there until we find a block that doesn't intersect with range.
  AddressSpaceImpl::RangeMap::iterator address_start =
      address_space_.FindFirstIntersection(range);
  AddressSpaceImpl::RangeMap::iterator address_it(address_start);

  BlockAddressVector intersecting;
  for (; address_it != address_space_.ranges().end() &&
         address_it->first.Intersects(range); ++address_it) {
    intersecting.push_back(std::make_pair(address_it->first.start(),
                                          address_it->second));
  }

  // Bail if the intersection doesn't cover at least two blocks.
  if (intersecting.empty())
    return NULL;

  // In case of single-block intersection, we're done.
  if (intersecting.size() == 1)
    return intersecting[0].second;

  DCHECK(!intersecting.empty());

  // Calculate the start and end addresses of the new block.
  BlockGraph::Block* first_block = intersecting[0].second;
  BlockGraph::Block* last_block = intersecting[intersecting.size() - 1].second;
  DCHECK(first_block != NULL && last_block != NULL);

  RelativeAddress begin = std::min(range.start(), intersecting[0].first);
  RelativeAddress end = std::max(range.start() + range.size(),
      intersecting[intersecting.size() - 1].first + last_block->size());

  DCHECK(begin <= range.start());
  DCHECK(end >= range.start() + range.size());

  const char* block_name = first_block->name();
  BlockType block_type = first_block->type();
  size_t section_id = first_block->section();
  BlockAttributes attributes = 0;

  // Remove the found blocks from the address space, and make sure they're all
  // of the same type and from the same section as the first block. Merge the
  // data from all the blocks as we go along, and the attributes.
  std::vector<uint8> merged_data(end - begin);
  bool have_data = false;
  for (size_t i = 0; i < intersecting.size(); ++i) {
    RelativeAddress addr = intersecting[i].first;
    BlockGraph::Block* block = intersecting[i].second;
    DCHECK_EQ(block_type, block->type());
    DCHECK_EQ(section_id, block->section());

    if (block->data() != NULL) {
      have_data = true;
      memcpy(&merged_data.at(addr - begin), block->data(), block->data_size());
    }
    attributes |= block->attributes();

    bool removed = address_space_.Remove(Range(addr, block->size()));
    DCHECK(removed);
    size_t num_removed = block_addresses_.erase(intersecting[i].second);
    DCHECK_EQ(1U, num_removed);
  }

  BlockGraph::Block* new_block = AddBlock(block_type,
                                          begin, end - begin,
                                          block_name);
  DCHECK(new_block != NULL);
  new_block->set_section(section_id);
  new_block->set_attributes(attributes);
  if (have_data) {
    uint8* data = new_block->CopyData(merged_data.size(), &merged_data.at(0));
    if (data == NULL) {
      LOG(ERROR) << "Unable to copy merged data";
      return false;
    }
  }

  // Now move all labels and references to the new block.
  for (size_t i = 0; i < intersecting.size(); ++i) {
    RelativeAddress addr = intersecting[i].first;
    BlockGraph::Block* block = intersecting[i].second;
    BlockGraph::Offset start_offset = addr - begin;

    // If the destination block is not a code block, preserve the old block
    // names as labels for debugging.
    if (block_type != BlockGraph::CODE_BLOCK)
      new_block->SetLabel(start_offset, block->name());

    // Move labels.
    BlockGraph::Block::LabelMap::const_iterator
        label_it(block->labels().begin());
    for (; label_it != block->labels().end(); ++label_it) {
      new_block->SetLabel(start_offset + label_it->first,
                          label_it->second.c_str());
    }

    // Copy the reference map since we mutate the original.
    BlockGraph::Block::ReferenceMap refs(block->references());
    BlockGraph::Block::ReferenceMap::const_iterator ref_it(refs.begin());
    for (; ref_it != refs.end(); ++ref_it) {
      block->RemoveReference(ref_it->first);
      new_block->SetReference(start_offset + ref_it->first, ref_it->second);
    }

    // Redirect all referrers to the new block.
    block->TransferReferrers(start_offset, new_block);

    // Check that we've removed all references and
    // referrers from the original block.
    DCHECK(block->references().empty());
    DCHECK(block->referrers().empty());
  }

  return new_block;
}

BlockGraph::Block::Block(BlockId id,
                         BlockType type,
                         Size size,
                         const char* name)
    : id_(id),
      type_(type),
      size_(size),
      name_(name),
      addr_(kInvalidAddress),
      original_addr_(kInvalidAddress),
      section_(kInvalidSection),
      attributes_(0),
      owns_data_(false),
      data_(NULL),
      data_size_(0) {
}

BlockGraph::Block::~Block() {
  if (owns_data_)
    delete [] data_;
}

uint8* BlockGraph::Block::AllocateData(size_t size) {
  DCHECK(size > 0 && size <= size_);
  uint8* new_data = new uint8[size];
  if (!new_data)
    return NULL;

  if (owns_data()) {
    DCHECK(data_ != NULL);
    delete data_;
  }

  data_ = new_data;
  data_size_ = size;
  owns_data_ = true;

  return new_data;
}

uint8* BlockGraph::Block::CopyData(size_t size, const void* data) {
  uint8* new_data = AllocateData(size);
  if (new_data == NULL)
    return NULL;

  memcpy(new_data, data, size);
  return new_data;
}

bool BlockGraph::Block::SetReference(Offset offset, const Reference& ref) {
  DCHECK(ref.referenced() != NULL);
  DCHECK(ref.offset() >= 0 &&
      static_cast<size_t>(ref.offset()) <= ref.referenced()->size());
  DCHECK(offset + ref.size() <= size());

  // Did we have an earlier reference at this location?
  ReferenceMap::iterator it(references_.find(offset));
  bool inserted = false;
  if (it != references_.end()) {
    // Erase the back reference.
    BlockGraph::Block* referenced = it->second.referenced();
    Referrer referrer(this, offset);
    size_t removed = referenced->referrers_.erase(referrer);
    DCHECK_EQ(1U, removed);

    // Lastly switch the reference.
    it->second = ref;
  } else {
    // It's a new reference, insert it.
    inserted = references_.insert(std::make_pair(offset, ref)).second;
    DCHECK(inserted);
  }

  // Record the back-reference.
  ref.referenced()->referrers_.insert(std::make_pair(this, offset));

  return inserted;
}

bool BlockGraph::Block::GetReference(Offset offset,
                                     Reference* reference) const {
  DCHECK(reference != NULL);
  ReferenceMap::const_iterator it(references_.find(offset));
  if (it == references_.end())
    return false;

  *reference = it->second;
  return true;
}

bool BlockGraph::Block::RemoveReference(Offset offset) {
  // Do we have reference at this location?
  ReferenceMap::iterator it(references_.find(offset));
  if (it == references_.end())
    return false;

  BlockGraph::Block* referenced = it->second.referenced();
  Referrer referrer(this, offset);
  size_t removed = referenced->referrers_.erase(referrer);
  DCHECK_EQ(1U, removed);
  references_.erase(it);

  return true;
}

bool BlockGraph::Block::SetLabel(Offset offset, const char* name) {
  DCHECK(offset >= 0 && static_cast<size_t>(offset) <= size_);

  return labels_.insert(std::make_pair(offset, name)).second;
}

bool BlockGraph::Block::HasLabel(Offset offset) {
  DCHECK(offset >= 0 && static_cast<size_t>(offset) <= size_);

  return labels_.find(offset) != labels_.end();
}

bool BlockGraph::Block::TransferReferrers(Offset offset,
                                          Block* new_block) {
  // Redirect all referrers to the new block, we copy the referrer set
  // because it is otherwise mutated during iteration.
  BlockGraph::Block::ReferrerSet referrers = referrers_;
  BlockGraph::Block::ReferrerSet::const_iterator referrer_it(referrers.begin());

  for (; referrer_it != referrers.end(); ++referrer_it) {
    // Get the original reference.
    BlockGraph::Block::Referrer referrer = *referrer_it;
    BlockGraph::Block::ReferenceMap::const_iterator found_ref(
        referrer.first->references().find(referrer.second));
    DCHECK(found_ref != referrer.first->references().end());
    BlockGraph::Reference ref(found_ref->second);

    Offset new_offset = ref.offset() + offset;
    if (new_offset < 0 || static_cast<size_t>(new_offset) > new_block->size()) {
      return false;
    }

    // Redirect the reference to the new block with the adjusted offset.
    BlockGraph::Reference new_ref(ref.type(),
                                  ref.size(),
                                  new_block,
                                  new_offset);
    referrer.first->SetReference(referrer.second, new_ref);
  }

  return true;
}

}  // namespace core
