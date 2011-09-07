// Copyright 2011 Google Inc.
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

const char* BlockGraph::kBlockType[] = {
  "CODE_BLOCK", "DATA_BLOCK", "BASIC_CODE_BLOCK", "BASIC_DATA_BLOCK",
};
COMPILE_ASSERT(arraysize(BlockGraph::kBlockType) == BlockGraph::BLOCK_TYPE_MAX,
               kBlockType_not_in_sync);

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

bool BlockGraph::RemoveBlock(Block* block) {
  DCHECK(block != NULL);

  BlockMap::iterator it(blocks_.find(block->id()));
  if (it == blocks_.end() || &it->second != block)
    return false;

  return RemoveBlockByIterator(it);
}

bool BlockGraph::RemoveBlockById(BlockId id) {
  BlockMap::iterator it(blocks_.find(id));
  if (it == blocks_.end())
    return false;

  return RemoveBlockByIterator(it);
}

BlockGraph::Block* BlockGraph::GetBlockById(BlockId id) {
  BlockMap::iterator it(blocks_.find(id));

  if (it == blocks_.end())
    return NULL;

  return &it->second;
}

bool BlockGraph::Save(OutArchive* out_archive) const {
  DCHECK(out_archive != NULL);

  if (!out_archive->Save(next_block_id_) || !out_archive->Save(blocks_.size()))
    return false;

  // Output the basic block properties first.
  BlockMap::const_iterator it = blocks_.begin();
  for (; it != blocks_.end(); ++it) {
    if (!out_archive->Save(it->first) ||
        !it->second.SaveProps(out_archive) ||
        !it->second.SaveData(out_archive)) {
      return false;
    }
  }

  // Now output the referrers and references.
  it = blocks_.begin();
  for (; it != blocks_.end(); ++it) {
    if (!it->second.SaveRefs(out_archive))
      return false;
  }

  return true;
}

bool BlockGraph::Load(InArchive* in_archive) {
  DCHECK(in_archive != NULL);

  size_t num_blocks = 0;
  if (!in_archive->Load(&next_block_id_) || !in_archive->Load(&num_blocks))
    return false;

  // Load the basic block properties first, and keep track of the
  // order of the blocks. We do this because we can't guarantee that the
  // underlying map will provide us the blocks in the order that we created
  // them, and this is the order in which the references are provided.
  std::vector<BlockGraph::Block*> order;
  for (size_t i = 0; i < num_blocks; ++i) {
    BlockGraph::BlockId id = 0;
    Block block;
    if (!in_archive->Load(&id) || !block.LoadProps(in_archive))
      return false;
    BlockMap::iterator it = blocks_.insert(std::make_pair(id, block)).first;
    order.push_back(&it->second);

    // Load the data *after* the block is inserted in the map so as not to
    // cause an extra alloc and copy.
    if (!it->second.LoadData(in_archive))
      return false;
  }
  DCHECK_EQ(num_blocks, order.size());

  // Load the references and referrers.
  for (size_t i = 0; i < num_blocks; ++i) {
    if (!order[i]->LoadRefs(*this, in_archive))
      return false;
  }

  return true;
}

bool BlockGraph::RemoveBlockByIterator(BlockMap::iterator it) {
  DCHECK(it != blocks_.end());

  // Verify this block is fully disconnected.
  if (it->second.referrers().size() > 0 || it->second.references().size() > 0)
    return false;

  blocks_.erase(it);

  return true;
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
  size_t alignment = first_block->alignment();
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
  new_block->set_alignment(alignment);
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

    // Remove the original block.
    bool removed = graph_->RemoveBlock(block);
    DCHECK(removed);
  }

  return new_block;
}

bool BlockGraph::AddressSpace::Save(OutArchive* out_archive) const {
  DCHECK(out_archive != NULL);

  // Simply dump the ids of the blocks that are actually in the address space.
  if (!out_archive->Save(address_space_.size()))
    return false;

  RangeMapConstIter it = address_space_.begin();
  for (; it != address_space_.end(); ++it) {
    if (!out_archive->Save(it->second->id()))
      return false;
  }

  return true;
}

bool BlockGraph::AddressSpace::Load(InArchive* in_archive) {
  DCHECK(in_archive != NULL);

  size_t num_blocks = 0;
  if (!in_archive->Load(&num_blocks)) {
    LOG(ERROR) << "Unable to load BlockGraph::AddressSpace size.";
    return false;
  }

  // Simply load the block ids. The address and length are implicit.
  for (size_t i = 0; i < num_blocks; ++i) {
    BlockId id = 0;
    if (!in_archive->Load(&id)) {
      LOG(ERROR) << "Unable to load block id.";
      return false;
    }

    Block* block = graph_->GetBlockById(id);
    if (block == NULL) {
      LOG(ERROR) << "No block found with id " << id << ".";
      return false;
    }

    if (!InsertBlock(block->addr(), block)) {
      LOG(ERROR) << "Unable to insert block in BlockGraph::AddressSpace.";
      return false;
    }
  }

  return true;
}

BlockGraph::Block::Block()
    : id_(0),
      type_(BlockGraph::CODE_BLOCK),
      size_(0),
      alignment_(1),
      addr_(kInvalidAddress),
      original_addr_(kInvalidAddress),
      section_(kInvalidSection),
      attributes_(0),
      owns_data_(false),
      data_(NULL),
      data_size_(0) {
}

BlockGraph::Block::Block(BlockId id,
                         BlockType type,
                         Size size,
                         const char* name)
    : id_(id),
      type_(type),
      size_(size),
      alignment_(1),
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

  // Non-code blocks can be referred to by pointers that lie outside of their
  // extent (due to loop induction, arrays indexed with an implicit offset,
  // etc). Code blocks can not be referred to in this manner, because references
  // in code blocks must be places where the flow of execution actually lands.
  if (ref.referenced()->type() == CODE_BLOCK) {
    DCHECK(ref.offset() >= 0 &&
        static_cast<size_t>(ref.offset()) <= ref.referenced()->size());
    DCHECK(offset + ref.size() <= size());
  }

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

    // Same thing as in SetReferrer, references to non-code blocks may lie
    // outside the extent of the block.
    if (type_ == CODE_BLOCK) {
      if (new_offset < 0 ||
          static_cast<size_t>(new_offset) > new_block->size()) {
        LOG(ERROR) << "Transferred reference lies outside of code block.";
        return false;
      }
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

// Returns true if this block contains the given range of bytes.
bool BlockGraph::Block::Contains(RelativeAddress address, size_t size) const {
  return (address >= addr_ && address + size <= addr_ + size_);
}

bool BlockGraph::Block::SaveProps(OutArchive* out_archive) const {
  DCHECK(out_archive != NULL);
  if (out_archive->Save(id_) && out_archive->Save((int)type_) &&
      out_archive->Save(size_) && out_archive->Save(alignment_) &&
      out_archive->Save(name_) && out_archive->Save(addr_) &&
      out_archive->Save(original_addr_) && out_archive->Save(section_) &&
      out_archive->Save(attributes_) && out_archive->Save(labels_)) {
    return true;
  }
  LOG(ERROR) << "Unable to save block properties.";
  return false;
}

bool BlockGraph::Block::LoadProps(InArchive* in_archive) {
  DCHECK(in_archive != NULL);
  if (in_archive->Load(&id_) && in_archive->Load((int*)&type_) &&
      in_archive->Load(&size_) && in_archive->Load(&alignment_) &&
      in_archive->Load(&name_) && in_archive->Load(&addr_) &&
      in_archive->Load(&original_addr_) && in_archive->Load(&section_) &&
      in_archive->Load(&attributes_) && in_archive->Load(&labels_)) {
    return true;
  }
  LOG(ERROR) << "Unable to load block properties.";
  return false;
}

bool BlockGraph::Block::SaveRefs(OutArchive* out_archive) const {
  DCHECK(out_archive != NULL);

  if (!out_archive->Save(references_.size()))
    return false;

  // Output the references.
  ReferenceMap::const_iterator it1 = references_.begin();
  for (; it1 != references_.end(); ++it1) {
    DCHECK(it1->second.referenced() != NULL);
    if (!out_archive->Save(it1->first) ||
        !out_archive->Save((int)it1->second.type()) ||
        !out_archive->Save(it1->second.size()) ||
        !out_archive->Save(it1->second.referenced()->id()) ||
        !out_archive->Save(it1->second.offset())) {
      LOG(ERROR) << "Unable to save block reference.";
      return false;
    }
  }

  return true;
}

bool BlockGraph::Block::LoadRefs(BlockGraph& block_graph,
                                 InArchive* in_archive) {
  DCHECK(in_archive != NULL);

  size_t num_references = 0;
  if (!in_archive->Load(&num_references)) {
    LOG(ERROR) << "Unable to load block reference count.";
    return false;
  }

  // Load the references.
  for (size_t i = 0; i < num_references; ++i) {
    Offset local_offset = 0;
    ReferenceType type = RELATIVE_REF;
    Size size = 0;
    BlockId id = 0;
    Offset remote_offset = 0;
    if (!in_archive->Load(&local_offset) ||
        !in_archive->Load((int*)&type) || !in_archive->Load(&size) ||
        !in_archive->Load(&id) || !in_archive->Load(&remote_offset)) {
      LOG(ERROR) << "Unable to load block reference.";
      return false;
    }

    Block* referenced = block_graph.GetBlockById(id);
    if (referenced == NULL) {
      LOG(ERROR) << "Unable to load block with id " << id << ".";
      return false;
    }
    if (!SetReference(local_offset,
                      Reference(type, size, referenced, remote_offset))) {
      LOG(ERROR) << "Unable to create block reference.";
      return false;
    }
  }

  return true;
}

bool BlockGraph::Block::SaveData(OutArchive* out_archive) const {
  DCHECK(out_archive != NULL);

  if (!out_archive->Save(owns_data_) ||
      !out_archive->Save(data_size_))
    return false;

  // If we own the data, we save it directly.
  if (owns_data_) {
    if (!out_archive->out_stream()->Write(data_size_, data_))
      return false;
  }

  return true;
}

bool BlockGraph::Block::LoadData(InArchive* in_archive) {
  DCHECK(in_archive != NULL);

  if (!in_archive->Load(&owns_data_) ||
      !in_archive->Load(&data_size_))
    return false;

  // No data? Nothing else to do.
  if (data_size_ == 0)
    return true;

  // If we own the data, load it directly.
  if (owns_data_) {
    uint8* data = new uint8[data_size_];
    data_ = data;
    if (!in_archive->in_stream()->Read(data_size_, data))
      return false;
  }

  return true;
}

}  // namespace core
