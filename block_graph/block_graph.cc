// Copyright 2012 Google Inc.
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

#include "syzygy/block_graph/block_graph.h"

#include "base/logging.h"

namespace block_graph {

namespace {

// Shift all items in an offset -> item map by 'distance', provided the initial
// item offset was >= @p offset.
template<typename ItemType>
void ShiftOffsetItemMap(BlockGraph::Offset offset,
                        BlockGraph::Offset distance,
                        std::map<BlockGraph::Offset, ItemType>* items) {
  DCHECK_GE(offset, 0);
  DCHECK_NE(distance, 0);
  DCHECK(items != NULL);

  typedef std::map<BlockGraph::Offset, ItemType> ItemMap;

  // Get iterators to all of the items that need changing.
  std::vector<ItemMap::iterator> item_its;
  ItemMap::iterator item_it = items->lower_bound(offset);
  while (item_it != items->end()) {
    item_its.push_back(item_it);
    ++item_it;
  }

  // Get the direction and bounds of the iteration. We need to walk through
  // the iterators in a different order depending on if we're shifting left
  // or right. This is to ensure that earlier shifts don't land on the values
  // of later unshifted offsets.
  int start = 0;
  int stop = item_its.size();
  int step = 1;
  if (distance > 0) {
    start = stop - 1;
    stop = -1;
    step = -1;
  }

  for (int i = start; i != stop; i += step) {
    item_it = item_its[i];
    items->insert(std::make_pair(item_it->first + distance,
                                 item_it->second));
    items->erase(item_it);
  }
}

// Shift all referrers beyond @p offset by @p distance.
void ShiftReferrers(BlockGraph::Offset offset,
                    BlockGraph::Offset distance,
                    BlockGraph::Block::ReferrerSet* referrers) {
  DCHECK_GE(offset, 0);
  DCHECK_NE(distance, 0);
  DCHECK(referrers != NULL);

  typedef BlockGraph::Block::ReferrerSet ReferrerSet;
  typedef BlockGraph::Reference Reference;

  ReferrerSet::iterator ref_it = referrers->begin();
  while (ref_it != referrers->end()) {
    // We need to keep around the next iterator as 'ref_it' will be invalidated
    // if we need to update the reference. (It will be deleted and then
    // recreated.)
    ReferrerSet::iterator next_ref_it = ref_it;
    ++next_ref_it;

    BlockGraph::Block* ref_block = ref_it->first;
    BlockGraph::Offset ref_offset = ref_it->second;

    Reference ref;
    bool ref_found = ref_block->GetReference(ref_offset, &ref);
    DCHECK(ref_found);

    // Shift the reference if need be.
    if (ref.offset() >= offset) {
      Reference new_ref(
          ref.type(), ref.size(), ref.referenced(), ref.offset() + distance);
      bool inserted = ref_block->SetReference(ref_offset, new_ref);
      DCHECK(!inserted);
    }

    ref_it = next_ref_it;
  }
}

}  // namespace

const core::RelativeAddress kInvalidAddress(0xFFFFFFFF);

const BlockGraph::SectionId BlockGraph::kInvalidSectionId = -1;

const char* BlockGraph::kBlockType[] = {
  "CODE_BLOCK", "DATA_BLOCK", "BASIC_CODE_BLOCK", "BASIC_DATA_BLOCK",
};
COMPILE_ASSERT(arraysize(BlockGraph::kBlockType) == BlockGraph::BLOCK_TYPE_MAX,
               kBlockType_not_in_sync);

BlockGraph::BlockGraph()
    : next_section_id_(0),
      next_block_id_(0) {
}

BlockGraph::~BlockGraph() {
}

BlockGraph::Section* BlockGraph::AddSection(const char* name,
                                            uint32 characteristics) {
  Section new_section(next_section_id_++, name, characteristics);
  std::pair<SectionMap::iterator, bool> result = sections_.insert(
      std::make_pair(new_section.id(), new_section));
  DCHECK(result.second);

  return &result.first->second;
}

BlockGraph::Section* BlockGraph::FindOrAddSection(const char* name,
                                                  uint32 characteristics) {
  // This is a linear scan, but thankfully images generally do not have many
  // sections and we do not create them very often. Fast lookup by index is
  // more important. If this ever becomes an issue, we could keep around a
  // second index by name.
  SectionMap::iterator it = sections_.begin();
  for (; it != sections_.end(); ++it) {
    if (it->second.name() == name) {
      it->second.set_characteristics(characteristics);
      return &it->second;
    }
  }

  return AddSection(name, characteristics);
}

bool BlockGraph::RemoveSection(Section* section) {
  DCHECK(section != NULL);

  SectionMap::iterator it(sections_.find(section->id()));
  if (it == sections_.end() || &it->second != section)
    return false;

  sections_.erase(it);
  return true;
}

bool BlockGraph::RemoveSectionById(SectionId id) {
  SectionMap::iterator it(sections_.find(id));
  if (it == sections_.end())
    return false;

  sections_.erase(it);
  return true;
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

BlockGraph::Section* BlockGraph::GetSectionById(SectionId id) {
  SectionMap::iterator it(sections_.find(id));

  if (it == sections_.end())
    return NULL;

  return &it->second;
}

const BlockGraph::Section* BlockGraph::GetSectionById(SectionId id) const {
  SectionMap::const_iterator it(sections_.find(id));

  if (it == sections_.end())
    return NULL;

  return &it->second;
}

BlockGraph::Block* BlockGraph::GetBlockById(BlockId id) {
  BlockMap::iterator it(blocks_.find(id));

  if (it == blocks_.end())
    return NULL;

  return &it->second;
}

const BlockGraph::Block* BlockGraph::GetBlockById(BlockId id) const {
  BlockMap::const_iterator it(blocks_.find(id));

  if (it == blocks_.end())
    return NULL;

  return &it->second;
}

bool BlockGraph::Save(OutArchive* out_archive) const {
  DCHECK(out_archive != NULL);

  if (!out_archive->Save(next_section_id_) ||
      !out_archive->Save(sections_) ||
      !out_archive->Save(next_block_id_) ||
      !out_archive->Save(blocks_.size())) {
    return false;
  }

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
  if (!in_archive->Load(&next_section_id_) ||
      !in_archive->Load(&sections_) ||
      !in_archive->Load(&next_block_id_) ||
      !in_archive->Load(&num_blocks)) {
    return false;
  }

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

  BlockGraph::Block::SourceRanges source_ranges;

  // Remove the found blocks from the address space, and make sure they're all
  // of the same type and from the same section as the first block. Merge the
  // data from all the blocks as we go along, as well as the attributes and
  // source ranges.
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

    // Merge in the source ranges from each block.
    BlockGraph::Offset block_offset = addr - begin;
    BlockGraph::Block::SourceRanges::RangePairs::const_iterator src_it =
        block->source_ranges().range_pairs().begin();
    for (; src_it != block->source_ranges().range_pairs().end(); ++src_it) {
      // The data range is wrt to the containing block, wo we have to translate
      // each individual block's offset to an offset in the merged block.
      BlockGraph::Offset merged_offset = block_offset + src_it->first.start();
      bool pushed = source_ranges.Push(
          BlockGraph::Block::DataRange(merged_offset, src_it->first.size()),
          src_it->second);
      DCHECK(pushed);
    }

    bool removed = address_space_.Remove(Range(addr, block->size()));
    DCHECK(removed);
    size_t num_removed = block_addresses_.erase(intersecting[i].second);
    DCHECK_EQ(1U, num_removed);
  }

  // Create the new block.
  BlockGraph::Block* new_block = AddBlock(block_type,
                                          begin, end - begin,
                                          block_name);
  DCHECK(new_block != NULL);

  // Set the rest of the properties for the new block.
  new_block->source_ranges() = source_ranges;
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

bool BlockGraph::Section::set_name(const char* name) {
  if (name == NULL)
    return false;

  std::string new_name(name);
  if (new_name.empty())
    return false;

  name_ = new_name;
  return true;
}

bool BlockGraph::Section::Save(OutArchive* out_archive) const {
  DCHECK(out_archive != NULL);
  return out_archive->Save(id_) && out_archive->Save(name_) &&
      out_archive->Save(characteristics_);
}

bool BlockGraph::Section::Load(InArchive* in_archive) {
  DCHECK(in_archive != NULL);
  return in_archive->Load(&id_) && in_archive->Load(&name_) &&
      in_archive->Load(&characteristics_);
}

BlockGraph::Block::Block()
    : id_(0),
      type_(BlockGraph::CODE_BLOCK),
      size_(0),
      alignment_(1),
      addr_(kInvalidAddress),
      section_(kInvalidSectionId),
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
      section_(kInvalidSectionId),
      attributes_(0),
      owns_data_(false),
      data_(NULL),
      data_size_(0) {
}

BlockGraph::Block::~Block() {
  if (owns_data_)
    delete [] data_;
}

uint8* BlockGraph::Block::AllocateRawData(size_t data_size) {
  DCHECK_GT(data_size, 0u);
  DCHECK_LE(data_size, size_);

  uint8* new_data = new uint8[data_size];
  if (!new_data)
    return NULL;

  if (owns_data()) {
    DCHECK(data_ != NULL);
    delete [] data_;
  }

  data_ = new_data;
  data_size_ = data_size;
  owns_data_ = true;

  return new_data;
}

void BlockGraph::Block::InsertData(Offset offset,
                                   Size size,
                                   bool always_allocate_data) {
  DCHECK_GE(offset, 0);
  DCHECK_LE(offset, static_cast<Offset>(size_));

  if (size > 0) {
    // Patch up the block.
    size_ += size;
    ShiftOffsetItemMap(offset, size, &labels_);
    ShiftOffsetItemMap(offset, size, &references_);
    ShiftReferrers(offset, size, &referrers_);
    source_ranges_.InsertUnmappedRange(DataRange(offset, size));

    // Does this affect already allocated data?
    if (static_cast<Size>(offset) < data_size_) {
      // Reallocate, shift the old data to the end, and zero out the new data.
      size_t old_data_size = data_size_;
      size_t bytes_to_shift = data_size_ - offset;
      ResizeData(data_size_ + size);
      uint8* new_data = GetMutableData();
      memmove(new_data + offset + size, new_data + offset, bytes_to_shift);
      memset(new_data + offset, 0, size);
    }
  }

  // If we've been asked to, at least make sure that the data is allocated.
  if (always_allocate_data && data_size_ < offset + size)
    ResizeData(offset + size);

  return;
}

bool BlockGraph::Block::RemoveData(Offset offset, Size size) {
  DCHECK_GE(offset, 0);
  DCHECK_LE(offset, static_cast<Offset>(size_));

  if (size == 0)
    return true;

  // Ensure there are no labels in this range.
  if (labels_.lower_bound(offset) != labels_.lower_bound(offset + size))
    return false;

  // Ensure that there are no references intersecting this range.
  ReferenceMap::const_iterator refc_it = references_.begin();
  for (; refc_it != references_.end(); ++refc_it) {
    if (refc_it->first >= static_cast<Offset>(offset + size))
      break;
    if (static_cast<Offset>(refc_it->first + refc_it->second.size()) > offset)
      return false;
  }

  // Ensure there are no referrers pointing to the data we want to remove.
  ReferrerSet::const_iterator refr_it = referrers_.begin();
  for (; refr_it != referrers_.end(); ++refr_it) {
    Reference ref;
    if (!refr_it->first->GetReference(refr_it->second, &ref)) {
      LOG(ERROR) << "Unable to get reference from referrer.";
      return false;
    }
    if (ref.offset() < static_cast<Offset>(offset + size) &&
        static_cast<Offset>(ref.offset() + ref.size()) > offset) {
      return false;
    }
  }

  // Patch up the block.
  size_ -= size;
  ShiftOffsetItemMap(offset + size, -static_cast<int>(size), &labels_);
  ShiftOffsetItemMap(offset + size, -static_cast<int>(size), &references_);
  ShiftReferrers(offset + size, -static_cast<int>(size), &referrers_);
  source_ranges_.RemoveMappedRange(DataRange(offset, size));

  // Does this affect already allocated data?
  if (static_cast<Size>(offset) < data_size_) {
    size_t new_data_size = data_size_ - size;
    // Is there data beyond the section to delete?
    if (static_cast<Size>(offset + size) < data_size_) {
      // Shift tail data to left.
      uint8* data = GetMutableData();
      size_t bytes_to_shift = data_size_ - offset - size;
      size_t old_data_size = data_size_;
      memmove(data + new_data_size - bytes_to_shift,
              data + old_data_size - bytes_to_shift,
              bytes_to_shift);
    } else {
      new_data_size = offset;
    }
    ResizeData(new_data_size);
  }

  return true;
}

bool BlockGraph::Block::InsertOrRemoveData(Offset offset,
                                           Size current_size,
                                           Size new_size,
                                           bool always_allocate_data) {
  DCHECK_GE(offset, 0);
  DCHECK_LE(offset, static_cast<Offset>(size_));

  // If we're growing use InsertData.
  if (new_size > current_size) {
    Offset insert_offset = offset + current_size;
    Size insert_size = new_size - current_size;
    InsertData(insert_offset, insert_size, always_allocate_data);
    return true;
  }

  // If we're shrinking we'll need to use RemoveData.
  if (new_size < current_size) {
    Offset remove_offset = offset + new_size;
    Size remove_size = current_size - new_size;
    if (!RemoveData(remove_offset, remove_size))
      return false;
    // We fall through so that 'always_allocate_data' can be respected.
  }

  // If we've been asked to, at least make sure that the data is allocated.
  if (always_allocate_data && data_size_ < offset + new_size)
    ResizeData(offset + new_size);

  return true;
}

void BlockGraph::Block::SetData(const uint8* data, size_t data_size) {
  DCHECK((data_size == 0 && data == NULL) ||
         (data_size != 0 && data != NULL));
  DCHECK(data_size <= size_);

  if (owns_data_)
    delete [] data_;

  owns_data_ = false;
  data_ = data;
  data_size_ = data_size;
}

uint8* BlockGraph::Block::AllocateData(size_t size) {
  uint8* new_data = AllocateRawData(size);
  if (new_data == NULL)
    return NULL;

  ::memset(new_data, 0, size);
  return new_data;
}

uint8* BlockGraph::Block::CopyData(size_t size, const void* data) {
  uint8* new_data = AllocateRawData(size);
  if (new_data == NULL)
    return NULL;

  memcpy(new_data, data, size);
  return new_data;
}

const uint8* BlockGraph::Block::ResizeData(size_t new_size) {
  if (new_size == data_size_)
    return data_;

  if (!owns_data() && new_size < data_size_) {
    // Not in our ownership and shrinking. We only need to adjust our length.
    data_size_ = new_size;
  } else {
    // Either our own data, or it's growing (or both). We need to reallocate.
    uint8* new_data = new uint8[new_size];
    if (new_data == NULL)
      return NULL;

    // Copy the (head of the) old data.
    memcpy(new_data, data_, std::min(data_size_, new_size));
    if (new_size > data_size_) {
      // Zero the tail.
      memset(new_data + data_size_, 0, new_size - data_size_);
    }

    if (owns_data())
      delete [] data_;

    owns_data_ = true;
    data_ = new_data;
    data_size_ = new_size;
  }

  return data_;
}

uint8* BlockGraph::Block::GetMutableData() {
  DCHECK(data_size_ != 0);
  DCHECK(data_ != NULL);

  // Make a copy if we don't already own the data.
  if (!owns_data()) {
    uint8* new_data = new uint8[data_size_];
    if (new_data == NULL)
      return NULL;
    memcpy(new_data, data_, data_size_);
    data_ = new_data;
    owns_data_ = true;
  }
  DCHECK(owns_data_);

  return const_cast<uint8*>(data_);
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

#if defined(DEBUG) || !defined(NDEBUG)
  {
    // NOTE: It might be worthwhile making SetReference return true on success,
    //     and false on failure as it is possible for references to conflict.
    //     For now we simply check for conflicts in debug builds and die an
    //     unglorious death if we find any.

    if (!ref.IsValid())
      NOTREACHED() << "Trying to insert invalid reference.";

    // Examine references before us that could possible conflict with us.
    Offset offset_begin = offset - Reference::kMaximumSize + 1;
    ReferenceMap::const_iterator it =
        references_.lower_bound(offset_begin);
    for (; it != references_.end() && it->first < offset; ++it) {
      if (static_cast<Offset>(it->first + it->second.size()) > offset)
        NOTREACHED() << "Trying to insert conflicting reference.";
    }

    // Examine the reference at the same offset if there is one. We expect it to
    // have the same size and type.
    if (it != references_.end() && it->first == offset) {
      if (it->second.size() != ref.size() || it->second.type() != ref.type()) {
      }
      ++it;
    }

    // This is the first reference after our offset. Check to see if it lands
    // within the range we want to occupy.
    if (it != references_.end() &&
        it->first < static_cast<Offset>(offset + ref.size())) {
      NOTREACHED() << "Trying to insert conflicting reference.";
    }
  }
#endif

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
      out_archive->Save(section_) && out_archive->Save(attributes_) &&
      out_archive->Save(source_ranges_) && out_archive->Save(labels_)) {
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
      in_archive->Load(&section_) && in_archive->Load(&attributes_) &&
      in_archive->Load(&source_ranges_) && in_archive->Load(&labels_)) {
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

bool BlockGraph::Reference::IsValid() const {
  switch (type_) {
    // We see 8- and 32-bit relative JMPs.
    case PC_RELATIVE_REF:
      return size_ == 1 || size_ == 4;

    // These guys are all pointer sized.
    case ABSOLUTE_REF:
    case RELATIVE_REF:
    case FILE_OFFSET_REF:
      return size_ == 4;

    default:
      NOTREACHED() << "Unknown ReferenceType.";
  }

  return false;
}

// This needs to be kept in sync with the values in IsValid.
const BlockGraph::Size BlockGraph::Reference::kMaximumSize = 4;

}  // namespace block_graph
