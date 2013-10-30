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

#include "syzygy/block_graph/block_graph.h"

#include <limits>

#include "base/logging.h"
#include "base/stringprintf.h"

namespace block_graph {

namespace {

COMPILE_ASSERT(BlockGraph::BLOCK_ATTRIBUTES_MAX_BIT < 32,
               too_many_block_attributes);

// A list of printable names corresponding to block types. This needs to
// be kept in sync with the BlockGraph::BlockType enum!
const char* kBlockType[] = {
  "CODE_BLOCK", "DATA_BLOCK",
};
COMPILE_ASSERT(arraysize(kBlockType) == BlockGraph::BLOCK_TYPE_MAX,
               kBlockType_not_in_sync);

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

void ShiftReferences(BlockGraph::Block* block,
                     BlockGraph::Offset offset,
                     BlockGraph::Offset distance) {
  // Make a copy of the reference map for simplicity.
  BlockGraph::Block::ReferenceMap references = block->references();

  // Start by removing all references that have moved.
  BlockGraph::Block::ReferenceMap::const_iterator it =
      references.lower_bound(offset);
  for (; it != references.end(); ++it) {
    if (it->first >= offset)
      block->RemoveReference(it->first);
  }

  // Then patch up all existing references.
  it = references.begin();
  for (; it != references.end(); ++it) {
    BlockGraph::Reference ref(it->second);
    BlockGraph::Offset new_offset(it->first);

    // If this is self-referential, fix the destination offset.
    if (ref.referenced() == block && ref.offset() >= offset) {
      ref = BlockGraph::Reference(ref.type(),
                                  ref.size(),
                                  ref.referenced(),
                                  ref.offset() + distance,
                                  ref.base() + distance);
    }

    // If its offset is past the change point, fix that.
    if (it->first >= offset)
      new_offset += distance;

    // In many cases this'll be a noop.
    // TODO(siggi): Optimize this.
    block->SetReference(new_offset, ref);
  }
}

// Shift all referrers beyond @p offset by @p distance.
void ShiftReferrers(BlockGraph::Block* self,
                    BlockGraph::Offset offset,
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
    // Our own references will have been moved already.
    if (ref_block != self) {
      BlockGraph::Offset ref_offset = ref_it->second;

      Reference ref;
      bool ref_found = ref_block->GetReference(ref_offset, &ref);
      DCHECK(ref_found);

      // Shift the reference if need be.
      if (ref.offset() >= offset) {
        Reference new_ref(ref.type(),
                          ref.size(),
                          ref.referenced(),
                          ref.offset() + distance,
                          ref.base() + distance);
        bool inserted = ref_block->SetReference(ref_offset, new_ref);
        DCHECK(!inserted);
      }
    }

    ref_it = next_ref_it;
  }
}

const char* BlockAttributeToString(BlockGraph::BlockAttributeEnum attr) {
  switch (attr) {
#define DEFINE_CASE(name) case BlockGraph::name: return #name;
    BLOCK_ATTRIBUTE_ENUM(DEFINE_CASE)
#undef DEFINE_CASE
    default:
      NOTREACHED();
      return NULL;
  }
}

}  // namespace

std::string BlockGraph::BlockAttributesToString(BlockAttributes attrs) {
  BlockAttributes attr = 1;
  std::string s;
  for (; attr < BLOCK_ATTRIBUTES_MAX; attr <<= 1) {
    if (attr & attrs) {
      if (!s.empty())
        s.append("|");
      s.append(BlockAttributeToString(static_cast<BlockAttributeEnum>(attr)));
    }
  }
  return s;
}

const char* BlockGraph::BlockTypeToString(BlockGraph::BlockType type) {
  DCHECK_LE(BlockGraph::CODE_BLOCK, type);
  DCHECK_GT(BlockGraph::BLOCK_TYPE_MAX, type);
  return kBlockType[type];
}

std::string BlockGraph::LabelAttributesToString(
    BlockGraph::LabelAttributes label_attributes) {
  static const char* kLabelAttributes[] = {
      "Code", "DebugStart", "DebugEnd", "ScopeStart", "ScopeEnd",
      "CallSite", "JumpTable", "CaseTable", "Data", "PublicSymbol" };
  COMPILE_ASSERT((1 << arraysize(kLabelAttributes)) == LABEL_ATTRIBUTES_MAX,
                 label_attribute_names_not_in_sync_with_enum);

  std::string s;
  for (size_t i = 0; i < arraysize(kLabelAttributes); ++i) {
    if (label_attributes & (1 << i)) {
      if (!s.empty())
        s.append("|");
      s.append(kLabelAttributes[i]);
    }
  }
  return s;
}

const BlockGraph::SectionId BlockGraph::kInvalidSectionId = -1;

BlockGraph::BlockGraph()
    : next_section_id_(0),
      next_block_id_(0) {
}

BlockGraph::~BlockGraph() {
}

BlockGraph::Section* BlockGraph::AddSection(const base::StringPiece& name,
                                            uint32 characteristics) {
  Section new_section(next_section_id_++, name, characteristics);
  std::pair<SectionMap::iterator, bool> result = sections_.insert(
      std::make_pair(new_section.id(), new_section));
  DCHECK(result.second);

  return &result.first->second;
}

BlockGraph::Section* BlockGraph::FindSection(const base::StringPiece& name) {
  const BlockGraph* self = const_cast<const BlockGraph*>(this);
  const BlockGraph::Section* section = self->FindSection(name);
  return const_cast<BlockGraph::Section*>(section);
}

const BlockGraph::Section* BlockGraph::FindSection(
    const base::StringPiece& name) const {
  // This is a linear scan, but thankfully images generally do not have many
  // sections and we do not create them very often. Fast lookup by index is
  // more important. If this ever becomes an issue, we could keep around a
  // second index by name.
  SectionMap::const_iterator it = sections_.begin();
  for (; it != sections_.end(); ++it) {
    if (it->second.name() == name)
      return &it->second;
  }

  return NULL;
}

BlockGraph::Section* BlockGraph::FindOrAddSection(const base::StringPiece& name,
                                                  uint32 characteristics) {
  Section* section = FindSection(name);
  if (section) {
    section->set_characteristic(characteristics);
    return section;
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
                                        const base::StringPiece& name) {
  BlockId id = ++next_block_id_;
  BlockMap::iterator it = blocks_.insert(
      std::make_pair(id, Block(id, type, size, name, this))).first;

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

BlockGraph::Block* BlockGraph::AddressSpace::AddBlock(
    BlockType type, RelativeAddress addr, Size size,
    const base::StringPiece& name) {
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
      address_space_.FindContaining(range);
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

bool BlockGraph::AddressSpace::ContainsBlock(const Block* block) {
  DCHECK(block != NULL);
  return block_addresses_.count(block) != 0;
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

  base::StringPiece block_name = first_block->name();
  BlockType block_type = first_block->type();
  size_t section_id = first_block->section();
  size_t alignment = first_block->alignment();
  BlockAttributes attributes = 0;

  // Some attributes are only propagated if they are present on *all* blocks
  // in the range.
  static const BlockAttributes kUniformAttributes =
      GAP_BLOCK | PADDING_BLOCK | BUILT_BY_SYZYGY;
  BlockAttributes uniform_attributes = kUniformAttributes;

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

    // Add any non-uniform attributes to the block, and keep track of the
    // uniform attributes.
    attributes |= block->attributes() & ~kUniformAttributes;
    uniform_attributes &= block->attributes();

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
  new_block->set_attributes(attributes | uniform_attributes);
  if (have_data) {
    uint8* data = new_block->CopyData(merged_data.size(), &merged_data.at(0));
    if (data == NULL) {
      LOG(ERROR) << "Unable to copy merged data";
      return NULL;
    }
  }

  // Now move all labels and references to the new block.
  for (size_t i = 0; i < intersecting.size(); ++i) {
    RelativeAddress addr = intersecting[i].first;
    BlockGraph::Block* block = intersecting[i].second;
    BlockGraph::Offset start_offset = addr - begin;

    // If the destination block is not a code block, preserve the old block
    // names as labels for debugging. We also need to make sure the label is
    // not empty, as that is verboten.
    if (block_type != BlockGraph::CODE_BLOCK && !block->name().empty()) {
      new_block->SetLabel(start_offset,
                          block->name(),
                          BlockGraph::DATA_LABEL);
    }

    // Move labels.
    BlockGraph::Block::LabelMap::const_iterator
        label_it(block->labels().begin());
    for (; label_it != block->labels().end(); ++label_it) {
      new_block->SetLabel(start_offset + label_it->first,
                          label_it->second);
    }

    // Copy the reference map since we mutate the original.
    BlockGraph::Block::ReferenceMap refs(block->references());
    BlockGraph::Block::ReferenceMap::const_iterator ref_it(refs.begin());
    for (; ref_it != refs.end(); ++ref_it) {
      block->RemoveReference(ref_it->first);
      new_block->SetReference(start_offset + ref_it->first, ref_it->second);
    }

    // Redirect all referrers to the new block.
    block->TransferReferrers(start_offset,
                             new_block,
                             BlockGraph::Block::kTransferInternalReferences);

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

bool BlockGraph::Section::set_name(const base::StringPiece& name) {
  if (name == NULL)
    return false;

  if (name.empty())
    return false;

  name.CopyToString(&name_);
  return true;
}

bool BlockGraph::Section::Save(core::OutArchive* out_archive) const {
  DCHECK(out_archive != NULL);
  return out_archive->Save(id_) && out_archive->Save(name_) &&
      out_archive->Save(characteristics_);
}

bool BlockGraph::Section::Load(core::InArchive* in_archive) {
  DCHECK(in_archive != NULL);
  return in_archive->Load(&id_) && in_archive->Load(&name_) &&
      in_archive->Load(&characteristics_);
}

std::string BlockGraph::Label::ToString() const {
  return base::StringPrintf("%s (%s)",
                            name_.c_str(),
                            LabelAttributesToString(attributes_).c_str());
}

bool BlockGraph::Label::IsValid() const {
  return AreValidAttributes(attributes_);
}

bool BlockGraph::Label::AreValidAttributes(LabelAttributes attributes) {
  // A label needs to have at least one attribute.
  if (attributes == 0)
    return false;

  // TODO(chrisha): Once we make the switch to VS2010 determine where call
  //     site labels may land. Are they at the beginning of the call
  //     instruction (in which case they may coincide with *_START_LABEL,
  //     *_END_LABEL and CODE_LABEL), or do they point at the address of the
  //     call (in which case they must be completely on their own)? For now, we
  //     simply ignore them entirely from consideration.
  attributes &= ~CALL_SITE_LABEL;

  // Public symbols can coincide with anything, so we can basically ignore
  // them.
  attributes &= ~PUBLIC_SYMBOL_LABEL;

  // A code label can coincide with a debug and scope labels. (It can coincide
  // with *_END_LABEL labels because of 1-byte instructions, like RET or INT.)
  const LabelAttributes kCodeDebugScopeLabels =
      CODE_LABEL | DEBUG_START_LABEL | DEBUG_END_LABEL | SCOPE_START_LABEL |
      SCOPE_END_LABEL;
  if ((attributes & CODE_LABEL) != 0 &&
      (attributes & ~kCodeDebugScopeLabels) != 0) {
    return false;
  }

  // A jump table must be paired with a data label. It may also be paired
  // with a debug-end label if tail-call optimization has been applied by
  // the compiler/linker.
  const LabelAttributes kJumpDataLabelAttributes =
      JUMP_TABLE_LABEL | DATA_LABEL;
  if (attributes & JUMP_TABLE_LABEL) {
    if ((attributes & kJumpDataLabelAttributes) != kJumpDataLabelAttributes)
      return false;
    // Filter out the debug-end label if present and check that nothing else
    // is set.
    attributes &= ~DEBUG_END_LABEL;
    if ((attributes & ~kJumpDataLabelAttributes) != 0)
      return false;
    return true;
  }

  // A case table must be paired with a data label and nothing else.
  const LabelAttributes kCaseDataLabelAttributes =
      CASE_TABLE_LABEL | DATA_LABEL;
  if (attributes & CASE_TABLE_LABEL) {
    if ((attributes & kCaseDataLabelAttributes) != kCaseDataLabelAttributes)
      return false;
    if ((attributes & ~kCaseDataLabelAttributes) != 0)
      return false;
    return true;
  }

  // If there is no case or jump label, then a data label must be on its own.
  if ((attributes & DATA_LABEL) != 0 && (attributes & ~DATA_LABEL) != 0)
    return false;

  return true;
}

BlockGraph::Block::Block(BlockGraph* block_graph)
    : id_(0),
      type_(BlockGraph::CODE_BLOCK),
      size_(0),
      alignment_(1),
      name_(NULL),
      compiland_name_(NULL),
      addr_(RelativeAddress::kInvalidAddress),
      block_graph_(block_graph),
      section_(kInvalidSectionId),
      attributes_(0),
      owns_data_(false),
      data_(NULL),
      data_size_(0) {
  DCHECK(block_graph != NULL);
}

BlockGraph::Block::Block(BlockId id,
                         BlockType type,
                         Size size,
                         const base::StringPiece& name,
                         BlockGraph* block_graph)
    : id_(id),
      type_(type),
      size_(size),
      alignment_(1),
      name_(NULL),
      compiland_name_(NULL),
      addr_(RelativeAddress::kInvalidAddress),
      block_graph_(block_graph),
      section_(kInvalidSectionId),
      attributes_(0),
      owns_data_(false),
      data_(NULL),
      data_size_(0) {
  DCHECK(block_graph != NULL);
  set_name(name);
}

BlockGraph::Block::~Block() {
  DCHECK(block_graph_ != NULL);
  if (owns_data_)
    delete [] data_;
}

void BlockGraph::Block::set_name(const base::StringPiece& name) {
  DCHECK(block_graph_ != NULL);
  const std::string& interned_name =
      block_graph_->string_table().InternString(name);
  name_ = &interned_name;
}

const std::string& BlockGraph::Block::compiland_name() const {
  DCHECK(block_graph_ != NULL);
  if (compiland_name_ == NULL)
    return block_graph_->string_table().InternString("");
  return *compiland_name_;
}

void BlockGraph::Block::set_compiland_name(const base::StringPiece& name) {
  DCHECK(block_graph_ != NULL);
  const std::string& interned_name =
      block_graph_->string_table().InternString(name);
  compiland_name_ = &interned_name;
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
    ShiftReferences(this, offset, size);
    ShiftReferrers(this, offset, size, &referrers_);
    source_ranges_.InsertUnmappedRange(DataRange(offset, size));

    // Does this affect already allocated data?
    if (static_cast<Size>(offset) < data_size_) {
      // Reallocate, shift the old data to the end, and zero out the new data.
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
  ShiftReferences(this, offset + size, -static_cast<int>(size));
  ShiftReferrers(this, offset + size, -static_cast<int>(size), &referrers_);
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
  DCHECK_NE(0U, data_size_);
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

bool BlockGraph::Block::HasExternalReferrers() const {
  ReferrerSet::const_iterator it = referrers().begin();
  for (; it != referrers().end(); ++it) {
    if (it->first != this)
      return true;
  }
  return false;
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

    // Examine references before us that could possibly conflict with us.
    Offset offset_begin = offset - Reference::kMaximumSize + 1;
    ReferenceMap::const_iterator it =
        references_.lower_bound(offset_begin);
    for (; it != references_.end() && it->first < offset; ++it) {
      if (static_cast<Offset>(it->first + it->second.size()) > offset)
        NOTREACHED() << "Trying to insert conflicting reference.";
    }

    // Skip the reference at the same offset if there is one. This reference
    // will be replaced by the new one.
    if (it != references_.end() && it->first == offset)
      ++it;

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

bool BlockGraph::Block::RemoveAllReferences() {
  ReferenceMap::iterator it = references_.begin();
  while (it != references_.end()) {
    ReferenceMap::iterator to_remove = it;
    ++it;

    // TODO(rogerm): As an optimization, we don't need to drop intra-block
    //     references when disconnecting from the block_graph. Consider having
    //     BlockGraph::RemoveBlockByIterator() check that the block has no
    //     external referrers before calling this function and erasing the
    //     block.

    // Unregister this reference from the referred block then erase it.
    BlockGraph::Block* referenced = to_remove->second.referenced();
    Referrer referrer(this, to_remove->first);
    size_t removed = referenced->referrers_.erase(referrer);
    DCHECK_EQ(1U, removed);
    references_.erase(to_remove);
  }

  return true;
}

bool BlockGraph::Block::SetLabel(Offset offset, const Label& label) {
  DCHECK_LE(0, offset);
  DCHECK_LE(static_cast<size_t>(offset), size_);

  VLOG(2) << name() << ": adding "
          << LabelAttributesToString(label.attributes()) << " label '"
          << label.name() << "' at offset " << offset << ".";

  // Try inserting the label into the label map.
  std::pair<LabelMap::iterator, bool> result(
      labels_.insert(std::make_pair(offset, label)));

  // If it was freshly inserted then we're done.
  if (result.second)
    return true;

  return false;
}

bool BlockGraph::Block::GetLabel(Offset offset, Label* label) const {
  DCHECK(offset >= 0 && static_cast<size_t>(offset) <= size_);
  DCHECK(label != NULL);

  LabelMap::const_iterator it = labels_.find(offset);
  if (it == labels_.end())
    return false;

  *label = it->second;
  return true;
}

bool BlockGraph::Block::RemoveLabel(Offset offset) {
  DCHECK(offset >= 0 && static_cast<size_t>(offset) <= size_);

  return labels_.erase(offset) == 1;
}

bool BlockGraph::Block::HasLabel(Offset offset) const {
  DCHECK(offset >= 0 && static_cast<size_t>(offset) <= size_);

  return labels_.find(offset) != labels_.end();
}

bool BlockGraph::Block::TransferReferrers(Offset offset,
    Block* new_block, TransferReferrersFlags flags) {
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

    if ((flags & kSkipInternalReferences) != 0 && referrer.first == this)
      continue;

    Offset new_offset = ref.offset() + offset;
    Offset new_base = ref.base() + offset;

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
                                  new_offset,
                                  new_base);
    referrer.first->SetReference(referrer.second, new_ref);
  }

  return true;
}

// Returns true if this block contains the given range of bytes.
bool BlockGraph::Block::Contains(RelativeAddress address, size_t size) const {
  return (address >= addr_ && address + size <= addr_ + size_);
}

bool BlockGraph::Reference::IsValid() const {
  // We can't reference a NULL block.
  if (referenced_ == NULL)
    return false;

  // First see if the base address is valid for the referenced block. Base
  // addresses must track an existing position in the block, between zero
  // (beginning of the block), and one past the last byte (end of the
  // block). These are the same offsets that are valid for InsertData(),
  // such that inserting data at that position or before would shift the
  // reference along. Hence, an end reference (one past the size of the
  // block) would always be shifted regardless of the point of insertion;
  // conversely, a reference to address zero would never move.
  if (base_ < 0 || static_cast<size_t>(base_) > referenced_->size())
    return false;

  if (!IsValidTypeSize(type_, size_))
    return false;

  return true;
}

bool BlockGraph::Reference::IsValidTypeSize(ReferenceType type, Size size) {
  switch (type & ~RELOC_REF_BIT) {
    // We see 8- and 32-bit relative JMPs.
    case PC_RELATIVE_REF:
      return size == 1 || size == 4;

    // These guys are all pointer sized.
    case ABSOLUTE_REF:
    case RELATIVE_REF:
    case FILE_OFFSET_REF:
      return size == 4;

    case SECTION_REF:
      return size == 2;
    case SECTION_OFFSET_REF:
      return size == 1 || size == 4;

    default:
      NOTREACHED() << "Unknown ReferenceType.";
  }

  return false;
}

}  // namespace block_graph
