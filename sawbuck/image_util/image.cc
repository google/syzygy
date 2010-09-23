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
#include "sawbuck/image_util/image.h"
#include "base/logging.h"

namespace image_util {

Image::Image() : next_block_id_(0) {
}

Image::~Image() {
}

Image::Block* Image::AddBlock(BlockType type,
                              Size size,
                              const char* name) {
  BlockId id = ++next_block_id_;
  BlockMap::iterator it = blocks_.insert(
      std::make_pair(id, Block(id, type, size, name))).first;

  return &it->second;
}

Image::Block* Image::GetBlockById(BlockId id) {
  BlockMap::iterator it(blocks_.find(id));

  if (it == blocks_.end())
    return NULL;

  return &it->second;
}

Image::AddressSpace::AddressSpace(RelativeAddress start,
                                  Size size,
                                  Image* image)
    : address_space_(Range(start, size)), image_(image) {
  DCHECK(image != NULL);
}

Image::Block* Image::AddressSpace::AddBlock(BlockType type,
                                            RelativeAddress addr,
                                            Size size,
                                            const char* name) {
  // First check to see that the range is clear.
  AddressSpaceImpl::Range range(addr, size);
  AddressSpaceImpl::RangeMap::iterator it =
      address_space_.FindFirstIntersection(range);
  if (it != address_space_.ranges().end())
    return NULL;

  Image::Block* block = image_->AddBlock(type, size, name);
  DCHECK(block != NULL);
  bool inserted = InsertImpl(addr, block);
  DCHECK(inserted);

  return block;
}

bool Image::AddressSpace::InsertBlock(RelativeAddress addr, Block* block) {
  return InsertImpl(addr, block);
}

Image::Block* Image::AddressSpace::GetBlockByAddress(RelativeAddress addr) {
  AddressSpaceImpl::Range range(addr, 1);
  AddressSpaceImpl::RangeMap::iterator it =
      address_space_.FindFirstIntersection(range);
  if (it == address_space_.ranges().end())
    return NULL;

  return it->second;
}

Image::Block* Image::AddressSpace::GetFirstItersectingBlock(
    RelativeAddress addr, Size size) {
  AddressSpaceImpl::Range range(addr, size);
  AddressSpaceImpl::RangeMap::iterator it =
      address_space_.FindFirstIntersection(range);
  if (it == address_space_.ranges().end())
    return NULL;

  return it->second;
}

bool Image::AddressSpace::GetAddressOf(Block* block, RelativeAddress* addr) {
  DCHECK(block != NULL);
  DCHECK(addr != NULL);

  BlockAddressMap::const_iterator it(block_addresses_.find(block));
  if (it == block_addresses_.end())
    return false;

  *addr = it->second;
  return true;
}

bool Image::AddressSpace::InsertImpl(RelativeAddress addr, Block* block) {
  Range range(addr, block->size());
  bool inserted = address_space_.Insert(range, block);
  if (!inserted)
    return false;

  inserted = block_addresses_.insert(std::make_pair(block, addr)).second;
  DCHECK(inserted);
  return true;
}


Image::Block::Block(BlockId id,
                    BlockType type,
                    Size size,
                    const char* name)
    : id_(id),
      type_(type),
      size_(size),
      name_(name),
      owns_data_(false),
      data_(NULL),
      data_size_(0) {
}

Image::Block::~Block() {
  if (owns_data_)
    delete [] data_;
}

void Image::Block::AddReference(Offset offset, const Reference& ref) {
  DCHECK(ref.referenced() != NULL);
  bool inserted = references_.insert(std::make_pair(offset, ref)).second;
  DCHECK(inserted);
  ref.referenced()->referers_.insert(this);
}

void Image::Block::AddLabel(Offset offset, const char* name) {
  DCHECK(offset >= 0 && offset <= size_);

  labels_.insert(std::make_pair(offset, name));
}

bool Image::Block::HasLabel(Offset offset) {
  DCHECK(offset >= 0 && offset <= size_);

  return labels_.find(offset) != labels_.end();
}

}  // namespace image_util
