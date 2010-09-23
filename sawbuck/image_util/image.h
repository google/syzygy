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
// An image is a set of blocks, each of which has an ID, a type, and a size.
// Each block represents either code or data, and blocks can reference
// one another through references of various types.
#ifndef SAWBUCK_IMAGE_UTIL_IMAGE_H_
#define SAWBUCK_IMAGE_UTIL_IMAGE_H_

#include "base/basictypes.h"
#include "sawbuck/image_util/address.h"
#include "sawbuck/image_util/address_space.h"
#include <map>
#include <hash_map>
#include <set>
#include <string>
#include <vector>

namespace image_util {

// The image class is a top-level container and namespace for blocks.
class Image {
 public:
  typedef size_t BlockId;
  typedef size_t Size;
  typedef size_t Offset;

  enum BlockType {
    CODE_BLOCK,
    DATA_BLOCK,
    READONLY_BLOCK,
  };

  enum ReferenceType {
    PC_RELATIVE_REF,
    ABSOLUTE_REF,
    RELATIVE_REF,
    FILE_OFFSET_REF,
  };
  class Block;
  class Reference;
  class AddressSpace;

  // The block map contains all blocks, indexed by id.
  typedef std::map<BlockId, Block> BlockMap;

  // Invalid block id.
  static const BlockId kInvalidBlock = -1;

  Image();
  ~Image();

  // Add @p block of type @p type and @p size and
  // return the new block.
  // @returns the new block.
  Block* AddBlock(BlockType type, Size size, const char* name);

  // Accessors.
  const BlockMap& blocks() const { return blocks_; }

  // Retrieve the block with id.
  // @returns the block in question or NULL if no such block.
  Block* GetBlockById(BlockId id);

 private:
  // All blocks we contain of.
  BlockMap blocks_;

  // Our block ID allocator.
  BlockId next_block_id_;
};

// An image block represents an indivisible block of either code or data.
// The block also stores references to other blocks in the image, their
// relative location within the block and their type and size.
// Lastly a block stores the symbols contained by the block.
// TODO(siggi): as-is, the block doesn't store a block offset for where
//    in the block the symbol start(ed), nor the symbol's size. This is
//    probably fine for the purpose of decomposing and reordering images.
class Image::Block {
 public:
  // Set of the blocks that have a reference to this block.
  typedef std::set<Block*> RefererSet;
  typedef std::map<Offset, Reference> ReferenceMap;
  typedef std::map<Offset, std::string> LabelMap;

  Block(BlockId id,
        BlockType type,
        Size size,
        const char* name);
  ~Block();

  // Accessors.
  BlockId id() const { return id_; }
  BlockType type() const { return type_; }

  Size size() const { return size_; }
  const std::string& name() const { return name_; }

  bool owns_data() const { return owns_data_; }
  void set_owns_data(bool owns_data) { owns_data_ = owns_data; }

  const uint8* data() const { return data_; }
  void set_data(const uint8* data) { data_ = data; }

  // The data size may be smaller than the block size (see size()),
  // when the block e.g. refers to data that's all or part
  // zero-initialized by the linker/loader.
  size_t data_size() const { return data_size_; }
  void set_data_size(size_t data_size) { data_size_ = data_size; }

  const ReferenceMap& references() const { return references_; }
  const RefererSet& referers() const { return referers_; }
  const LabelMap& labels() const { return labels_; }

  // Add a reference to another block.
  // @param offset offset of the reference into this block.
  // @param ref the reference to add.
  void AddReference(Offset offset, const Reference& ref);

  // Adds a label to the block. A label in code marks the location of the
  // start of an instruction - e.g. a location where disassembly can usefully
  // commence. Labels appear to be inserted by the tool chain where e.g.
  // a switch statement is implemented with a jump table, to note the location
  // of the jump destinations.
  void AddLabel(Offset offset,
                const char* name);
  bool HasLabel(Offset offset);

 private:
  BlockId id_;
  BlockType type_;
  Size size_;
  std::string name_;
  ReferenceMap references_;
  RefererSet referers_;
  LabelMap labels_;

  // True iff data_ is ours to deallocate.
  bool owns_data_;
  // A pointer to the code or data we represent.
  const uint8* data_;
  // Size of the above.
  size_t data_size_;
};

// An image address space endows an image with a non-overlapping ordering
// on blocks, where each block occupies zero or one address ranges in the
// address space. No two blocks may overlap in an address space.
class Image::AddressSpace {
 public:
  // Constructs a new empty address space with range
  // @p start to @p start + @p size on @p image.
  AddressSpace(RelativeAddress start, Size size, Image* image);

  // Add a block of type @p type and @p size at @p address to our associated
  // image, and return the new block.
  // @returns the new block, or NULL if the new block would overlap
  //    an existing block.
  Block* AddBlock(BlockType type,
                  RelativeAddress addr,
                  Size size,
                  const char* name);

  // Insert @ block at @p address.
  // @returns true on succes, or false if the new block would overlap
  //    an existing block.
  bool InsertBlock(RelativeAddress addr, Block* block);

  // Returns a pointer to the block containing address, or NULL
  // if no block contains address.
  Block* GetBlockByAddress(RelativeAddress address);

  // Finds the first block, if any that intersects
  // [@p address, @p address + @p size).
  Block* GetFirstItersectingBlock(RelativeAddress address, Size size);

  // Retrieve the address off @p block.
  // @param block the block in question.
  // @param addr on success, returns the address of @p block in this
  //    address space.
  // @returns true on success, false if @p block is not in this
  //    address space.
  bool GetAddressOf(Block* block, RelativeAddress* addr);

  // Accessor.
  Image* image() const { return image_; }

 private:
  bool InsertImpl(RelativeAddress addr, Block* block);

  typedef image_util::AddressSpace<RelativeAddress, Image::Size, Block*>
      AddressSpaceImpl;
  typedef AddressSpaceImpl::Range Range;

  typedef stdext::hash_map<Block*, RelativeAddress> BlockAddressMap;

  AddressSpaceImpl address_space_;
  BlockAddressMap block_addresses_;
  Image* image_;
};

// Represents a reference from one block to another.
class Image::Reference {
 public:
  // @param type type of reference.
  // @param size size of reference.
  // @param referenced the referenced block.
  // @param referenced_offset offset of reference into referenced.
  Reference(ReferenceType type,
            Size size,
            Block* referenced,
            Offset offset)
      : type_(type),
        size_(size),
        referenced_(referenced),
        offset_(offset) {
  }

  // Copy constructor.
  Reference(const Reference& other)
      : type_(other.type_),
        size_(other.size_),
        referenced_(other.referenced_),
        offset_(other.offset_) {
  }

  // Accessors.
  ReferenceType type() const { return type_; }
  Size size() const { return size_; }
  Block* referenced() const { return referenced_; }
  Offset offset() const { return offset_; }

 private:
  // Type of this reference.
  ReferenceType type_;

  // Size of this reference.
  // Absolute references are always pointer wide, but PC-relative
  // references can be 1, 2 or 4 byte wide, which affects their range.
  Size size_;

  // The block referenced.
  Block* referenced_;

  // Offset into the referenced block.
  Offset offset_;
};

}  // namespace image_util

#endif  // SAWBUCK_IMAGE_UTIL_IMAGE_H_
