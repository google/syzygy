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
// A block graph is a an abstract graph of blocks, each of which has an ID,
// a type, a size and a few other properties.
// Each block represents either code or data, and blocks can reference
// one another through references of various types.
#ifndef SYZYGY_CORE_BLOCK_GRAPH_H_
#define SYZYGY_CORE_BLOCK_GRAPH_H_

#include <hash_map>
#include <map>
#include <set>
#include <string>
#include <vector>
#include "base/basictypes.h"
#include "syzygy/core/address.h"
#include "syzygy/core/address_space.h"
#include "syzygy/common/align.h"

namespace core {

// The invalid address can never occur in an graph, it's used as default
// value for block addresses.
extern const RelativeAddress kInvalidAddress;
extern const size_t kInvalidSection;

// The BlockGraph is a top-level container for Blocks.
class BlockGraph {
 public:
  typedef size_t BlockId;
  typedef size_t Size;
  typedef ptrdiff_t Offset;
  typedef uint32 BlockAttributes;

  enum BlockAttributeEnum {
    // Set for functions declared non-returning.
    NON_RETURN_FUNCTION = (1 << 0),
    // Set for blocks that are inferred by the decomposer.
    GAP_BLOCK = (1 << 1),
    // Set for blocks that are parsed by the PEFileParser. These
    // blocks are unmovable, indivisible, etc, and have to be treated
    // specially.
    PE_PARSED = (1 << 2),
    // Set for blocks that are created from section contribution information.
    SECTION_CONTRIB = (1 << 3),
    // This is used to indicate that a block consists purely of padding data.
    PADDING_BLOCK = (1 << 4),
    // This is used to indicate that a block is orphaned, meaning that it has no
    // module entry point as a referrer, or is part of a tree of blocks whose
    // root has no module entry point as a referrer.
    ORPHANED_BLOCK = (1 << 5),
  };

  enum BlockType {
    CODE_BLOCK,
    DATA_BLOCK,
    BASIC_CODE_BLOCK,
    BASIC_DATA_BLOCK,
    // TODO(robertshield): Add a BASIC_PADDING_BLOCK here!

    // NOTE: This must always be last, and kBlockType must be kept in sync
    // with this enum.
    BLOCK_TYPE_MAX
  };

  // A list of printable names corresponding to block types. This needs to
  // be kept in sync with the BlockType enum!
  static const char* kBlockType[];

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

  BlockGraph();
  ~BlockGraph();

  // Add @p block of type @p type and @p size and
  // return the new block.
  // @returns the new block.
  Block* AddBlock(BlockType type, Size size, const char* name);

  // Deletes the given block from the BlockGraph. The block must belong to this
  // block graph, and have no references or referrers. Returns true on success,
  // false otherwise. On failure, the BlockGraph has not been changed.
  bool RemoveBlock(Block* block);

  // Deletes the block with the given @p id from the block graph. The block id
  // must be valid, and the block must have no references or referrers. Returns
  // true on success, false otherwise. On failure, the BlockGraph has not been
  // changed.
  bool RemoveBlockById(BlockId id);

  // Accessors.
  const BlockMap& blocks() const { return blocks_; }
  BlockMap& blocks_mutable() { return blocks_; }

  // Retrieve the block with id.
  // @returns the block in question or NULL if no such block.
  Block* GetBlockById(BlockId id);

  // Serialization is supported at the level of an entire BlockGraph, but not
  // individual blocks. This is because blocks have pointers to other blocks
  // and it is impossible to serialize one without serializing all others.
  bool Save(OutArchive* out_archive) const;
  // Note that after a 'Load', it is possible to have 'data_size > 0' and
  // 'data == NULL'. This indicates that the block was pointing to data that
  // it did not own. This will be resolved by DecomposedImage serialization.
  bool Load(InArchive* in_archive);

 private:
  // Removes a block by the iterator to it. The iterator must be valid.
  bool RemoveBlockByIterator(BlockMap::iterator it);

  // All blocks we contain.
  BlockMap blocks_;

  // Our block ID allocator.
  BlockId next_block_id_;
};

// A block represents an indivisible block of either code or data.
// The block also stores references to other blocks in the graph, their
// relative location within the block and their type and size.
// Each block has a set of attributes, including a size, a name,
// an original address and a "current" address.
// Most of those attributes are mutable, and are set in the process of
// creating and manipulating images and graph address spaces.
class BlockGraph::Block {
 public:
  // Set of the blocks that have a reference to this block.
  // This is keyed on block and source offset (not destination offset),
  // to allow easily locate and remove the backreferences on change or
  // deletion.
  typedef std::pair<Block*, Offset> Referrer;
  typedef std::set<Referrer> ReferrerSet;
  typedef std::map<Offset, Reference> ReferenceMap;
  typedef std::map<Offset, std::string> LabelMap;

  // Blocks need to be default constructible for serialization.
  Block();

  Block(BlockId id,
        BlockType type,
        Size size,
        const char* name);
  ~Block();

  // Accessors.
  BlockId id() const { return id_; }
  BlockType type() const { return type_; }

  Size size() const { return size_; }
  const char* name() const { return name_.c_str(); }
  void set_name(const char* name) { name_ = name; }

  Size alignment() const { return alignment_; }
  void set_alignment(Size alignment) {
    // Ensure that alignment is a non-zero power of two.
    DCHECK(common::IsPowerOfTwo(alignment));
    alignment_ = alignment;
  }

  // The address of the block is set any time the block is assigned
  // an address in an address space.
  RelativeAddress addr() const { return addr_; }
  void set_addr(RelativeAddress addr) { return addr_ = addr; }

  // The original address of the block is set the first time the block
  // is assigned an address in any address space, and does not change
  // after that.
  RelativeAddress original_addr() const { return original_addr_; }
  void set_original_addr(RelativeAddress addr) {
      return original_addr_ = addr;
  }

  // The section index for the block, this is a convenience attribute.
  size_t section() const { return section_; }
  void set_section(size_t section) { section_ = section; }

  // The block attributes are a bitmask. You can set them wholesale,
  // or set and clear them individually by bitmasking.
  BlockAttributes attributes() const { return attributes_; }
  void set_attributes(BlockAttributes attributes) { attributes_ = attributes; }

  // Set or clear one or more attributes.
  void set_attribute(BlockAttributes attribute) { attributes_ |= attribute; }
  void clear_attribute(BlockAttributes attribute) {
    attributes_ &= ~attribute;
  }

  // This is true iff data_ is in the ownership of the block.
  // When true, the block will delete [] data_ on destruction.
  bool owns_data() const { return owns_data_; }
  void set_owns_data(bool owns_data) { owns_data_ = owns_data; }

  // Allocates and returns a new data buffer of the given size. The returned
  // data buffer will not have been initialized in any way.
  uint8* AllocateRawData(size_t size);

  // Allocates and returns a new data buffer of the given size. The returned
  // data will have been initialized to zero.
  uint8* AllocateData(size_t size);

  // Makes a copy of data, returns a pointer to the copy.
  uint8* CopyData(size_t size, const void* data);

  // The data bytes the block refers to.
  const uint8* data() const { return data_; }
  void set_data(const uint8* data) { data_ = data; }

  // The data size may be smaller than the block size (see size()),
  // when the block e.g. refers to data that's all or part
  // zero-initialized by the linker/loader.
  size_t data_size() const { return data_size_; }
  void set_data_size(size_t data_size) { data_size_ = data_size; }

  const ReferenceMap& references() const { return references_; }
  const ReferrerSet& referrers() const { return referrers_; }
  const LabelMap& labels() const { return labels_; }

  // Set the reference at @p offset to @p ref.
  // If there's a pre-existing reference at @p offset, this overrides it.
  // @param offset offset of the reference into this block.
  // @param ref the reference to add.
  // @returns true iff this inserts a new reference.
  bool SetReference(Offset offset, const Reference& ref);

  // Retrieve the reference at @p offset if one exists.
  // @param reference on success returns the reference @p offset.
  // @returns true iff there was a reference at @p offset.
  bool GetReference(Offset offset, Reference* reference) const;

  // Remove the reference at @p offset.
  // @returns true iff there was a reference at @p offset.
  bool RemoveReference(Offset offset);

  // Set a label to @p offset.
  // A label in code marks the location of the start of an instruction -
  // e.g. a location where disassembly can usefully commence. Labels
  // appear to be inserted by the VS tool chain where e.g. a switch
  // statement is implemented with a jump table, to note the location
  // of the jump destinations.
  // @returns true iff a new label is inserted.
  // @note that only one label can exist at each offset, and the first
  //     label set at any offset will stay there.
  bool SetLabel(Offset offset, const char* name);

  // Returns true iff the block has a label at @p offset.
  bool HasLabel(Offset offset);

  // Change all references to this block to refer to @p new_block instead,
  // while offsetting each reference by @p offset.
  // @note this fails if any of the transferred references end up with offsets
  //     less than zero, or greater than new_block->size().
  // @returns true iff all references were transferred successfully.
  bool TransferReferrers(Offset offset, Block* new_block);

  // Returns true if this block contains the given range of bytes.
  bool Contains(RelativeAddress address, size_t size) const;

 protected:
  // Give BlockGraph access to our innards for serialization.
  friend class BlockGraph;

  BlockId id_;
  BlockType type_;
  Size size_;
  Size alignment_;
  std::string name_;
  RelativeAddress addr_;
  RelativeAddress original_addr_;

  size_t section_;
  BlockAttributes attributes_;

  ReferenceMap references_;
  ReferrerSet referrers_;
  LabelMap labels_;

  // True iff data_ is ours to deallocate with delete [].
  // If this is false, data_ must be guaranteed to outlive the block.
  bool owns_data_;
  // A pointer to the code or data we represent.
  const uint8* data_;
  // Size of the above.
  size_t data_size_;

  // The following are serialization functions, and are intended for use by
  // the BlockGraph that owns the Block.

  // Serializes basic block properties.
  bool SaveProps(OutArchive* out_archive) const;
  bool LoadProps(InArchive* in_archive);

  // Serializes block data.
  bool SaveData(OutArchive* out_archive) const;
  bool LoadData(InArchive* in_archive);

  // Saves referrers and references.
  bool SaveRefs(OutArchive* out_archive) const;
  bool LoadRefs(BlockGraph& block_graph, InArchive* in_archive);
};

// A graph address space endows a graph with a non-overlapping ordering
// on blocks, where each block occupies zero or one address ranges in the
// address space. No two blocks may overlap in an address space.
class BlockGraph::AddressSpace {
 public:
  typedef core::AddressSpace<RelativeAddress, BlockGraph::Size, Block*>
      AddressSpaceImpl;
  typedef AddressSpaceImpl::Range Range;
  typedef AddressSpaceImpl::RangeMap RangeMap;
  typedef AddressSpaceImpl::RangeMapIter RangeMapIter;
  typedef AddressSpaceImpl::RangeMapConstIter RangeMapConstIter;
  typedef AddressSpaceImpl::RangeMapIterPair RangeMapIterPair;
  typedef AddressSpaceImpl::RangeMapConstIterPair RangeMapConstIterPair;

  // Constructs a new empty address space.
  // @p start to @p start + @p size on @p graph.
  explicit AddressSpace(BlockGraph* graph);

  // Add a block of type @p type and @p size at @p address to our associated
  // graph, and return the new block.
  // @returns the new block, or NULL if the new block would overlap
  //     an existing block.
  Block* AddBlock(BlockType type,
                  RelativeAddress addr,
                  Size size,
                  const char* name);

  // Merges all blocks that intersect @p range into a single block.
  // Moves labels and references from the intersecting blocks to the
  // merged block, and changes referring blocks to refer to the new,
  // merged block. Removes the original blocks from the BlockGraph.
  // @returns the new, merged block if there was at least one intersecting
  //     block in @p range, or NULL otherwise.
  Block* MergeIntersectingBlocks(const Range& range);

  // Insert existing block @p block at @p address.
  // @returns true on succes, or false if the @p block would overlap
  //     an existing block.
  bool InsertBlock(RelativeAddress addr, Block* block);

  // Returns a pointer to the block containing address, or NULL
  // if no block contains address.
  Block* GetBlockByAddress(RelativeAddress addr) const;

  // Returns a pointer to the block containing the address range
  // [address, address + size), or NULL if no block contains that
  // range.
  Block* GetContainingBlock(RelativeAddress addr, Size size) const;

  // Finds the first block, if any that intersects
  // [@p address, @p address + @p size).
  Block* GetFirstIntersectingBlock(RelativeAddress address, Size size);

  // Locates all blocks that intersect [@p address, @p address + @p size).
  // @returns a pair of iterators that iterate over the found blocks.
  RangeMapConstIterPair GetIntersectingBlocks(RelativeAddress address,
                                              Size size) const;
  RangeMapIterPair GetIntersectingBlocks(RelativeAddress address, Size size);

  // Retrieve the address off @p block.
  // @param block the block in question.
  // @param addr on success, returns the address of @p block in this
  //     address space.
  // @returns true on success, false if @p block is not in this
  //     address space.
  bool GetAddressOf(const Block* block, RelativeAddress* addr) const;

  // Accessor.
  BlockGraph* graph() { return graph_; }
  const BlockGraph* graph() const { return graph_; }

  RangeMapConstIter begin() const {
    return address_space_.ranges().begin();
  }

  RangeMapConstIter end() const {
    return address_space_.ranges().end();
  }

  const AddressSpaceImpl& address_space_impl() const {
    return address_space_;
  }

  // For serialization.
  bool Save(OutArchive* out_archive) const;
  bool Load(InArchive* in_archive);

 private:
  bool InsertImpl(RelativeAddress addr, Block* block);

  typedef stdext::hash_map<const Block*, RelativeAddress> BlockAddressMap;

  AddressSpaceImpl address_space_;
  BlockAddressMap block_addresses_;
  BlockGraph* graph_;
};

// Represents a reference from one block to another.
class BlockGraph::Reference {
 public:
  Reference() : type_(RELATIVE_REF), size_(0), referenced_(NULL), offset_(0) {
  }

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

  bool operator==(const Reference& other) const {
    return type_ == other.type_ &&
        size_ == other.size_ &&
        referenced_ == other.referenced_ &&
        offset_ == other.offset_;
  }
 private:
  // Type of this reference.
  ReferenceType type_;

  // Size of this reference.
  // Absolute references are always pointer wide, but PC-relative
  // references can be 1, 2 or 4 bytes wide, which affects their range.
  Size size_;

  // The block referenced.
  Block* referenced_;

  // Offset into the referenced block.
  Offset offset_;
};

}  // namespace core

#endif  // SYZYGY_CORE_BLOCK_GRAPH_H_
