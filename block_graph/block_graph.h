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
//
// A block graph is a an abstract graph of blocks, each of which has an ID,
// a type, a size and a few other properties. Each block represents either code
// or data, and blocks can reference one another through references of various
// types.
//
// The BlockGraph also stores minimum knowledge of sections (names and
// characteristics), and each block belongs to at most one section. In this
// sense, a BlockGraph acts as top-level division of blocks.

#ifndef SYZYGY_BLOCK_GRAPH_BLOCK_GRAPH_H_
#define SYZYGY_BLOCK_GRAPH_BLOCK_GRAPH_H_

#include <hash_map>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "base/basictypes.h"
#include "base/string_piece.h"
#include "syzygy/common/align.h"
#include "syzygy/core/address.h"
#include "syzygy/core/address_space.h"

namespace block_graph {

// The invalid address can never occur in an graph, it's used as default
// value for block addresses.
extern const core::RelativeAddress kInvalidAddress;

// The BlockGraph is a top-level container for Blocks.
class BlockGraph {
 public:
  typedef core::InArchive InArchive;
  typedef core::OutArchive OutArchive;
  typedef core::RelativeAddress RelativeAddress;

  typedef size_t SectionId;
  typedef size_t BlockId;
  typedef size_t Size;
  typedef ptrdiff_t Offset;
  typedef uint32 BlockAttributes;
  typedef uint32 SerializationAttributes;

  // The BlockGraph maintains a list of sections, and each block belongs
  // to one of them. This is the set of information we keep regarding them.
  struct Section;
  // The section map contains all sections, indexed by id.
  typedef std::map<SectionId, Section> SectionMap;

  static const SectionId kInvalidSectionId;

  // Attributes are phrased such that if true for a part, they are also true
  // for the whole. That way, if an attribute is set for any block it can also
  // be set for a block that is created via any merger that contains the
  // original block.
  //
  // For example, the attribute is HAS_INLINE_ASSEMBLY (the positive), rather
  // than HAS_NO_INLINE_ASSEMBLY (the negative).
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
    // This is only filled out post-merging, so does not obey the "true for the
    // part, true for the whole" convention.
    PADDING_BLOCK = (1 << 4),
    // Indicates blocks that contain inline assembly.
    HAS_INLINE_ASSEMBLY = (1 << 5),
    // Indicates that the block was built by a compiler whose precise behaviour
    // and semantics we are unfamiliar with.
    BUILT_BY_UNSUPPORTED_COMPILER = (1 << 6),
    // Indicates that the block has been built by the Syzygy toolchain, and thus
    // is inherently safe for basic-block decomposition without having to
    // perform the myriad of safety checks we do otherwise. This is only ever
    // set long after decomposition, so does not obey the "true for the part,
    // true for the whole" convention.
    BUILT_BY_SYZYGY = (1 << 7),
  };

  // Attributes that can be passed to the save function.
  enum SerializationAttributesEnum {
    DEFAULT = 0,
    OMIT_DATA = (1 << 0),
    OMIT_STRINGS = (1 << 1),
    OMIT_LABELS = (1 << 2),
  };

  enum BlockType {
    CODE_BLOCK,
    DATA_BLOCK,
    BASIC_CODE_BLOCK,
    BASIC_DATA_BLOCK,

    // NOTE: This must always be last, and kBlockType must be kept in sync
    // with this enum.
    BLOCK_TYPE_MAX
  };

  static const char* BlockTypeToString(BlockType type);

  enum LabelType {
    LABEL_TYPE_UNKNOWN,
    CODE_LABEL,
    DATA_LABEL,
    DEBUG_START_LABEL,
    DEBUG_END_LABEL,
    SCOPE_START_LABEL,
    SCOPE_END_LABEL,  // TODO(rogerm): Infer these from block length.
    CALL_SITE_LABEL,
    PADDING_LABEL,

    // Note: This must always be last.
    LABEL_TYPE_MAX
  };

  static const char* LabelTypeToString(LabelType type);

  enum ReferenceType {
    PC_RELATIVE_REF,
    ABSOLUTE_REF,
    RELATIVE_REF,
    FILE_OFFSET_REF,
  };

  // Forward declarations;
  class AddressSpace;
  class Block;
  class Label;
  class Reference;

  // The block map contains all blocks, indexed by id.
  typedef std::map<BlockId, Block> BlockMap;

  BlockGraph();
  ~BlockGraph();

  // Adds a section with the given name.
  //
  // @param name The section name.
  // @param characteristics The section characteristics.
  // @returns the newly created section.
  Section* AddSection(const base::StringPiece& name, uint32 characteristics);

  // Finds a section with the given name, returning NULL if no such section
  // exists.
  //
  // @param name The section name.
  // @returns the section if one is found, NULL otherwise.
  Section* FindSection(const base::StringPiece& name);

  // Find or adds section with the given name.
  //
  // If a section with the given name already exists, updates its
  // characteristics and returns it. Otherwise, creates a new section and
  // returns it. If multiple sections exist with the given name, the first
  // one encountered is returned.
  //
  // TODO(chrisha): The semantics of this function are a little odd. It would
  //     make more sense for it to return only if a section with matching name
  //     AND characteristics is found, otherwise to create a new one.
  //
  // @param name The section name.
  // @param characteristics The section characteristics.
  // @returns the new or found section.
  Section* FindOrAddSection(const base::StringPiece& name,
                            uint32 characteristics);

  // Removes the given section from the BlockGraph.
  //
  // The section must belong to this block graph. Be aware that this can leave
  // Blocks with dangling section_ids.
  //
  // @param section The section to remove.
  // @returns true on success, false otherwise.
  bool RemoveSection(Section* section);

  // Removes the section with the given id from the BlockGraph.
  //
  // @param section The id of the section to remove.
  // @returns true on success, false otherwise.
  bool RemoveSectionById(SectionId id);

  // Add @p block of type @p type and @p size and
  // return the new block.
  // @returns the new block.
  Block* AddBlock(BlockType type, Size size, const base::StringPiece& name);

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
  const SectionMap& sections() const { return sections_; }
  SectionMap& sections_mutable() { return sections_; }
  const BlockMap& blocks() const { return blocks_; }
  BlockMap& blocks_mutable() { return blocks_; }

  // @{
  // Retrieve the section with the given id.
  //
  // @param id The id of the section to retrieve.
  // @returns the section in question or NULL if no such section.
  Section* GetSectionById(SectionId id);
  const Section* GetSectionById(SectionId id) const;
  // @}

  // @{
  // Retrieve the block with id.
  // @returns the block in question or NULL if no such block.
  Block* GetBlockById(BlockId id);
  const Block* GetBlockById(BlockId id) const;
  // @}

  // Serialization is supported at the level of an entire BlockGraph, but not
  // individual blocks. This is because blocks have pointers to other blocks
  // and it is impossible to serialize one without serializing all others. The
  // attributes allow to not serialize some information of the blocks.
  bool Save(OutArchive* out_archive, SerializationAttributes attributes) const;
  // Note that after a 'Load', it is possible to have 'data_size > 0' and
  // 'data == NULL'. This indicates that the block was pointing to data that
  // it did not own. To make the graph fully consistent, the data can be
  // reattached after the graph is loaded. The @p attributes will contain the
  // flags that have been used to save this block-graph.
  bool Load(InArchive* in_archive, SerializationAttributes* attributes);

 private:
  // Removes a block by the iterator to it. The iterator must be valid.
  bool RemoveBlockByIterator(BlockMap::iterator it);

  // Serialization of the attributes of the block-graph.
  bool SaveAttributes(OutArchive* out_archive) const;
  bool LoadAttributes(InArchive* in_archive, size_t* num_blocks);

  // Serialization of the blocks references.
  bool SaveBlocksRefs(OutArchive* out_archive) const;
  bool LoadBlocksRefs(const std::vector<BlockGraph::Block*>& order,
                      size_t num_blocks,
                      InArchive* in_archive);

  // Serialization of a label if needed (depending on the attributes passed).
  bool MaybeSaveLabels(const Block* iter_block,
                       OutArchive* out_archive,
                       SerializationAttributes attributes) const;
  bool MaybeLoadLabels(InArchive* in_archive,
                       SerializationAttributes attributes,
                       Block* block);

  // All sections we contain.
  SectionMap sections_;

  // Our section ID allocator.
  SectionId next_section_id_;

  // All blocks we contain.
  BlockMap blocks_;

  // Our block ID allocator.
  BlockId next_block_id_;
};

// The BlockGraph maintains a list of sections, and each block belongs
// to one of them. This is the set of information we keep regarding them.
struct BlockGraph::Section {
  // Default constructor.
  Section() : id_(kInvalidSectionId), characteristics_(0) {
  }

  // Full constructor.
  //
  // @param id The section id. This must not be kInvalidSectionId.
  // @param name The name of the section. Must not be empty or NULL.
  // @param characteristics The characteristics of the section.
  Section(SectionId id, const base::StringPiece& name, uint32 characteristics)
      : id_(id), name_(), characteristics_(characteristics) {
    DCHECK_NE(kInvalidSectionId, id);
    DCHECK(name != NULL);
    name.CopyToString(&name_);
    DCHECK(!name_.empty());
  }

  // Get the id of this section.
  //
  // @returns the id of the section.
  SectionId id() const { return id_; }

  // Get the name of this section.
  //
  // @returns the section name.
  const std::string& name() const { return name_; }

  // Sets the name for this section.
  //
  // @param name The name of the section. If NULL or empty, this will fail.
  // @returns true if the name is set, false otherwise.
  bool set_name(const base::StringPiece& name);

  // Get the characteristics of this section.
  //
  // @returns the section characteristics.
  uint32 characteristics() const { return characteristics_; }

  // Sets the characteristics for this section.
  //
  // @param characteristics The new characteristics to set.
  void set_characteristics(uint32 characteristics) {
    characteristics_ = characteristics;
  }

  // Sets a one or more additional characteristics for this section.
  //
  // @param characteristic The new characteristic(s) to set for this section.
  void set_characteristic(uint32 characteristic) {
    characteristics_ |= characteristic;
  }

  // Clears one or more characteristics for this section.
  //
  // @param characteristic The characteristic(s) to clear for this section.
  void clear_characteristic(uint32 characteristic) {
    characteristics_ &= ~characteristic;
  }

  // For serializing this Section.
  //
  // @param out_archive The output archive which will store this Section.
  bool Save(OutArchive* out_archive) const;

  // For deserializing this Section.
  //
  // @param in_archive The input archive storing a Section.
  bool Load(InArchive* in_archive);

  // A simple comparison operator for serialization tests.
  bool operator==(const Section& other) const {
    return id_ == other.id_ && name_ == other.name_ &&
        characteristics_ == other.characteristics_;
  }

  // A not-equal comparison operator.
  bool operator!=(const Section& other) const {
    return !operator==(other);
  }

 private:
  // The id of the section. This has no particular meaning other than as a way
  // to identify sections uniquely.
  SectionId id_;
  // The name of the section. This will be truncated to a max of 8 characters
  // on output.
  std::string name_;
  // The section characteristics, a bitmask of IMAGE_SCN_* values.
  uint32 characteristics_;
};

// A label denotes the beginning (or end) of a sub-region within a (code)
// block. In particular, a code label represents an instruction boundary
// at which disassembly can begin and a data label represents the beginning
// of embedded data.
class BlockGraph::Label {
 public:
  // Default constructor.
  Label() : type_(LABEL_TYPE_UNKNOWN) {
  }

  // Full constructor.
  Label(const base::StringPiece& name, LabelType type)
      : name_(name.begin(), name.end()), type_(type) {
    DCHECK_LE(LABEL_TYPE_UNKNOWN, type);
    DCHECK_GT(LABEL_TYPE_MAX, type);
  }

  // @name Accessors.
  // @{
  const std::string& name() const { return name_; }
  LabelType type() const { return type_; }
  // @}

  // Change a label's type.
  void set_type(LabelType new_type) { type_ = new_type; }

  // A helper function for logging and debugging.
  std::string ToString() const;

  // @name Persistence functions.
  // @{
  bool Save(OutArchive* out_archive) const;
  bool Load(InArchive* in_archive);
  // @}

  // Equality comparator for unittesting.
  bool operator==(const Label& other) const {
    return name_ == other.name_ && type_ == other.type_;
  }

 private:
  // The name by which this label is known.
  std::string name_;

  // The disposition of the bytes found at this label.
  LabelType type_;
};


// A block represents a block of either code or data.
//
// Since blocks may be split and up and glued together in arbitrary ways, each
// block maintains an address-space over its data, associating ranges of block
// data to ranges of bytes in the original image. This effectively encodes OMAP
// data, allowing the PDB file to be updated.
//
// Each block also stores references to other blocks in the graph, their
// relative location within the block and their type and size.
//
// Each block has a set of attributes, including a size, a name and a
// "current" address. Most of those attributes are mutable, and are set in the
// process of creating and manipulating images and graph address spaces.
class BlockGraph::Block {
 public:
  // Set of the blocks that have a reference to this block.
  // This is keyed on block and source offset (not destination offset),
  // to allow easily locate and remove the backreferences on change or
  // deletion.
  typedef std::pair<Block*, Offset> Referrer;
  typedef std::set<Referrer> ReferrerSet;

  // Map of references that this block makes to other blocks.
  typedef std::map<Offset, Reference> ReferenceMap;

  // Represents a range of data in this block.
  typedef core::AddressRange<Offset, Size> DataRange;

  // Represents a range of data in the original image.
  typedef core::AddressRange<RelativeAddress, Size> SourceRange;

  // A map between bytes in this block and bytes in the original image.
  typedef core::AddressRangeMap<DataRange, SourceRange> SourceRanges;

  // Typed labels associated with various offsets in the block. Some of these
  // labels (of type CODE_LABEL) represent code start points for disassembly
  // while others (of type DATA_LABEL) represent the start of embedded data
  // within the block. Note that, while possible, it is NOT guaranteed that
  // all basic blocks are marked with a label. Basic block decomposition should
  // dissassemble from the code labels to discover all basic blocks.
  typedef std::map<Offset, Label> LabelMap;

  // Blocks need to be default constructible for serialization.
  Block();

  Block(BlockId id,
        BlockType type,
        Size size,
        const base::StringPiece& name);
  ~Block();

  // Accessors.
  BlockId id() const { return id_; }
  BlockType type() const { return type_; }
  void set_type(BlockType type) { type_ = type; }

  Size size() const { return size_; }
  void set_size(Size size) { size_ = size; }

  const std::string& name() const { return name_; }
  void set_name(const base::StringPiece& name) { name.CopyToString(&name_); }

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

  // The section ID for the block. These IDs are wrt to the SectionMap in the
  // parent BlockGraph.
  SectionId section() const { return section_; }
  void set_section(SectionId section) { section_ = section; }

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
  // Iff true, the block will delete [] data_ on destruction or when
  // data is overwritten.
  bool owns_data() const { return owns_data_; }

  // Makes room for the given amount of data at the given offset. This is
  // special in that it will patch up any labels, source ranges and referrers
  // that land beyond the newly created data, shifting them to the right by
  // @p size. If the data for this block is actually allocated it will also
  // patch up the allocated data by zeroing the newly allocate range of data,
  // and shifting the tail by @p size. If the new data is strictly implicit
  // (offset > data_size), then the allocated data is not affected in any way
  // unless @p always_allocate_data is true.
  //
  // @param offset the offset at which to insert the new data.
  // @param size the size of the new data to be inserted.
  // @param always_allocate_data if true, then data_size will be grown if
  //     necessary to ensure that the newly created data can be written.
  // @pre 0 <= offset <= size()
  void InsertData(Offset offset, Size size, bool always_allocate_data);

  // Removes the data in the given range. This will refuse to remove labels,
  // references and referrers that land in the range, and will fail if any
  // exist. It will also shift any labels, references and referrers that land
  // beyond the end of the removed range. Source ranges will also be fixed. If
  // the removed range lies within the initialized data then the data will also
  // be truncated/shifted as necessary.
  //
  // @param offset the offset at which to remove data.
  // @param size the size of the data to remove, in bytes.
  // @returns true on success, false otherwise.
  // @pre 0 <= offset <= size
  bool RemoveData(Offset offset, Size size);

  // Performs an inline resize of data in a BlockGraph. If the data is shrinking
  // this equates to a RemoveData operation. If it is growing it equates to an
  // InsertData operation.
  //
  // @param offset the offset of the data to resize.
  // @param current_size the current size of the data to resize.
  // @param new_size the desired size of the data.
  // @param always_allocate_data if true, then data_size will be grown if
  //     necessary to ensure that the resized data can be written.
  // @returns true on success, false otherwise.
  // @pre 0 <= offset <= size
  bool InsertOrRemoveData(Offset offset, Size current_size, Size new_size,
                          bool always_allocate_data);

  // Set the data the block refers to.
  // @param data NULL or the data this block refers to.
  //     The underlying data must outlive this block.
  // @param data_size the size of data, or zero if data == NULL.
  // @pre data_size <= size().
  void SetData(const uint8* data, size_t data_size);

  // Allocates and returns a new data buffer of the given size. The returned
  // data will have been initialized to zero.
  // @pre data_size <= size().
  uint8* AllocateData(size_t data_size);

  // Makes a copy of data, returns a pointer to the copy.
  // @pre data_size <= size().
  uint8* CopyData(size_t data_size, const void* data);

  // Resizes data to new_size by truncating or zero-extending the current data.
  // @pre new_size <= size().
  const uint8* ResizeData(size_t new_size);

  // Returns a mutable copy of the block's data. If the block doesn't own
  // the data on entry, it'll be copied and the copy returned to the caller.
  uint8* GetMutableData();

  // The data bytes the block refers to.
  const uint8* data() const { return data_; }

  // The data size may be smaller than the block size (see size()),
  // when the block e.g. refers to data that's all or part
  // zero-initialized by the linker/loader.
  size_t data_size() const { return data_size_; }

  const ReferenceMap& references() const { return references_; }
  const ReferrerSet& referrers() const { return referrers_; }
  const SourceRanges& source_ranges() const { return source_ranges_; }
  SourceRanges& source_ranges() { return source_ranges_; }
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
  // @param offset the offset of the label to set.
  // @param name the name of the label.
  // @param type the type of the label.
  // @returns true iff a new label is inserted.
  // @note that only one label can exist at each offset, and the first
  //     label set at any offset will stay there.
  // @{
  bool SetLabel(Offset offset, const Label& label);
  bool SetLabel(Offset offset, const base::StringPiece& name, LabelType type) {
    return SetLabel(offset, Label(name, type));
  }
  // @}

  // Gets the label at the given @p offset.
  // @param offset the offset of the label to get.
  // @param label the string to receive the label.
  // @return true if the label exists, false otherwise.
  bool GetLabel(Offset offset, Label* label) const;

  // Removes the label at the given @p offset.
  // @param offset the offset of the label to remove.
  // @return true if the label existed and was removed, false it it did not
  //     exist.
  bool RemoveLabel(Offset offset);

  // Returns true iff the block has a label at @p offset.
  // @param offset the offset of the label to search for.
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
  // Allocates and returns a new data buffer of the given size. The returned
  // data buffer will not have been initialized in any way.
  uint8* AllocateRawData(size_t size);

  // Give BlockGraph access to our innards for serialization.
  friend class BlockGraph;

  BlockId id_;
  BlockType type_;
  Size size_;
  Size alignment_;
  std::string name_;
  RelativeAddress addr_;

  SectionId section_;
  BlockAttributes attributes_;

  ReferenceMap references_;
  ReferrerSet referrers_;
  SourceRanges source_ranges_;
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
  bool SaveProps(OutArchive* out_archive,
                 SerializationAttributes attributes) const;
  bool LoadProps(InArchive* in_archive,
                 SerializationAttributes attributes);

  // Serializes block data.
  bool SaveData(OutArchive* out_archive) const;
  bool LoadData(InArchive* in_archive);

  // Serialize the data size.
  bool SaveDataSize(OutArchive* out_archive) const;
  bool LoadDataSize(InArchive* in_archive);

  // Saves referrers and references.
  bool SaveRefs(OutArchive* out_archive) const;
  bool LoadRefs(BlockGraph& block_graph, InArchive* in_archive);

  // Saves the label map.
  bool SaveLabels(OutArchive* out_archive,
                  SerializationAttributes attributes) const;
  bool LoadLabels(InArchive* in_archive,
                  SerializationAttributes attributes);
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
                  const base::StringPiece& name);

  // Merges all blocks that intersect @p range into a single block.
  // Moves labels and references from the intersecting blocks to the
  // merged block, and changes referring blocks to refer to the new,
  // merged block. Removes the original blocks from the BlockGraph.
  // @returns the new, merged block if there was at least one intersecting
  //     block in @p range, or NULL otherwise.
  Block* MergeIntersectingBlocks(const Range& range);

  // Insert existing block @p block at @p address.
  // @returns true on success, or false if the @p block would overlap
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

  // Check whether the address space contains @p block.
  // @param block the block in question.
  // @returns true if the block is in the address space, false otherwise.
  bool ContainsBlock(const Block* block);

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

  size_t size() const {
    return address_space_.ranges().size();
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

// Represents a reference from one block to another. References may be offset.
// That is, they may refer to an object at a given location, but actually point
// to a location that is some fixed distance away from that object. This allows,
// for example, non-zero based indexing into a table. The object that is
// intended to be dereferenced is called the 'base' of the offset.
//
// BlockGraph references are from a location (offset) in one block, to some
// location in another block. The referenced block itself plays the role of the
// 'base' of the reference, with the offset of the reference being stored as
// an integer from the beginning of the block. However, basic block
// decomposition requires breaking the block into smaller pieces and thus we
// need to carry around an explicit base value, indicating which byte in the
// block is intended to be referenced.
//
// A direct reference to a location will have the same value for 'base' and
// 'offset'.
//
// Here is an example:
//
//        /----------\
//        +---------------------------+
//  O     |          B                | <--- Referenced block
//        +---------------------------+      B = base
//  \-----/                                  O = offset
//
class BlockGraph::Reference {
 public:
  Reference() :
      type_(RELATIVE_REF), size_(0), referenced_(NULL), offset_(0), base_(0) {
  }

  // @param type type of reference.
  // @param size size of reference.
  // @param referenced the referenced block.
  // @param offset offset from the beginning of the block of the location to be
  //     explicitly referred to.
  // @param base offset into the block of the location actually being
  //     referenced. This must be strictly within @p referenced.
  Reference(ReferenceType type,
            Size size,
            Block* referenced,
            Offset offset,
            Offset base)
      : type_(type),
        size_(size),
        referenced_(referenced),
        offset_(offset),
        base_(base) {
    DCHECK(IsValid());
  }

  // Copy constructor.
  Reference(const Reference& other)
      : type_(other.type_),
        size_(other.size_),
        referenced_(other.referenced_),
        offset_(other.offset_),
        base_(other.base_) {
  }

  // Accessors.
  ReferenceType type() const { return type_; }
  Size size() const { return size_; }
  Block* referenced() const { return referenced_; }
  Offset offset() const { return offset_; }
  Offset base() const { return base_; }

  // Determines if this is a direct reference. That is, if the actual location
  // being referenced (offset) and the intended location being referenced (base)
  // are the same.
  //
  // @returns true if the reference is direct, false otherwise.
  bool IsDirect() const { return base_ == offset_; }

  // Determines if this is a valid reference, by imposing size constraints on
  // reference types, and determining if the base address of the reference is
  // strictly contained within the referenced block.
  //
  // @returns true if valid, false otherwise.
  bool IsValid() const;

  bool operator==(const Reference& other) const {
    return type_ == other.type_ &&
        size_ == other.size_ &&
        referenced_ == other.referenced_ &&
        offset_ == other.offset_ &&
        base_ == other.base_;
  }

  // The maximum size that a reference may have.
  static const Size kMaximumSize;

  // Returns true if the given reference type and size combination is valid.
  static bool IsValidTypeSize(ReferenceType type, Size size);

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

  // The base of the reference, as in offset in the block. This must be a
  // location strictly within the block.
  Offset base_;
};

}  // namespace block_graph

#endif  // SYZYGY_BLOCK_GRAPH_BLOCK_GRAPH_H_
