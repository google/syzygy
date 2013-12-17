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
// A block graph is an abstract graph of blocks, each of which has an ID, a
// type, a size and a few other properties. Each block represents either code or
// data, and blocks can reference one another through references of various
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
#include "base/file_util.h"
#include "base/string_piece.h"
#include "syzygy/common/align.h"
#include "syzygy/core/address.h"
#include "syzygy/core/address_space.h"
#include "syzygy/core/string_table.h"

namespace block_graph {

// Forward declaration.
class BlockGraphSerializer;

// NOTE: When adding attributes be sure to update any uses of them in
//       block_graph.cc, for example in MergeIntersectingBlocks.
#define BLOCK_ATTRIBUTE_ENUM(F) \
    /* Set for functions declared non-returning. */ \
    F(NON_RETURN_FUNCTION) \
    /* Set for blocks that are inferred by the decomposer. */ \
    F(GAP_BLOCK) \
    /* Set for blocks that are parsed by the PEFileParser. These */ \
    /* blocks are unmovable, indivisible, etc, and have to be treated */ \
    /* specially. */ \
    F(PE_PARSED) \
    /* Set for blocks that are created from section contribution */ \
    /* information or directly from COFF sections. */ \
    F(SECTION_CONTRIB) \
    /* This is used to indicate that a block consists purely of padding */ \
    /* data. */ \
    F(PADDING_BLOCK) \
    /* Indicates blocks that contain inline assembly. */ \
    F(HAS_INLINE_ASSEMBLY) \
    /* Indicates that the block was built by a compiler whose precise */ \
    /* behaviour and semantics we are unfamiliar with. */ \
    F(BUILT_BY_UNSUPPORTED_COMPILER) \
    /* Indicates that the block has been built by the Syzygy toolchain, and */ \
    /* thus is inherently safe for basic-block decomposition without having */ \
    /* to perform the myriad of safety checks we do otherwise. */ \
    F(BUILT_BY_SYZYGY) \
    /* This is set for blocks whose initial disassembly was incomplete. */ \
    /* This is not necessarily an error, as we see have seen blocks with */ \
    /* unreachable code, even in release mode. */ \
    /* DEPRECATED AND DISAPPEARING WITH THE OLD DECOMPOSER. */ \
    F(INCOMPLETE_DISASSEMBLY) \
    /* This is set for blocks whose disassembly was unable to finish due to */ \
    /* an error. This block has violated assumptions that we make or */ \
    /* conventions that we have observed the compiler to use. It is not safe */\
    /* for basic block disassembly. */ \
    F(ERRORED_DISASSEMBLY) \
    /* This is set for functions that have exception handling enabled. */ \
    /* Without delving far deeper into the specifics, it is unsafe to basic */ \
    /* block decompose these blocks. */ \
    F(HAS_EXCEPTION_HANDLING) \
    /* This is set for blocks whose disassembly went off the end of the */ \
    /* block, or into data. These blocks have control flow that we are not */ \
    /* aware of, or are otherwise malformed. */ \
    /* DEPRECATED AND DISAPPEARING WITH THE OLD DECOMPOSER. */ \
    F(DISASSEMBLED_PAST_END) \
    /* This is set for blocks that have a thunk symbol pointing to them. */ \
    /* Typically thunk blocks are compiler or linker-generated, such as */ \
    /* e.g. import thunks, delay load import thunks, etc. */ \
    F(THUNK) \
    /* This is set for blocks that have been parsed as COFF groups. The */ \
    /* contents of these blocks are semantically indivisible. */ \
    F(COFF_GROUP) \
    /* COFF headers block; not set for PE. */ \
    F(COFF_HEADERS) \
    /* COFF symbol table. */ \
    F(COFF_SYMBOL_TABLE) \
    /* COFF string table. */ \
    F(COFF_STRING_TABLE) \
    /* COFF relocation table; these should be ignored when dealing with */ \
    /* block graphs, as all the information is represented as references. */ \
    F(COFF_RELOC_DATA) \
    /* COFF BSS (unmapped) block; has size but no data. */ \
    F(COFF_BSS) \
    /* This always needs to be set to the next available attribute bit. */ \
    F(BLOCK_ATTRIBUTES_MAX)

// The BlockGraph is a top-level container for Blocks.
class BlockGraph {
 public:
  typedef core::RelativeAddress RelativeAddress;

  typedef size_t SectionId;
  typedef size_t BlockId;
  typedef size_t Size;
  typedef ptrdiff_t Offset;
  typedef uint32 BlockAttributes;
  typedef uint32 LabelAttributes;

  // The BlockGraph maintains a list of sections, and each block belongs
  // to one of them. This is the set of information we keep regarding them.
  struct Section;
  // The section map contains all sections, indexed by id.
  typedef std::map<SectionId, Section> SectionMap;

  static const SectionId kInvalidSectionId;

  // Assign distinct bit IDs to each attribute constant.
  enum BlockAttributeIdEnum {
#define DECLARE_ENUM_BIT(name) name##_BIT,
    BLOCK_ATTRIBUTE_ENUM(DECLARE_ENUM_BIT)
#undef DECLARE_ENUM_BIT
  };

  enum BlockAttributeEnum {
#define DECLARE_ENUM(name) name = (1 << name##_BIT),
    BLOCK_ATTRIBUTE_ENUM(DECLARE_ENUM)
#undef DECLARE_ENUM
  };

  // Returns a string containing the names of the supplied attributes.
  static std::string BlockAttributesToString(BlockAttributes attrs);

  enum BlockType {
    CODE_BLOCK,
    DATA_BLOCK,

    // NOTE: This must always be last, and kBlockType must be kept in sync
    // with this enum.
    BLOCK_TYPE_MAX
  };

  static const char* BlockTypeToString(BlockType type);

  // Label attributes. Attributes of the form _END_LABEL type actually
  // point to the first byte past the range they delineate. To make the
  // semantics of moving labels easier, we shift these labels left by one and
  // make them follow the last byte of the delineated range.
  enum LabelAttributesEnum {
    // The label points to an entry-point in a code block.
    CODE_LABEL = (1 << 0),

    // Mark the start and end of the debuggable portion of a code block.
    DEBUG_START_LABEL = (1 << 1),
    DEBUG_END_LABEL = (1 << 2),

    // Mark the start and end of an embedded scope in a code block.
    SCOPE_START_LABEL = (1 << 3),
    SCOPE_END_LABEL = (1 << 4),

    // Marks the location of a (virtual table?) call.
    CALL_SITE_LABEL = (1 << 5),

    // The label points to the start of a jump table. The length is inferred
    // by the location of the next label, or the end of the block. This will
    // also have DATA_LABEL set.
    JUMP_TABLE_LABEL = (1 << 6),
    // The label points to the start of a case table. The length is inferred
    // by the location of the next label, or the end of the block. This will
    // also have DATA_LABEL set.
    CASE_TABLE_LABEL = (1 << 7),
    // The label originated from a data symbol. The length is inferred by the
    // location of the next label, or the end of the block. The type of data
    // is unknown.
    DATA_LABEL = (1 << 8),

    // Used to mark a label that was derived from a public symbol. These are
    // usually actually pointing to code and global data symbols, but we can't
    // always tell (there may be public symbols pointing to data in a code
    // block).
    PUBLIC_SYMBOL_LABEL = (1 << 9),

    // This always needs to be the most significant bit.
    LABEL_ATTRIBUTES_MAX = (1 << 10),
  };

  static std::string LabelAttributesToString(LabelAttributes label_attributes);

  enum ReferenceType {
    // Common reference types.
    PC_RELATIVE_REF,
    ABSOLUTE_REF,
    RELATIVE_REF,
    FILE_OFFSET_REF,

    // Object-file reference types.
    SECTION_REF,
    SECTION_OFFSET_REF,

    // Relocation reference types.
    RELOC_REF_BIT = 1u << 3,
    RELOC_PC_RELATIVE_REF = PC_RELATIVE_REF | RELOC_REF_BIT,
    RELOC_ABSOLUTE_REF = ABSOLUTE_REF | RELOC_REF_BIT,
    RELOC_RELATIVE_REF = RELATIVE_REF | RELOC_REF_BIT,
    RELOC_SECTION_REF = SECTION_REF | RELOC_REF_BIT,
    RELOC_SECTION_OFFSET_REF = SECTION_OFFSET_REF | RELOC_REF_BIT,

    // Must be last!
    REFERENCE_TYPE_MAX,
  };

  // Forward declarations.
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
  const Section* FindSection(const base::StringPiece& name) const;

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
  // @param id The id of the section to remove.
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

  // Get the string table.
  // @returns the string table of this BlockGraph.
  core::StringTable& string_table() { return string_table_; }

 private:
  // Give BlockGraphSerializer access to our innards for serialization.
  friend BlockGraphSerializer;

  // Removes a block by the iterator to it. The iterator must be valid.
  bool RemoveBlockByIterator(BlockMap::iterator it);

  // All sections we contain.
  SectionMap sections_;

  // Our section ID allocator.
  SectionId next_section_id_;

  // All blocks we contain.
  BlockMap blocks_;

  // Our block ID allocator.
  BlockId next_block_id_;

  // A string table used to intern strings.
  core::StringTable string_table_;

  DISALLOW_COPY_AND_ASSIGN(BlockGraph);
};

// The BlockGraph maintains a list of sections, and each block belongs
// to one of them. This is the set of information we keep regarding them.
struct BlockGraph::Section {
  // Default constructor. Required for serialization.
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

  // @name Serialization functions.
  // @{
  bool Save(core::OutArchive* out_archive) const;
  bool Load(core::InArchive* in_archive);
  // @}

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
  Label() : attributes_(0) {
  }

  // Full constructor.
  Label(const base::StringPiece& name, LabelAttributes attributes)
      : name_(name.begin(), name.end()), attributes_(attributes) {
  }

  // Copy construction.
  Label(const Label& other)
      : name_(other.name_), attributes_(other.attributes_) {
  }

  // @name Accessors.
  // @{
  const std::string& name() const { return name_; }
  // @}

  // A helper function for logging and debugging.
  std::string ToString() const;

  // Equality comparator for unittesting.
  bool operator==(const Label& other) const {
    return name_ == other.name_ && attributes_ == other.attributes_;
  }

  // The label attributes are a bitmask. You can set them wholesale,
  // or set and clear them individually by bitmasking.
  LabelAttributes attributes() const { return attributes_; }
  void set_attributes(LabelAttributes attributes) { attributes_ = attributes; }

  // Set or clear one or more attributes.
  void set_attribute(LabelAttributes attribute) { attributes_ |= attribute; }
  void clear_attribute(LabelAttributes attribute) { attributes_ &= ~attribute; }

  // Determines if all or any of the given attributes are set.
  bool has_attributes(LabelAttributes attributes) const {
    return (attributes_ & attributes) == attributes;
  }
  bool has_any_attributes(LabelAttributes attributes) const {
    return (attributes_ & attributes) != 0;
  }

  // @returns true if this label is valid, false otherwise.
  bool IsValid() const;

  // Tests a set of label attributes for validity.
  // @param attributes the attributes to test.
  // @returns true if the provided attributes are valid, false otherwise.
  static bool AreValidAttributes(LabelAttributes attributes);

 private:
  // The name by which this label is known.
  std::string name_;

  // The disposition of the bytes found at this label.
  LabelAttributes attributes_;
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
  // to allow one to easily locate and remove the backreferences on change or
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

  // The flags that can be passed to the TransferReferrers function.
  enum TransferReferrersFlags {
    kSkipInternalReferences = (1 << 0),
    kTransferInternalReferences = (1 << 1)
  };

  // Typed labels associated with various offsets in the block. Some of these
  // labels (of type CODE_LABEL) represent code start points for disassembly
  // while others (of type DATA_LABEL) represent the start of embedded data
  // within the block. Note that, while possible, it is NOT guaranteed that
  // all basic blocks are marked with a label. Basic block decomposition should
  // disassemble from the code labels to discover all basic blocks.
  typedef std::map<Offset, Label> LabelMap;

  ~Block();

  // Accessors.
  BlockId id() const { return id_; }
  BlockType type() const { return type_; }
  void set_type(BlockType type) { type_ = type; }

  Size size() const { return size_; }

  // Set the total size of the block. Note that allocated data_size_ must
  // always be less than or equal to the total size.
  void set_size(Size size) {
    DCHECK_LE(data_size_, size);
    size_ = size;
  }

  const std::string& name() const {
    DCHECK(name_ != NULL);
    return *name_;
  }
  void set_name(const base::StringPiece& name);

  const std::string& compiland_name() const;
  void set_compiland_name(const base::StringPiece& name);

  Size alignment() const { return alignment_; }
  void set_alignment(Size alignment) {
    // Ensure that alignment is a non-zero power of two.
    DCHECK(common::IsPowerOfTwo(alignment));
    alignment_ = alignment;
  }

  // The address of the block is set any time the block is assigned
  // an address in an address space.
  RelativeAddress addr() const { return addr_; }
  void set_addr(RelativeAddress addr) { addr_ = addr; }

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
  // @pre data_size > 0.
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

  // Returns true if there are any other blocks holding a reference to this one.
  bool HasExternalReferrers() const;

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

  // Remove all references from this block. This is handy when removing a block
  // from the block graph.
  bool RemoveAllReferences();

  // Set a label to @p offset.
  // A label in code marks the location of the start of an instruction -
  // e.g. a location where disassembly can usefully commence. Labels
  // appear to be inserted by the VS tool chain where e.g. a switch
  // statement is implemented with a jump table, to note the location
  // of the jump destinations.
  // @param offset the offset of the label to set.
  // @param name the name of the label.
  // @param attributes the attributes of the label.
  // @returns true iff a new label is inserted.
  // @note that only one label can exist at each offset, and the first
  //     label set at any offset will stay there.
  // @{
  bool SetLabel(Offset offset, const Label& label);
  bool SetLabel(Offset offset,
                const base::StringPiece& name,
                LabelAttributes attributes) {
    return SetLabel(offset, Label(name, attributes));
  }
  // @}

  // Gets the label at the given @p offset.
  // @param offset the offset of the label to get.
  // @param label the string to receive the label.
  // @returns true if the label exists, false otherwise.
  bool GetLabel(Offset offset, Label* label) const;

  // Removes the label at the given @p offset.
  // @param offset the offset of the label to remove.
  // @returns true if the label existed and was removed, false it it did not
  //     exist.
  bool RemoveLabel(Offset offset);

  // Returns true iff the block has a label at @p offset.
  // @param offset the offset of the label to search for.
  bool HasLabel(Offset offset) const;

  // Change all references to this block to refer to @p new_block instead,
  // while offsetting each reference by @p offset.
  // @param offset The offset that we should apply to each reference.
  // @param new_block The block the reference should point to.
  // @param flags The flags that control some parameters of this function.
  // @note this fails if any of the transferred references end up with offsets
  //     less than zero, or greater than new_block->size().
  // @returns true iff all references were transferred successfully.
  bool TransferReferrers(Offset offset,
                         Block* new_block,
                         TransferReferrersFlags flags);

  // Returns true if this block contains the given range of bytes.
  bool Contains(RelativeAddress address, size_t size) const;

 protected:
  // Give BlockGraph access to our innards for serialization.
  friend class BlockGraph;
  // Give BlockGraphSerializer access to our innards for serialization.
  friend class BlockGraphSerializer;

  // Full constructor.
  // @note This is protected so that blocks may only be created via the
  //     BlockGraph factory.
  Block(BlockId id,
        BlockType type,
        Size size,
        const base::StringPiece& name,
        BlockGraph* block_graph);

  // This constructor is used by serialization.
  explicit Block(BlockGraph* block_graph);

  // Allocates and returns a new data buffer of the given size. The returned
  // data buffer will not have been initialized in any way.
  uint8* AllocateRawData(size_t size);

  BlockId id_;
  BlockType type_;
  Size size_;
  Size alignment_;
  const std::string* name_;
  const std::string* compiland_name_;
  RelativeAddress addr_;

  // BlockGraph to which belongs this Block. A block can only belongs to one
  // Block Graph.
  BlockGraph* block_graph_;

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
};

// A graph address space endows a graph with a non-overlapping ordering
// on blocks, where each block occupies zero or one address ranges in the
// address space. No two blocks may overlap in an address space. Empty blocks
// are not stored in the underlying address-space implementation itself, but do
// have associated addresses and are stored in the block-address map.
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
  typedef stdext::hash_map<const Block*, RelativeAddress> BlockAddressMap;

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

  // Resizes a block in the address-space by extending to the right, or
  // trimming. Updates the block size but does not udpate its contents. This
  // invalidates any RangeMap iterators to the block in question.
  // @param block The block whose size is to change.
  // @param size The new size of the block. Must be > 0.
  // @returns true on success, false if not possible due to a conflict.
  bool ResizeBlock(Block* block, size_t size);

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

  // @returns the number of blocks in the address-space. This includes empty
  //     blocks, which won't actually be visited by iteration.
  size_t size() const {
    // We use the size of the map of addresses, as zero sized blocks only live
    // there.
    return block_addresses_.size();
  }

  // @returns a reference to the underlaying address-space implementation. Only
  //     non-empty blocks are inserted in the address space.
  const AddressSpaceImpl& address_space_impl() const {
    return address_space_;
  }

  // @returne a reference to the map of blocks addresses, by block pointer.
  const BlockAddressMap& block_addresses() const {
    return block_addresses_;
  }

 protected:
  bool InsertImpl(RelativeAddress addr, Block* block);

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

  // The maximum size that a reference may have. This needs to be kept in sync
  // with the expectations of IsValid().
  static const size_t kMaximumSize = 4;

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

// Commonly used container types.
typedef std::vector<BlockGraph::Block*> BlockVector;
typedef std::vector<const BlockGraph::Block*> ConstBlockVector;

}  // namespace block_graph

#endif  // SYZYGY_BLOCK_GRAPH_BLOCK_GRAPH_H_
