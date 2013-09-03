// Copyright 2013 Google Inc. All Rights Reserved.
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
// The COFF decomposer parses a COFF file and constructs a corresponding
// block graph and image layout.
//
// COFF files are expected to be compiled with function-level linking (/Gy
// in MSVC), and are made of the following parts:
// - a file header;
// - a section table containing section headers;
// - a symbol table followed by a string table;
// - a chunk of raw data for each initialized section;
// - and a relocation table for each section that needs one.
//
// The COFF decomposer creates blocks that mirror that organization:
// - one block for the file and section headers;
// - one block for the symbol table;
// - and a separate block for the string table;
// - one block for the raw data of each section;
// - one unmapped block for each BSS section;
// - and one block for each relocation table.
//
// The different blocks have been split in this way in anticipation of
// modifications that may grow or shrink them independently; symbols may be
// added without the need to shift the contents of the string table.
//
// When working with COFF files, relative addresses in the image layout are
// to be interpreted as file offsets. The two can be converted from and to
// freely, although, for the sake of consistency, file offsets should be
// used in COFF-aware code (e.g., the decomposer and reader), while relative
// addresses can continue to be used elsewhere in generic transforms working
// on blocks.
//
// In addition, the decomposer attaches references to blocks to represent
// connections between blocks that need to be preserved through the
// transforms. There are three kinds of references created, which require
// different handling when assembling and writing back a modified COFF
// file. These differences should not affect other (non-COFF-aware)
// transforms, however.
//
// - Pointer references, from headers and tables to other parts of the COFF
//   file, indicate actual addresses encoded at the source location of the
//   reference; the contents at the source address will require update
//   before writing back.
//
// - Relocation references, from raw section data to other sections,
//   represent COFF relocations. They are NOT encoded at the source address
//   of the reference. Instead, they should be translated to relocations
//   (replacing the associated relocation table) when recomposing a modified
//   COFF file.
//
// - Symbol references, from raw section data to entries within the symbol
//   table, are placeholders. They refer to things that are not physically
//   encoded in the COFF file, such as external functions or uninitialized
//   data. All such occurrences in a COFF file use the symbol table to
//   specify the target to look up. The references in the block graph need
//   to be translated to relocations along with relocation references.

#ifndef SYZYGY_PE_COFF_DECOMPOSER_H_
#define SYZYGY_PE_COFF_DECOMPOSER_H_

#include <windows.h>  // NOLINT
#include <map>

#include "syzygy/pe/coff_file.h"
#include "syzygy/pe/image_layout.h"

namespace pe {

// A CoffDecomposer extracts code and data from a CoffFile into an
// ImageLayout, and the corresponding block graph.
//
// The block graph contains all data from the COFF file as well as
// references for all locations that will need to be relocated on
// output. References include relocations in the code and data sections, as
// well as internal file offset pointers in headers and metadata, such that
// writing back the COFF file only require patching those specific
// references.
class CoffDecomposer {
 public:
  // The separator that is used between the section and COMDAT name in
  // a block name.
  static const char kSectionComdatSep[];

  // Initialize the decomposer for the given image file.
  //
  // @param image_file the image file to decompose; must outlive the
  //     instance of the decomposer.
  explicit CoffDecomposer(const CoffFile& image_file);

  // Decompose the image file into an image layout, including a block
  // graph. The resulting block graph contains the breakdown of code and
  // data blocks with typed references; the remaining components of the
  // layout hold information on where the blocks resided in the original
  // image.
  //
  // @param image_layout the image layout to populate.
  // @returns true on success, false on failure.
  //
  // @note In COFF decomposition, the relative addresses in the block graph
  // and image layout are equal to the file offsets of the COFF file.
  bool Decompose(ImageLayout* image_layout);

 private:
  typedef block_graph::BlockGraph BlockGraph;
  typedef core::FileOffsetAddress FileOffsetAddress;
  typedef core::RelativeAddress BlockGraphAddress;

  // A map from section indexes to the corresponding block in the
  // block graph.
  typedef std::map<size_t, BlockGraph::Block*> SectionBlockMap;

  // @name Decomposition steps.
  // @{
  // Add non-section contents as blocks with associated references in the
  // block graph.
  //
  // @returns true on success, false on failure.
  bool CreateBlocksAndReferencesFromNonSections();

  // Add header contents as blocks with associated references in the block
  // graph.
  //
  // @returns true on success, false on failure.
  bool CreateBlocksAndReferencesFromHeaders();

  // Add the symbol table and string table as blocks with associated
  // references in the block graph.
  //
  // @returns true on success, false on failure.
  bool CreateBlocksAndReferencesFromSymbolAndStringTables();

  // Add every relocation table as a block. We do not track references
  // originating from the relocation tables, as that information is already
  // stored as parsed references from the section data directly to the
  // destination.
  //
  // When needed, the relocation tables will have to be regenerated from the
  // references in each section, in accordance with an up-to-date symbol
  // table. Reference types and sizes contain all the information necessary
  // to infer relocation entries; addresses will need to be converted to
  // symbols through the symbol table.
  //
  // @returns true on success, false on failure.
  bool CreateBlocksFromRelocationTables();

  // Add section contents as blocks in the block graph.
  //
  // @returns true on success, false on failure.
  bool CreateBlocksFromSections();

  // Add references to section blocks created with
  // CreateBlocksFromSections(), computed from the relocation table
  // associated with each section.
  //
  // @returns true on success, false on failure.
  bool CreateReferencesFromRelocations();

  // Add references to debug section blocks created with
  // CreateBlocksFromSections(), for debug symbol offsets and pointers not
  // covered by relocations.
  //
  // Also add attributes to blocks based on debug information.
  //
  // @returns true on success, false on failure.
  bool CreateReferencesFromDebugInfo();

  // Add jump and case table labels to code blocks, based on STATIC entries
  // present in the COFF symbol table.
  //
  // @returns true on success, false on failure.
  bool CreateLabelsFromSymbols();
  // @}

  // Create a new block with the given properties, and data read from the
  // image file.
  //
  // @param type the type of block to create.
  // @param addr the offset where the block starts in the COFF file.
  // @param size the size of data, in bytes.
  // @param name the name of the block, which needs not be unique, but
  //     should be informative.
  // @returns the new block, or NULL if it would overlap with an existing
  //     block.
  BlockGraph::Block* CreateBlock(BlockGraph::BlockType type,
                                 FileOffsetAddress addr,
                                 BlockGraph::Size size,
                                 const base::StringPiece& name);

  // Create a reference as specified, ignoring any existing identical
  // reference at the same source offset.
  //
  // @param src_addr the source offset where the reference is located.
  // @param ref_type the type of reference to create.
  // @param ref_size the size of the reference to create.
  // @param target the destination block of the reference.
  // @param offset the offset within @p target to the destination.
  // @returns true on success, false on failure.
  bool CreateReference(FileOffsetAddress src_addr,
                       BlockGraph::ReferenceType ref_type,
                       BlockGraph::Size ref_size,
                       BlockGraph::Block* target,
                       BlockGraph::Offset offset);

  // Create a reference to the specified file offset, ignoring any existing
  // identical reference at the same source offset.
  //
  // @param src_addr the source offset where the reference is located.
  // @param ref_type the type of reference to create.
  // @param ref_size the size of the reference to create.
  // @param dst_addr the destination, as an offset within the COFF file.
  // @returns true on success, false on failure.
  bool CreateFileOffsetReference(FileOffsetAddress src_addr,
                                 BlockGraph::ReferenceType ref_type,
                                 BlockGraph::Size ref_size,
                                 FileOffsetAddress dst_addr);

  // Create a reference to the specified section offset, ignoring any
  // existing identical reference at the same source offset.
  //
  // @param src_addr the source offset where the reference is located.
  // @param ref_type the type of reference to create.
  // @param ref_size the size of the reference to create.
  // @param section_index the destination section of the reference.
  // @param section_offset the offset to the destination within the section.
  // @returns true on success, false on failure.
  bool CreateSectionOffsetReference(FileOffsetAddress src_addr,
                                    BlockGraph::ReferenceType ref_type,
                                    BlockGraph::Size ref_size,
                                    size_t section_index,
                                    size_t section_offset);

  // Create a reference to the specified symbol, ignoring any existing
  // identical reference at the same source offset.
  //
  // References to symbols differ from normal references in that they may
  // point either to the actual target of the symbol, or to the symbol
  // itself if it is unbound in the object file (external symbol).
  //
  // If @p symbol is an external symbol, then @p offset is ignored and
  // should be set to either 0 (for a section reference) or the value of the
  // Value field of @p symbol (for a normal reference).
  //
  // @param src_addr the source offset where the reference is located.
  // @param ref_type the type of reference to create.
  // @param ref_size the size of the reference to create.
  // @param symbol the destination symbol of the reference.
  // @param offset the offset from @p symbol to the destination; ignored for
  //     external symbols.
  // @returns true on success, false on failure.
  bool CreateSymbolOffsetReference(FileOffsetAddress src_addr,
                                   BlockGraph::ReferenceType ref_type,
                                   BlockGraph::Size ref_size,
                                   const IMAGE_SYMBOL* symbol,
                                   size_t offset);

  // Translate a file offset to a block and offset within that block.
  // Translated offsets are always positive or zero and fall within
  // the boundaries of the block.
  //
  // @param addr the file offset to translate.
  // @param block where to store the resulting block pointer.
  // @param offset where to store the resulting offset.
  // @returns true on success, false on failure; on failure, the
  //     contents of the output arguments is unspecified.
  bool FileOffsetToBlockOffset(FileOffsetAddress addr,
                               BlockGraph::Block** block,
                               BlockGraph::Offset* offset);

  // Translate a section index and offset to a block and offset within that
  // block. Translated offsets are always positive or zero and fall within
  // the boundaries of the block.
  //
  // @param section_index the index of the section.
  // @param section_offset the offset within that section.
  // @param block where to store the resulting block pointer.
  // @param offset where to store the resulting offset.
  // @returns true on success, false on failure; on failure, the
  //     contents of the output arguments is unspecified.
  bool SectionOffsetToBlockOffset(size_t section_index, size_t section_offset,
                                  BlockGraph::Block** block,
                                  BlockGraph::Offset* offset);

  // Convert a file offset to a relative address suitable for use in the
  // block graph and associated structures. The values of the address
  // objects will be equal.
  //
  // @param addr the file offset to translate.
  // @returns a relative address with the same value as the file offset.
  BlockGraphAddress FileOffsetToBlockGraphAddress(FileOffsetAddress addr);

  // The CoffFile that is being decomposed.
  const CoffFile& image_file_;

  // A map from section indexes to the corresponding block in the block
  // graph.
  SectionBlockMap section_block_map_;

  // @name Temporaries that are only valid while inside of Decompose().
  // @{
  // The image layout we are building.
  ImageLayout* image_layout_;

  // The image address space we are decomposing to.
  BlockGraph::AddressSpace* image_;
  // @}
};

}  // namespace pe

#endif  // SYZYGY_PE_COFF_DECOMPOSER_H_
