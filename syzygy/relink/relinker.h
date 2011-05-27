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

#ifndef SYZYGY_RELINK_RELINKER_H_
#define SYZYGY_RELINK_RELINKER_H_

#include "syzygy/core/block_graph.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/pe_file_builder.h"
#include "syzygy/pe/pe_file_parser.h"
#include "syzygy/reorder/reorderer.h"

#include <base/scoped_ptr.h>

// This base class is used to help track data required for relinking a binary.
// TODO(ericdingle): Find a better place and/or name for this.
class RelinkerBase {
 public:
  typedef core::BlockGraph BlockGraph;
  typedef BlockGraph::AddressSpace AddressSpace;
  typedef core::RelativeAddress RelativeAddress;
  typedef pe::PEFileBuilder PEFileBuilder;
  typedef pe::PEFileParser PEFileParser;
  typedef pe::Decomposer Decomposer;
  typedef reorder::Reorderer Reorderer;

  RelinkerBase();
  virtual ~RelinkerBase();

 protected:
  // Sets up the basic relinker state for the given decomposed image.
  // TODO(rogerm) Logically, the decomposed param should be const. The
  //     blockgraph managed by the decomposed image is used in a mutable
  //     fashion by the relinker (via its PEFileBuilder). The "correct"
  //     fix would probably be to take a copy of the original block graph
  //     and have the builder use that ... but that's a really expensive
  //     concession to make for const-correctness.
  virtual bool Initialize(Decomposer::DecomposedImage& decomposed);

  // Copies data directory header values from the decomposed imaage
  // into the new image under construction.
  bool CopyDataDirectory(const PEFileParser::PEHeader& original_header);

  // Calculates header values for the relinked image, in prep for writing.
  bool FinalizeImageHeaders(const PEFileParser::PEHeader& original_header);

  // Commits the relinked image to disk at the given output path.
  bool WriteImage(const FilePath& output_path);

  // Copies a section from the old image into the new one.
  bool CopySection(const IMAGE_SECTION_HEADER& section);

  // Copies the blocks identified by iter_pair from the old image into
  // the new one, inserting them in order from insert_at.
  bool CopyBlocks(const AddressSpace::RangeMapConstIterPair& iter_pair,
                  RelativeAddress insert_at, size_t* bytes_copied);

  // Queries about the original image.
  size_t original_num_sections() const {
    return original_num_sections_;
  }
  const IMAGE_SECTION_HEADER* original_sections() const {
    return original_sections_;
  }
  const BlockGraph::AddressSpace& original_addr_space() const {
    // TODO(rogerm) Sort out which value to track, the original address
    //     space or the decomposed image, which owns the address space.
    //     This dereference isn't particularly hygeinic.
    CHECK(original_addr_space_ != NULL);
    return *original_addr_space_;
  }

  // Accesses the PE file builder.
  PEFileBuilder& builder() { return *builder_; }

  // Helper to stringify the name of a section.
  std::string GetSectionName(const IMAGE_SECTION_HEADER& section) const;

 private:
  DISALLOW_COPY_AND_ASSIGN(RelinkerBase);

  // Information from the original image.
  size_t original_num_sections_;
  const IMAGE_SECTION_HEADER* original_sections_;
  const BlockGraph::AddressSpace* original_addr_space_;

  // The builder that we use to construct the new image.
  scoped_ptr<PEFileBuilder> builder_;
};

// This class keeps track of data we need around during reordering
// and after reordering for PDB rewriting.
class Relinker : public RelinkerBase {
 public:
  // Default constructor.
  Relinker();

  // Sets the amount of padding to insert between blocks.
  void set_padding_length(size_t length);
  static size_t max_padding_length();
  static const uint8* padding_data();

  // Drives the basic relinking process.  This takes input image and pdb
  // paths and creates correponsing output files at the given output
  // paths, reordering sections as defined by a subclass' ReorderSection
  // method.
  virtual bool Relink(const FilePath& input_dll_path,
                      const FilePath& input_pdb_path,
                      const FilePath& output_dll_path,
                      const FilePath& output_pdb_path);

 protected:
  // Sets up internal state based on the decomposed image.
  bool Initialize(Decomposer::DecomposedImage& decomposed);

  // Returns true if the given section be reordered? There is a default
  // implementation which can be overridden if the subclass supports a
  // different set of sections.  By default, only code sections can be
  // reordered.
  virtual bool IsReorderable(const IMAGE_SECTION_HEADER& section);

  // Performs whatever custom initialization of the order that it required.
  virtual bool SetupOrdering(Reorderer::Order& order) = 0;

  // Function to be overridden by subclasses so that each subclass can have its
  // own reordering implementation.
  virtual bool ReorderSection(size_t section_index,
                              const IMAGE_SECTION_HEADER& section,
                              const Reorderer::Order& order) = 0;

  // Updates the debug information in the debug directory with our new GUID.
  bool UpdateDebugInformation(BlockGraph::Block* debug_directory_block);

  // Call after relinking and finalizing image to create a PDB file that
  // matches the reordered image.
  bool WritePDBFile(const FilePath& input_path,
                    const FilePath& output_path);

  // Returns the GUID for the new image.
  const GUID& new_image_guid() { return new_image_guid_; }

  // Insert a padding block of the configured size at the given location.
  bool InsertPaddingBlock(const RelativeAddress& insert_at,
                          BlockGraph::BlockType block_type,
                          BlockGraph::Block** out_block);

 private:
  DISALLOW_COPY_AND_ASSIGN(Relinker);

  // The GUID we stamp into the new image and Pdb file.
  GUID new_image_guid_;

  // The amount of padding bytes to add between blocks.
  size_t padding_length_;

};

#endif  // SYZYGY_RELINK_RELINKER_H_
