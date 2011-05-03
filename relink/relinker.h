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
#include "syzygy/pe/pe_file_builder.h"
#include "syzygy/pe/pe_file_parser.h"

// This base class is used to help track data required for relinking a binary.
// TODO(ericdingle): Find a better place and/or name for this.
class RelinkerBase {
 public:
  typedef core::BlockGraph BlockGraph;
  typedef core::RelativeAddress RelativeAddress;
  typedef pe::PEFileBuilder PEFileBuilder;
  typedef pe::PEFileParser PEFileParser;

  RelinkerBase(const BlockGraph::AddressSpace& original_addr_space,
               BlockGraph* block_graph);
  virtual ~RelinkerBase();

 protected:
  // TODO(siggi): document me.
  virtual bool Initialize(const BlockGraph::Block* original_nt_headers);

  bool CopyDataDirectory(const PEFileParser::PEHeader& original_header);
  bool FinalizeImageHeaders(const PEFileParser::PEHeader& original_header);
  bool WriteImage(const FilePath& output_path);

  typedef BlockGraph::AddressSpace AddressSpace;

  // Copies a section from the old image into the new one.
  bool CopySection(const IMAGE_SECTION_HEADER& section);

  // Copies the blocks identified by iter_pair from the old image into
  // the new one, inserting them in order from insert_at.
  bool CopyBlocks(const AddressSpace::RangeMapConstIterPair& iter_pair,
                  RelativeAddress insert_at);

  size_t original_num_sections() { return original_num_sections_; }
  const IMAGE_SECTION_HEADER* original_sections() { return original_sections_; }
  const BlockGraph::AddressSpace& original_addr_space() {
    return original_addr_space_;
  }
  PEFileBuilder& builder() { return builder_; }

 private:
  // Information from the original image.
  size_t original_num_sections_;
  const IMAGE_SECTION_HEADER* original_sections_;
  const BlockGraph::AddressSpace& original_addr_space_;

  // The builder that we use to construct the new image.
  PEFileBuilder builder_;

  DISALLOW_COPY_AND_ASSIGN(RelinkerBase);
};

// This class keeps track of data we need around during reordering
// and after reordering for PDB rewriting.
class Relinker : public RelinkerBase {
 public:
  typedef core::BlockGraph BlockGraph;

  Relinker(const BlockGraph::AddressSpace& original_addr_space,
           BlockGraph* block_graph);
  ~Relinker();

  // Static wrapper functions to relink an input dll to an output dll.
  static bool Relink(const FilePath& input_dll_path,
                     const FilePath& input_pdb_path,
                     const FilePath& output_dll_path,
                     const FilePath& output_pdb_path,
                     const FilePath& order_file_path);
  static bool Relink(const FilePath& input_dll_path,
                     const FilePath& input_pdb_path,
                     const FilePath& output_dll_path,
                     const FilePath& output_pdb_path,
                     uint32 seed);

 protected:
  static bool Relink(const FilePath& input_dll_path,
                     const FilePath& input_pdb_path,
                     const FilePath& output_dll_path,
                     const FilePath& output_pdb_path,
                     const FilePath& order_file_path,
                     uint32 seed);

  bool Initialize(const BlockGraph::Block* original_nt_headers);

  // TODO(ericdingle): It'd be nice to have a pure virtual function here to
  // copy the sections and reorder the code blocks. The ordering
  // implementation could then be delegated to subclasses

  // Order code blocks using the ordering specified in the order file.
  bool ReorderCode(const FilePath& order_file_path);

  // Randomly reorder code blocks.
  bool RandomlyReorderCode(int seed);

  // Updates the debug information in the debug directory with our new GUID.
  bool UpdateDebugInformation(BlockGraph::Block* debug_directory_block);

  // Call after relinking and finalizing image to create a PDB file that
  // matches the reordered image.
  bool WritePDBFile(const BlockGraph::AddressSpace& original,
                    const FilePath& input_path,
                    const FilePath& output_path);

  const GUID& new_image_guid() { return new_image_guid_; }

 private:
  // The GUID we stamp into the new image and Pdb file.
  GUID new_image_guid_;

  DISALLOW_COPY_AND_ASSIGN(Relinker);
};

#endif  // SYZYGY_RELINK_RELINKER_H_
