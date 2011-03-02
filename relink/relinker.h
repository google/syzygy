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

// This class keeps track of data we need around during reordering
// and after reordering for PDB rewriting.
class Relinker {
 public:
  typedef core::BlockGraph BlockGraph;
  typedef core::RelativeAddress RelativeAddress;
  typedef pe::PEFileBuilder PEFileBuilder;
  typedef pe::PEFileParser PEFileParser;

  explicit Relinker(const BlockGraph::AddressSpace& original_addr_space,
                    BlockGraph* block_graph);

  // TODO(siggi): document me.
  bool Initialize(const BlockGraph::Block* original_nt_headers);
  bool RandomlyReorderCode(unsigned int seed);

  // Updates the debug information in the debug directory with our new GUID.
  bool UpdateDebugInformation(BlockGraph::Block* debug_directory_block);

  bool CopyDataDirectory(PEFileParser::PEHeader* original_header);
  bool FinalizeImageHeaders(BlockGraph::Block* original_dos_header);
  bool WriteImage(const FilePath& output_path);

  // Call after relinking and finalizing image to create a PDB file that
  // matches the reordered image.
  bool WritePDBFile(const BlockGraph::AddressSpace& original,
                    const FilePath& input_path,
                    const FilePath& output_path);

  PEFileBuilder& builder() { return builder_; }

 private:
  typedef BlockGraph::AddressSpace AddressSpace;

  // Copies the blocks identified by iter_pair from the new image into
  // the new one, inserting them in order from insert_at.
  bool CopyBlocks(const AddressSpace::RangeMapConstIterPair& iter_pair,
                  RelativeAddress insert_at);

  // Information from the original image.
  size_t original_num_sections_;
  const IMAGE_SECTION_HEADER* original_sections_;
  const BlockGraph::AddressSpace& original_addr_space_;

  // The GUID we stamp into the new image and Pdb file.
  GUID new_image_guid_;

  // The builder that we use to construct the new image.
  PEFileBuilder builder_;
};

#endif  // SYZYGY_RELINK_RELINKER_H_
