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
// The decomposer decomposes a given image file into a series of blocks
// and references by reference to the image's symbols and disassembled
// executable code.
#ifndef SYZYGY_PE_DECOMPOSER_H_
#define SYZYGY_PE_DECOMPOSER_H_

#include <windows.h>
#include <dbghelp.h>
#include <dia2.h>
#include <map>
#include <set>
#include <string>
#include "base/file_path.h"
#include "syzygy/core/block_graph.h"
#include "syzygy/core/disassembler.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/pe/pe_file_parser.h"

namespace pe {

class Decomposer {
 public:
  typedef core::BlockGraph BlockGraph;
  typedef core::Disassembler Disassembler;
  typedef core::RelativeAddress RelativeAddress;

  // Initializes the decomposer for a given image file and path.
  Decomposer(const PEFile& image_file, const FilePath& file_path);

  // The decomposed image data.
  class DecomposedImage;

  // Decomposes the image file into the specified DecomposedImage, which
  // has the breakdown of code and data blocks with typed references.
  // @returns true on success, false on failure.
  bool Decompose(DecomposedImage* image);

 protected:
  // Create blocks for all code.
  bool CreateCodeBlocks(IDiaSymbol* globals);
  // Create blocks for all functions in @p globals.
  bool CreateFunctionBlocks(IDiaSymbol* globals);
  // Create a function block for @p function.
  // @pre @p function is a function or a thunk.
  bool CreateFunctionBlock(IDiaSymbol* function);
  // Create labels for @p function, which corresponds to @p block.
  bool CreateLabelsForFunction(IDiaSymbol* function, BlockGraph::Block* block);
  // Create blocks for all thunks in @p globals.
  // @note thunks are offspring of Compilands.
  bool CreateThunkBlocks(IDiaSymbol* globals);
  // Enumerates labels in @p globals and add them to the
  // corresponding (code) blocks.
  bool CreateGlobalLabels(IDiaSymbol* globals);

  // Create blocks of type @p block_type for any gaps in the image
  // section represented by @p header.
  bool CreateSectionGapBlocks(const IMAGE_SECTION_HEADER* header,
                              BlockGraph::BlockType block_type);

  // Create blocks for all data segments.
  bool CreateDataBlocks(IDiaSymbol* globals);
  bool CreateDataBlock(IDiaSymbol* data);

  // Translates intermediate references to block->block references.
  bool FinalizeIntermediateReferences();

  // Adds an intermediate reference from @p src_addr to @p dst_addr of
  // type @p type and size @p size with optional name @p name.
  // @returns true iff the reference was added, e.g. there was not already
  //    a reference at @p src_addr.
  bool AddReference(RelativeAddress src_addr,
                    BlockGraph::ReferenceType type,
                    BlockGraph::Size size,
                    RelativeAddress dst_addr,
                    const char* name);
  // Adds an intermediate reference from @p src_addr to @p dst_addr of
  // type @p type and size @p size with optional name @p name.
  void AddReferenceCallback(RelativeAddress src_addr,
                            BlockGraph::ReferenceType type,
                            BlockGraph::Size size,
                            RelativeAddress dst_addr,
                            const char* name);

  // Walk relocations and create cross-block references.
  bool CreateRelocationReferences();
  // Disassemble all code blocks and create code->code references.
  bool CreateCodeReferences();
  // Disassemble @p block and invoke @p on_instruction for each instruction
  // encountered.
  bool CreateCodeReferencesForBlock(
      BlockGraph::Block* block,
      Disassembler::InstructionCallback *on_instruction);

  // Schedules the address range covering block1 and block2 for merging.
  void ScheduleForMerging(BlockGraph::Block* block1, BlockGraph::Block* block2);

  // Parses the PE BlockGraph header and other important PE structures,
  // adds them as blocks to the image, and creates the references
  // they contain.
  bool CreatePEImageBlocksAndReferences(PEFileParser::PEHeader* header);

  // Create block for the given @p address and @p size of the given @p type,
  // or return an existant block that has the same @p type, @p address and
  // @p size.
  // @returns the block created or found, or NULL if there's a conflicting block
  //    for the address range.
  BlockGraph::Block* FindOrCreateBlock(BlockGraph::BlockType type,
                                       RelativeAddress address,
                                       BlockGraph::Size size,
                                       const char* name);

  // Called through a callback during function disassembly.
  void OnInstruction(const Disassembler& disassembler,
                     const _DInst& instruction,
                     bool* terminate_walk);

  // The image address space we're decomposing to.
  BlockGraph::AddressSpace* image_;

  // The image file we're decomposing and its path.
  // Note that the resultant BlockGraph will contain pointers to the
  // data in the image file, so the user must ensure the image file
  // outlives the BlockGraph.
  const PEFile& image_file_;
  FilePath file_path_;

  // During decomposition we collect references in this format, e.g.
  // address->address. After thunking up the entire image into blocks,
  // we convert them to block->block references.
  // TODO(siggi): Is there reason to keep these in an address space to guard
  //     against overlapping references?
  struct IntermediateReference {
    BlockGraph::ReferenceType type;
    BlockGraph::Size size;
    RelativeAddress destination;
    std::string name;
  };
  typedef std::map<RelativeAddress, IntermediateReference>
      IntermediateReferenceMap;
  IntermediateReferenceMap references_;

  // Disassembly state.
  typedef std::set<BlockGraph::Block*> BlockSet;
  typedef std::set<BlockGraph::AddressSpace::Range> RangeSet;

  // The block we're currently disassembling.
  BlockGraph::Block* current_block_;
  // This set keeps track of which blocks we've yet to disassemble.
  BlockSet to_disassemble_;
  // This set keeps track of address ranges that we want to merge because
  // we've found control flow from one block to another within the range,
  // either through short branches or by execution continuing past the tail
  // of a block.
  RangeSet to_merge_;
};

// The results of the decomposition process are stored in this class.
class Decomposer::DecomposedImage {
 public:
  DecomposedImage() : address_space(&image) {
  }

 public:
  BlockGraph image;
  BlockGraph::AddressSpace address_space;
  PEFileParser::PEHeader header;
};

}  // namespace pe

#endif  // SYZYGY_PE_DECOMPOSER_H_
