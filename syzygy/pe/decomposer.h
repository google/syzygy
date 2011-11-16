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
#include <dia2.h>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "base/file_path.h"
#include "pcrecpp.h"  // NOLINT
#include "syzygy/block_graph/basic_block_disassembler.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/core/disassembler.h"
#include "syzygy/core/serialization.h"
#include "syzygy/pdb/pdb_data.h"
#include "syzygy/pe/dia_browser.h"
#include "syzygy/pe/image_layout.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/pe/pe_file_parser.h"

namespace pe {

using pcrecpp::RE;

class Decomposer {
 public:
  // Output type for basic block decomposition.
  class BasicBlockBreakdown;
  // A struct for storing fixups.
  struct Fixup;
  // Used for storing references before the block graph is complete.
  struct IntermediateReference;

  typedef core::RelativeAddress RelativeAddress;
  typedef core::AddressSpace<RelativeAddress, size_t, std::string> DataSpace;
  typedef block_graph::BasicBlockDisassembler BasicBlockDisassembler;
  typedef block_graph::BlockGraph BlockGraph;
  typedef core::Disassembler Disassembler;
  typedef std::map<RelativeAddress, Fixup> FixupMap;
  typedef std::map<RelativeAddress, IntermediateReference>
      IntermediateReferenceMap;

  // Initializes the decomposer for a given image file.
  explicit Decomposer(const PEFile& image_file);

  // Decomposes the image file into a BlockGraph and an ImageLayout, which
  // have the breakdown of code and data blocks with typed references and
  // information on where the blocks resided in the original image,
  // respectively.
  // @returns true on success, false on failure. If @p stats is non-null, it
  // will be populated with decomposition coverage statistics.
  bool Decompose(ImageLayout* image_layout);

  // Decomposes the decomposed image into basic blocks.
  // @returns true on success, false on failure.
  bool BasicBlockDecompose(const ImageLayout& image_layout,
                           BasicBlockBreakdown* basic_block_breakdown);

  // Registers a pair of static initializer search patterns. Each of these
  // patterns will be converted to a regular expression, and they are required
  // to produce exactly one match group. The match group must be the same for
  // each of the patterns in order for the symbols to be correlated to each
  // other.
  // TODO(chrisha): Expose a mechanism for bulk-importing these via some JSON
  //     representation. We will likely want to expose this on the command-line
  //     of any utility using Decomposer.
  bool RegisterStaticInitializerPatterns(const char* begin, const char* end);

 protected:
  typedef std::map<RelativeAddress, std::string> DataLabels;
  typedef std::vector<pdb::PdbFixup> PdbFixups;

  // Temporary bottleneck implementation function for decomposition.
  bool DecomposeImpl(BlockGraph::AddressSpace* image,
                     PEFileParser::PEHeader* header);

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
  // Enumerates labels in @p globals and adds them to the corresponding (code)
  // blocks.
  bool CreateGlobalLabels(IDiaSymbol* globals);

  // Creates a gap block of type @p block_type for the given range. For use by
  // CreateSectionGapBlocks.
  bool CreateGapBlock(BlockGraph::BlockType block_type,
                      RelativeAddress address,
                      BlockGraph::Size size);
  // Create blocks of type @p block_type for any gaps in the image
  // section represented by @p header.
  bool CreateSectionGapBlocks(const IMAGE_SECTION_HEADER* header,
                              BlockGraph::BlockType block_type);

  // Processes the SectionContribution table, creating code/data blocks from it.
  bool CreateBlocksFromSectionContribs(IDiaSession* session);

    // Creates data blocks.
  bool CreateDataBlocks(IDiaSymbol* global);
  // Creates data gap blocks.
  bool CreateDataGapBlocks();
  // Guesses data block alignments and padding.
  bool GuessDataBlockAlignments();
  // Process static initializer data labels, ensuring they remain contiguous.
  bool ProcessStaticInitializers();

  // These process symbols in the DIA tree via DiaBrowser and the following
  // callbacks.
  bool ProcessDataSymbols(IDiaSymbol* root);
  bool ProcessPublicSymbols(IDiaSymbol* root);

  // DiaBrowser callbacks.
  void OnDataSymbol(const DiaBrowser& dia_browser,
                    const DiaBrowser::SymTagVector& sym_tags,
                    const DiaBrowser::SymbolPtrVector& symbols,
                    DiaBrowser::BrowserDirective* directive);
  void OnPublicSymbol(const DiaBrowser& dia_browser,
                      const DiaBrowser::SymTagVector& sym_tags,
                      const DiaBrowser::SymbolPtrVector& symbols,
                      DiaBrowser::BrowserDirective* directive);

  // Translates intermediate references to block->block references.
  bool FinalizeIntermediateReferences();

  // Checks that the fixups were all visited.
  bool ConfirmFixupsVisited() const;

  // Searches through the final block graph and labels blocks that are
  // orphans. Orphans are blocks that are not reachable from any module entry
  // point (PE_PARSED blocks).
  bool FindOrphanedBlocks();

  // Searches through the final block graph, and labels blocks that are
  // simply padding blocks. This must be called after all references are
  // finalized.
  bool FindPaddingBlocks();

  // Invokable once we have completed our original block graphs, this breaks
  // up code-blocks into their basic sub-components.
  bool BuildBasicBlockGraph(const ImageLayout& image_layout,
                            BasicBlockBreakdown* breakdown);

  // Parses the section headers and creates BlockGraph sections.
  bool CreateSections();

  // Parses the various debug streams. This populates fixup_map_ as well.
  bool LoadDebugStreams(IDiaSession* dia_session);

  // Validates a reference against a matching fixup, or creates a new
  // intermediate reference from @p src_addr to @p dst_addr of
  // type @p type and size @p size with optional name @p name. This assumes
  // an offset of zero.
  void AddReferenceCallback(RelativeAddress src_addr,
                            BlockGraph::ReferenceType type,
                            BlockGraph::Size size,
                            RelativeAddress dst_addr,
                            const char* name);
  // Parse the relocation entries.
  bool ParseRelocs();
  // Uses the fixup map to create cross-block references. These contain
  // relative references, lookup tables, absolute references, PC-relative from
  // code references, etc.
  bool CreateReferencesFromFixups();
  // Walk relocations and validate them against the fixups.
  bool ValidateRelocs(const PEFile::RelocMap& reloc_map);
  // Creates an initial set of code labels from fixups.
  bool CreateCodeLabelsFromFixups();
  // Disassemble all code blocks and create code->code references.
  bool CreateCodeReferences();
  // Disassemble @p block and invoke @p on_instruction for each instruction
  // encountered.
  bool CreateCodeReferencesForBlock(BlockGraph::Block* block);

  // Schedules the address range covering block1 and block2 for merging.
  void ScheduleForMerging(BlockGraph::Block* block1, BlockGraph::Block* block2);

  // Parses the PE BlockGraph header and other important PE structures,
  // adds them as blocks to the image, and creates the references
  // they contain.
  bool CreatePEImageBlocksAndReferences(PEFileParser::PEHeader* header);

  // Creates a new block with the given properties, and attaches the
  // data to it. This assumes that no conflicting block exists.
  BlockGraph::Block* CreateBlock(BlockGraph::BlockType type,
                                 RelativeAddress address,
                                 BlockGraph::Size size,
                                 const char* name);

  enum FindOrCreateBlockDirective {
    // Expect that no block exists in the given range and that a block will be
    // created.
    kExpectNoBlock,
    // Allow the existence of a block with identical range to that provided.
    kAllowIdenticalBlock,
    // Allow the existence of a block that completely covers the provided range.
    kAllowCoveringBlock,
  };
  // Create block for the given @p address and @p size of the given @p type,
  // or return an existant block that has the same @p type, @p address and
  // @p size. Care must be taken in using the returned block. Regardless of the
  // provided directive, the block that is returned may be a strict superset
  // of the requested range, and offsets into it may need to be calculated.
  // @returns the block created or found, or NULL if there's a conflicting block
  //    for the address range.
  BlockGraph::Block* FindOrCreateBlock(BlockGraph::BlockType type,
                                       RelativeAddress address,
                                       BlockGraph::Size size,
                                       const char* name,
                                       FindOrCreateBlockDirective directive);

  // Called through a callback during function disassembly.
  void OnInstruction(const Disassembler& disassembler,
                     const _DInst& instruction,
                     Disassembler::CallbackDirective* directive);
  // Called through a callback during function disassembly.
  void OnBasicInstruction(const Disassembler& disassembler,
                          const _DInst& instruction,
                          Disassembler::CallbackDirective* directive);

  // Repairs the DIA "FIXUPS" with any loaded OMAP information, validates them,
  // and stores them in the given FixupMap.
  bool OmapAndValidateFixups(const std::vector<OMAP>& omap_from,
                             const PdbFixups& pdb_fixups);

  // The image address space we're decomposing to.
  BlockGraph::AddressSpace* image_;

  // The image file we're decomposing.
  // Note that the resultant BlockGraph will contain pointers to the
  // data in the image file, so the user must ensure the image file
  // outlives the BlockGraph.
  const PEFile& image_file_;

  // Stores intermediate references before the block graph is complete.
  IntermediateReferenceMap references_;

  typedef std::set<BlockGraph::Block*> BlockSet;
  typedef std::set<BlockGraph::AddressSpace::Range> RangeSet;
  typedef std::map<RelativeAddress, std::string> LabelMap;
  typedef std::set<RelativeAddress> RelativeAddressSet;
  typedef std::pair<RE, RE> REPair;
  typedef std::vector<REPair> REPairs;

  // The block we're currently disassembling.
  BlockGraph::Block* current_block_;
  // Keeps track of which blocks we've yet to disassemble.
  BlockSet to_disassemble_;
  // Keeps track of address ranges that we want to merge because
  // we've found control flow from one block to another within the range,
  // either through short branches or by execution continuing past the tail
  // of a block.
  RangeSet to_merge_;
  // Keeps track of reloc entry information, which is used by various
  // pieces of the decomposer.
  PEFile::RelocSet reloc_set_;
  RelativeAddressSet reloc_refs_;
  // Keeps track of fixups, which are necessary if we want to move around
  // code and data. These are keyed by the location in the image of the
  // reference. We keep them around so that the disassembly phase can be
  // validated against them.
  FixupMap fixup_map_;
  // A set of static initializer search pattern pairs. These are used to
  // ensure we don't break up blocks of static initializer function pointers.
  REPairs static_initializer_patterns_;
};

class Decomposer::BasicBlockBreakdown {
 public:
  BasicBlockBreakdown() : basic_block_address_space(&basic_block_graph) {
  }

  BlockGraph basic_block_graph;
  BlockGraph::AddressSpace basic_block_address_space;
};

// This is for serializing a PEFile/BlockGraph/ImageLayout triple, which
// allows us to avoid doing decomposition repeatedly. The serialized format also
// stores toolchain metadata for input validation.
bool SaveDecomposition(const PEFile& pe_file,
                       const block_graph::BlockGraph& block_graph,
                       const ImageLayout& image_layout,
                       core::OutArchive* out_archive);
bool LoadDecomposition(core::InArchive* in_archive,
                       PEFile* pe_file,
                       block_graph::BlockGraph* block_graph,
                       ImageLayout* image_layout);

// This stores fixups, but in a format more convenient for us than the
// basic PdbFixup struct.
struct Decomposer::Fixup {
  BlockGraph::ReferenceType type;
  bool refers_to_code;
  bool is_data;
  // Has this fixup been visited by our decomposition?
  bool visited;
  RelativeAddress location;
  RelativeAddress base;
};

// During decomposition we collect references in this format, e.g.
// address->address. After thunking up the entire image into blocks,
// we convert them to block->block references.
// TODO(siggi): Is there reason to keep these in an address space to guard
//     against overlapping references?
struct Decomposer::IntermediateReference {
  BlockGraph::ReferenceType type;
  BlockGraph::Size size;
  // A reference actually takes the form of a pointer that is offset
  // from a base address (its intended target). Direct references will
  // have offset = 0, but this allows us to represent offset references
  // into data as seen in loop induction variables, etc.
  RelativeAddress base;
  BlockGraph::Offset offset;
  std::string name;
};

}  // namespace pe

#endif  // SYZYGY_PE_DECOMPOSER_H_
