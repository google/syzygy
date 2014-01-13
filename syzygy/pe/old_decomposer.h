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
// The decomposer decomposes a given image file into a series of blocks
// and references by reference to the image's symbols and disassembled
// executable code.
#ifndef SYZYGY_PE_OLD_DECOMPOSER_H_
#define SYZYGY_PE_OLD_DECOMPOSER_H_

#include <windows.h>  // NOLINT
#include <dia2.h>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "base/files/file_path.h"
#include "pcrecpp.h"  // NOLINT
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/core/disassembler.h"
#include "syzygy/core/serialization.h"
#include "syzygy/pdb/pdb_data.h"
#include "syzygy/pe/dia_browser.h"
#include "syzygy/pe/image_layout.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/pe/pe_file_parser.h"

// Fwd.
namespace pdb {
class PdbStream;
class PdbFile;
}  // namespace pdb

namespace pe {

class OldDecomposer {
 public:
  // A struct for storing fixups.
  struct Fixup;
  // Used for storing references before the block graph is complete.
  struct IntermediateReference;

  typedef block_graph::BlockGraph BlockGraph;
  typedef core::AbsoluteAddress AbsoluteAddress;
  typedef core::RelativeAddress RelativeAddress;
  typedef core::AddressSpace<RelativeAddress, size_t, std::string> DataSpace;
  typedef core::Disassembler Disassembler;
  typedef Disassembler::CallbackDirective CallbackDirective;
  typedef std::map<RelativeAddress, Fixup> FixupMap;
  typedef std::map<RelativeAddress, IntermediateReference>
      IntermediateReferenceMap;

  // Initializes the decomposer for a given image file.
  // @param image_file the image file to decompose.
  explicit OldDecomposer(const PEFile& image_file);

  // Decomposes the image file into a BlockGraph and an ImageLayout, which
  // have the breakdown of code and data blocks with typed references and
  // information on where the blocks resided in the original image,
  // respectively.
  // @returns true on success, false on failure. If @p stats is non-null, it
  // will be populated with decomposition coverage statistics.
  bool Decompose(ImageLayout* image_layout);

  // @{
  // TODO(chrisha): Expose a mechanism for bulk-importing these via some JSON
  //     representation. We will likely want to expose this on the command-line
  //     of any utility using OldDecomposer.

  // Registers a pair of static initializer search patterns. Each of these
  // patterns will be converted to a regular expression, and they are required
  // to produce exactly one match group. The match group must be the same for
  // each of the patterns in order for the symbols to be correlated to each
  // other.
  // @param begin the regular-expression used to find the open bracketing
  //     symbol.
  // @param end the regular-expression used to find the end bracketing symbol.
  // @returns true on success, false otherwise.
  bool RegisterStaticInitializerPatterns(const base::StringPiece& begin,
                                         const base::StringPiece& end);

  // Registers a function as non-returning. This can be used to set
  // no-return semantics for functions whose debug information is missing or
  // incomplete.
  // @param function_name the undecorated function name.
  // @returns true if the function was added, false if it already existed in
  //     the set.
  bool RegisterNonReturningFunction(const base::StringPiece& function_name);

  // Registers an imported symbol as a non-returning function. This can be used
  // to set no-return semantics for imported functions (we don't get symbol
  // information for these).
  // @param module_name the name of the imported module.
  // @param function_name the undecorated function name.
  // @returns true if the function was added, false if it already existed in
  //     the set.
  bool RegisterNonReturningImport(const base::StringPiece& module_name,
                                  const base::StringPiece& function_name);
  // @}

  // Sets the PDB path to be used. If this is not called it will be inferred
  // using the information in the module, and searched for using the OS
  // search functionality.
  // @param pdb_path the path to the PDB file to be used in decomposing the
  //     image.
  void set_pdb_path(const base::FilePath& pdb_path) { pdb_path_ = pdb_path; }

  // Accessor to the PDB path. If Decompose has been called successfully this
  // will reflect the path of the PDB file that was used to perform the
  // decomposition.
  // @returns the PDB path.
  const base::FilePath& pdb_path() const { return pdb_path_; }

 protected:
  typedef std::map<RelativeAddress, std::string> DataLabels;
  typedef std::vector<pdb::PdbFixup> PdbFixups;

  // Searches for (if necessary) the PDB file to be used in the decomposition,
  // and validates that the file exists and matches the module.
  bool FindAndValidatePdbPath();

  // Parse functions and thunks, using their data to annotate blocks.
  bool ProcessCodeSymbols(IDiaSymbol* globals);
  // Parses all function symbols.
  bool ProcessFunctionSymbols(IDiaSymbol* globals);
  // Create a function or thunk symbol.
  // @pre @p function is a function or a thunk.
  bool ProcessFunctionOrThunkSymbol(IDiaSymbol* function);
  // Create labels for @p function, which corresponds to @p block.
  bool CreateLabelsForFunction(IDiaSymbol* function, BlockGraph::Block* block);
  // Create blocks for all thunks in @p globals.
  // @note thunks are offspring of Compilands.
  bool ProcessThunkSymbols(IDiaSymbol* globals);

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
  // Creates gap blocks.
  bool CreateGapBlocks();

  // Processes the SectionContribution table, creating code/data blocks from it.
  bool CreateBlocksFromSectionContribs(IDiaSession* session);

  // Guesses data block alignments and padding.
  bool GuessDataBlockAlignments();
  // Process static initializer data labels, ensuring they remain contiguous.
  bool ProcessStaticInitializers();

  // These process symbols in the DIA tree via DiaBrowser and the following
  // callbacks.
  bool ProcessDataSymbols(IDiaSymbol* root);
  bool ProcessPublicSymbols(IDiaSymbol* root);

  // DiaBrowser callbacks.
  DiaBrowser::BrowserDirective OnDataSymbol(
      const DiaBrowser& dia_browser,
      const DiaBrowser::SymTagVector& sym_tags,
      const DiaBrowser::SymbolPtrVector& symbols);
  DiaBrowser::BrowserDirective OnPublicSymbol(
      const DiaBrowser& dia_browser,
      const DiaBrowser::SymTagVector& sym_tags,
      const DiaBrowser::SymbolPtrVector& symbols);

  // Translates intermediate references to block->block references.
  bool FinalizeIntermediateReferences();

  // Checks that the fixups were all visited.
  bool ConfirmFixupsVisited() const;

  // Searches through the final block graph, and labels blocks that are
  // simply padding blocks. This must be called after all references are
  // finalized.
  bool FindPaddingBlocks();

  // Parses the section headers and creates BlockGraph sections.
  bool CreateSections();

  // Parses the various debug streams. This populates fixup_map_ as well.
  bool LoadDebugStreams(IDiaSession* dia_session);

  // Validates a reference against a matching fixup, or creates a new
  // intermediate reference from @p src_addr to @p dst_addr of
  // type @p type and size @p size with optional name @p name. This assumes
  // an offset of zero.
  // @returns true if the reference was successfully added, false otherwise.
  bool AddReferenceCallback(RelativeAddress src_addr,
                            BlockGraph::ReferenceType type,
                            BlockGraph::Size size,
                            RelativeAddress dst_addr);
  // Parse the relocation entries.
  bool ParseRelocs();
  // Uses the fixup map to create cross-block references. These contain
  // relative references, lookup tables, absolute references, PC-relative from
  // code references, etc.
  bool CreateReferencesFromFixups();
  // Walk relocations and validate them against the fixups.
  bool ValidateRelocs(const PEFile::RelocMap& reloc_map);
  // Disassemble all code blocks and create code->code references.
  bool CreateCodeReferences();
  // Disassemble @p block and invoke @p on_instruction for each instruction
  // encountered.
  bool CreateCodeReferencesForBlock(BlockGraph::Block* block);

  // Parses the PE BlockGraph header and other important PE structures,
  // adds them as blocks to the image, and creates the references
  // they contain.
  bool CreatePEImageBlocksAndReferences(PEFileParser::PEHeader* header);

  // Creates a new block with the given properties, and attaches the
  // data to it. This assumes that no conflicting block exists.
  BlockGraph::Block* CreateBlock(BlockGraph::BlockType type,
                                 RelativeAddress address,
                                 BlockGraph::Size size,
                                 const base::StringPiece& name);

  enum FindOrCreateBlockDirective {
    // Expect that no block exists in the given range and that a block will be
    // created.
    kExpectNoBlock,
    // Allow the existence of a block with identical range to that provided.
    kAllowIdenticalBlock,
    // Allow the existence of a block that completely covers the provided range.
    kAllowCoveringBlock,
    // Allow the existence of a block that contains the start of the provided
    // range, but which may not fully contain the provided range.
    kAllowPartialCoveringBlock,
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
                                       const base::StringPiece& name,
                                       FindOrCreateBlockDirective directive);

  // @name OnInstruction helper functions.
  // @{
  void MarkDisassembledPastEnd();
  CallbackDirective LookPastInstructionForData(RelativeAddress instr_end);
  CallbackDirective VisitNonFlowControlInstruction(RelativeAddress instr_start,
                                                   RelativeAddress instr_end);
  CallbackDirective VisitPcRelativeFlowControlInstruction(
      AbsoluteAddress instr_abs,
      RelativeAddress instr_rel,
      const _DInst& instruction,
      bool end_of_code);
  CallbackDirective VisitIndirectMemoryCallInstruction(
      const _DInst& instruction, bool end_of_code);
  CallbackDirective OnInstruction(const Disassembler& disassembler,
                                  const _DInst& instruction);
  // @}

  // Repairs the DIA "FIXUPS" with any loaded OMAP information, validates them,
  // and stores them in the given FixupMap.
  bool OmapAndValidateFixups(const std::vector<OMAP>& omap_from,
                             const PdbFixups& pdb_fixups);

  // Check if there's a block-graph stream in the PDB and load it in this case.
  // @param pdb_path The path of the PDB file.
  // @param image_file The image file we're decomposing. This is used to set
  //     block data pointers.
  // @param image_layout The image-layout we're trying to populate.
  // @param stream_exist A pointer to a boolean to indicate if the block-graph
  //     stream exists in the PDB.
  // @returns true if the block-graph has been successfully loaded, false
  //     otherwise.
  bool LoadBlockGraphFromPdb(const base::FilePath& pdb_path,
                             const PEFile& image_file,
                             ImageLayout* image,
                             bool* stream_exists);

  // Load a block-graph from a PDB stream.
  // @param image_file The image file we're decomposing. This is used to set
  //     block data pointers.
  // @param block_graph_stream The stream containing the block-graph.
  // @param image_layout The image-layout we're trying to populate.
  // @returns true if the block-graph has been successfully loaded, false
  //     otherwise.
  bool LoadBlockGraphFromPdbStream(const PEFile& image_file,
                                   pdb::PdbStream* block_graph_stream,
                                   ImageLayout* image_layout);

  // Try to get the block-graph stream from a PDB.
  // @param pdb_file The PDB file from which the stream will be read.
  // @returns a scoped pointer to a the stream in case of success, otherwise
  //     the pointer will contain a NULL reference.
  scoped_refptr<pdb::PdbStream> GetBlockGraphStreamFromPdb(
      pdb::PdbFile* pdb_file);

  // Callback for use with PEFileParser. Will set the NON_RETURN_FUNCTION
  // attribute for imports that are found in the non_returning_imports_ set.
  bool OnImportThunkCallback(const char* module_name,
                             const char* symbol_name,
                             BlockGraph::Block* thunk);

  // The image address space we're decomposing to.
  BlockGraph::AddressSpace* image_;

  // The image file we're decomposing.
  // Note that the resultant BlockGraph will contain pointers to the
  // data in the image file, so the user must ensure the image file
  // outlives the BlockGraph.
  const PEFile& image_file_;

  // The path to the PDB file to be used in decomposing the image.
  base::FilePath pdb_path_;

  // Stores intermediate references before the block graph is complete.
  IntermediateReferenceMap references_;

  typedef std::set<BlockGraph::Block*> BlockSet;
  typedef std::set<BlockGraph::AddressSpace::Range> RangeSet;
  typedef std::map<RelativeAddress, std::string> LabelMap;
  typedef std::set<RelativeAddress> RelativeAddressSet;
  typedef pcrecpp::RE RE;
  typedef std::pair<RE, RE> REPair;
  typedef std::vector<REPair> REPairs;
  typedef std::set<std::string> StringSet;
  typedef std::map<std::string, StringSet> StringSetMap;

  // @name State tracking for the disassembler.
  // @{
  // The block we're currently disassembling. We need this for use in the
  // OnInstruction callback.
  BlockGraph::Block* current_block_;
  // Used to indicate the decomposer's handling of the current block. Needed
  // for OnInstruction callback.
  bool be_strict_with_current_block_;
  // @}

  // Keeps track of reloc entry information, which is used by various
  // pieces of the decomposer.
  PEFile::RelocSet reloc_set_;

  // Keeps track of fixups, which are necessary if we want to move around
  // code and data. These are keyed by the location in the image of the
  // reference. We keep them around so that the disassembly phase can be
  // validated against them.
  FixupMap fixup_map_;
  // A set of static initializer search pattern pairs. These are used to
  // ensure we don't break up blocks of static initializer function pointers.
  REPairs static_initializer_patterns_;
  // A set of functions known to be non-returning but not tagged as such in the
  // debug symbols.
  StringSet non_returning_functions_;
  // A map of module names, each containing a set of known non-returning
  // functions.
  StringSetMap non_returning_imports_;
};

// This stores fixups, but in a format more convenient for us than the
// basic PdbFixup struct.
struct OldDecomposer::Fixup {
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
struct OldDecomposer::IntermediateReference {
  BlockGraph::ReferenceType type;
  BlockGraph::Size size;
  // A reference actually takes the form of a pointer that is offset
  // from a base address (its intended target). Direct references will
  // have offset = 0, but this allows us to represent offset references
  // into data as seen in loop induction variables, etc.
  RelativeAddress base;
  BlockGraph::Offset offset;
};

}  // namespace pe

#endif  // SYZYGY_PE_OLD_DECOMPOSER_H_
