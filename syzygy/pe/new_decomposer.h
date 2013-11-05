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
// Declares the decomposer, which decomposes a PE file into an ImageLayout and
// its corresponding BlockGraph.
//
// TODO(chrisha): When the new decomposer is ready, swap out the old for the
//     new and rename this. The new decomposer does not use all of the block
//     attributes, so some cleanup can be done there once we switch over!

#ifndef SYZYGY_PE_NEW_DECOMPOSER_H_
#define SYZYGY_PE_NEW_DECOMPOSER_H_

#include <windows.h>  // NOLINT
#include <dia2.h>
#include <vector>

#include "syzygy/pdb/pdb_file.h"
#include "syzygy/pdb/pdb_stream.h"
#include "syzygy/pe/dia_browser.h"
#include "syzygy/pe/image_layout.h"
#include "syzygy/pe/pe_file.h"

namespace pe {

// Forward declaration of a helper class where we hide our implementation
// details.
class NewDecomposerImpl;

class NewDecomposer {
 public:
  struct IntermediateReference;
  typedef std::vector<IntermediateReference> IntermediateReferences;

  // The separator that is used between the multiple symbol names that can be
  // associated with a single label.
  static const char kLabelNameSep[];

  // Initialize the decomposer for a given image file.
  // @param image_file the image file to decompose. This must outlive the
  //     instance of the decomposer.
  explicit NewDecomposer(const PEFile& image_file);

  // Decomposes the image file into a BlockGraph and an ImageLayout, which
  // have the breakdown of code and data blocks with typed references and
  // information on where the blocks resided in the original image,
  // respectively.
  // @returns true on success, false on failure.
  bool Decompose(ImageLayout* image_layout);

  // @name Mutators.
  // @{
  // Sets the PDB path to be used. If this is not called it will be inferred
  // using the information in the module, and searched for using the OS
  // search functionality.
  // @param pdb_path the path to the PDB file to be used in decomposing the
  //     image.
  void set_pdb_path(const base::FilePath& pdb_path) { pdb_path_ = pdb_path; }
  // @}

  // @name Accessors
  // @{
  // Accessor to the PDB path. If Decompose has been called successfully this
  // will reflect the path of the PDB file that was used to perform the
  // decomposition.
  // @returns the PDB path.
  const base::FilePath& pdb_path() const { return pdb_path_; }
  // @}

 protected:
  typedef block_graph::BlockGraph BlockGraph;
  typedef core::RelativeAddress RelativeAddress;

  // Searches for (if necessary) the PDB file to be used in the decomposition,
  // and validates that the file exists and matches the module.
  bool FindAndValidatePdbPath();

  // @name Used for round-trip decomposition when a serialized block graph is
  //     in the PDB. Exposed here for unittesting.
  // @{
  static bool LoadBlockGraphFromPdbStream(const PEFile& image_file,
                                          pdb::PdbStream* block_graph_stream,
                                          ImageLayout* image_layout);
  static bool LoadBlockGraphFromPdb(const base::FilePath& pdb_path,
                                    const PEFile& image_file,
                                    ImageLayout* image_layout,
                                    bool* stream_exists);
  // @}

  // @name Decomposition steps, in order.
  // @{
  // Performs the actual decomposition.
  bool DecomposeImpl();
  // Parses PE-related blocks and references.
  bool CreatePEImageBlocksAndReferences(IntermediateReferences* references);
  // Creates blocks from the COFF group symbols in the linker symbol stream.
  bool CreateBlocksFromCoffGroups();
  // Processes the SectionContribution table, creating code/data blocks from it.
  bool CreateBlocksFromSectionContribs(IDiaSession* session);
  // Creates gap blocks to flesh out the image. After this has been run all
  // references should be resolvable.
  bool CreateGapBlocks();
  // Finalizes the given vector of intermediate references.
  bool FinalizeIntermediateReferences(const IntermediateReferences& references);
  // Creates inter-block references from fixups.
  bool CreateReferencesFromFixups(IDiaSession* session);
  // Disassembles code blocks.
  // TODO(chrisha): Remove this in favor of using BasicBlockDecomposer.
  bool DisassembleCodeBlocks();
  // Processes symbols from the PDB, setting block names and labels. This
  // step is purely optional and only necessary to provide debug information.
  // This adds names to blocks, adds code labels and their names, and adds
  // more informative names to data labels.
  bool ProcessSymbols(IDiaSymbol* root);
  // @}

  // @{
  // @name Callbacks and context structures used by the COFF group parsing
  //     mechanism.
  struct VisitLinkerSymbolContext;
  bool VisitLinkerSymbol(VisitLinkerSymbolContext* context,
                         uint16 symbol_length,
                         uint16 symbol_type,
                         pdb::PdbStream* stream);
  // @}

  // @{
  // @name Callbacks used when parsing DIA symbols. Symbols only need to be
  //     parsed for debug information and can be completely ignored otherwise.
  DiaBrowser::BrowserDirective OnPushFunctionOrThunkSymbol(
      const DiaBrowser& dia_browser,
      const DiaBrowser::SymTagVector& sym_tags,
      const DiaBrowser::SymbolPtrVector& symbols);
  DiaBrowser::BrowserDirective OnPopFunctionOrThunkSymbol(
      const DiaBrowser& dia_browser,
      const DiaBrowser::SymTagVector& sym_tags,
      const DiaBrowser::SymbolPtrVector& symbols);
  DiaBrowser::BrowserDirective OnFunctionChildSymbol(
      const DiaBrowser& dia_browser,
      const DiaBrowser::SymTagVector& sym_tags,
      const DiaBrowser::SymbolPtrVector& symbols);
  DiaBrowser::BrowserDirective OnDataSymbol(
      const DiaBrowser& dia_browser,
      const DiaBrowser::SymTagVector& sym_tags,
      const DiaBrowser::SymbolPtrVector& symbols);
  DiaBrowser::BrowserDirective OnPublicSymbol(
      const DiaBrowser& dia_browser,
      const DiaBrowser::SymTagVector& sym_tags,
      const DiaBrowser::SymbolPtrVector& symbols);
  DiaBrowser::BrowserDirective OnLabelSymbol(
      const DiaBrowser& dia_browser,
      const DiaBrowser::SymTagVector& sym_tags,
      const DiaBrowser::SymbolPtrVector& symbols);
  // @}

  // @name These are called within the scope of OnFunctionChildSymbol, during
  //     which current_block_ is always set.
  // @{
  DiaBrowser::BrowserDirective OnScopeSymbol(enum SymTagEnum type,
                                             DiaBrowser::SymbolPtr symbol);
  DiaBrowser::BrowserDirective OnCallSiteSymbol(DiaBrowser::SymbolPtr symbol);
  // @}

  // @name Block creation members.
  // @{
  // Creates a new block with the given properties, and attaches the
  // data to it. This assumes that no conflicting block exists.
  BlockGraph::Block* CreateBlock(BlockGraph::BlockType type,
                                 RelativeAddress address,
                                 BlockGraph::Size size,
                                 const base::StringPiece& name);
  // Creates a new block with the given properties, or finds an existing PE
  // parsed block that subsumes it.
  BlockGraph::Block* CreateBlockOrFindCoveringPeBlock(
      BlockGraph::BlockType type,
      RelativeAddress address,
      BlockGraph::Size size,
      const base::StringPiece& name);
  // Creates a gap block of type @p block_type for the given range. For use by
  // CreateSectionGapBlocks.
  bool CreateGapBlock(BlockGraph::BlockType block_type,
                      RelativeAddress address,
                      BlockGraph::Size size);
  // Create blocks of type @p block_type for any gaps in the image
  // section represented by @p header.
  bool CreateSectionGapBlocks(const IMAGE_SECTION_HEADER* header,
                              BlockGraph::BlockType block_type);
  // @}

  // The PEFile that is being decomposed.
  const PEFile& image_file_;
  // The path to corresponding PDB file.
  base::FilePath pdb_path_;

  // @name Temporaries that are only valid while inside DecomposeImpl.
  //     Prevents us from having to pass these around everywhere.
  // @{
  // The image layout we're building.
  ImageLayout* image_layout_;
  // The image address space we're decomposing to.
  BlockGraph::AddressSpace* image_;
  // @}

  // @name Temporaries that are only valid while in DiaBrowser.
  // @{
  BlockGraph::Block* current_block_;
  RelativeAddress current_address_;
  size_t current_scope_count_;
  // @}
};

}  // namespace pe

#endif  // SYZYGY_PE_NEW_DECOMPOSER_H_
