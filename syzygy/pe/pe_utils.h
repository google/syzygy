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

#ifndef SYZYGY_PE_PE_UTILS_H_
#define SYZYGY_PE_PE_UTILS_H_

#include <windows.h>
#include <winnt.h>

#include "syzygy/block_graph/block_graph.h"

namespace pe {

// @name Operations on PE/COFF headers.
// @{
// Known section types.
enum SectionType {
  kSectionCode,
  kSectionData,
  kSectionUnknown
};

// Typical section names.
extern const char kCodeSectionName[];
extern const char kReadOnlyDataSectionName[];
extern const char kReadWriteDataSectionName[];
extern const char kRelocSectionName[];
extern const char kResourceSectionName[];
extern const char kTlsSectionName[];

// Typical section characteristics.
extern const DWORD kCodeCharacteristics;
extern const DWORD kReadOnlyDataCharacteristics;
extern const DWORD kReadWriteDataCharacteristics;
extern const DWORD kRelocCharacteristics;

// Validates @p dos_header_block for the size, magic constants and other
// properties of a valid DOS header.
// @returns true iff @p dos_header_block has all the correct properties
//     of a DOS header.
bool IsValidDosHeaderBlock(
    const block_graph::BlockGraph::Block* dos_header_block);

// Validates @p nt_headers_block for the the size, magic constants and
// other properties of valid NT headers.
// @returns true iff block has correct size and signature for a DOS
//     header block.
bool IsValidNtHeadersBlock(
    const block_graph::BlockGraph::Block* nt_headers_block);

// Retrieves and validates the NT headers block from a valid DOS headers block.
// @returns the NT headers block, iff it can be retrieved from the DOS headers
//     block, and if the NT headers block has valid signatures.
const block_graph::BlockGraph::Block* GetNtHeadersBlockFromDosHeaderBlock(
    const block_graph::BlockGraph::Block* dos_header_block);
block_graph::BlockGraph::Block* GetNtHeadersBlockFromDosHeaderBlock(
    block_graph::BlockGraph::Block* dos_header_block);

// Updates the provided DOS header block in preparation for writing a module
// from a BlockGraph. Trims any superfluous data and inserts a new DOS stub.
// After this has been applied IsValidDosHeaderBlock will succeed.
// @param dos_header_block the DOS header block to update.
// @returns true on success, false otherwise.
bool UpdateDosHeader(block_graph::BlockGraph::Block* dos_header_block);

// Determine the type of a section based on its attributes. Used to tag
// blocks with an appropriate type.
//
// @param header the header of the section.
// @returns the type of section.
SectionType GetSectionType(const IMAGE_SECTION_HEADER& header);
// @}

// @name Block graph helpers.
// @{
// The separator that is used between the multiple symbol names that can be
// associated with a single label.
extern const char kLabelNameSep[];

// Add the specified label to @p block, merging with existing labels at the
// same position, if any. Label names are joined with kLabelNameSep.
// Attributes are OR-ed.
//
// @param offset the position to insert the label at.
// @param name the name of the label to insert.
// @param label_attributes attributes to add to the label.
// @param block the block to add the label to.
// @returns true on success, false on failure.
bool AddLabelToBlock(block_graph::BlockGraph::Offset offset,
                     const base::StringPiece& name,
                     block_graph::BlockGraph::LabelAttributes label_attributes,
                     block_graph::BlockGraph::Block* block);

// Create sections in @p image corresponding to the ones in @p image_file,
// copying over relevant information.
//
// @tparam ImageFile the class of the file reader; must be derived
//     from PECoffFile.
// @param image_file the image file to read sections from.
// @param block_graph the block graph to add sections to.
// @returns true on success, false on failure.
template <typename ImageFile>
bool CopySectionInfoToBlockGraph(const ImageFile& image_file,
                                 block_graph::BlockGraph* block_graph);
// @}

// @name Operations on entry points.
// @{
typedef std::pair<block_graph::BlockGraph::Block*,
                  block_graph::BlockGraph::Offset> EntryPoint;
typedef std::set<EntryPoint> EntryPointSet;

// Retrieves the image entry point into @p entry_points IFF the image is an
// EXE. If the image is not an EXE then this is a NOP.
// @param dos_header_block the DOS header block of the image.
// @param entry_points the entry-point will be inserted into this set if the
//     image in question is an executable.
// @returns true on success, false otherwise. It is not considered a failure
//     if @p entry_points is left unchanged because @p dos_header_block
//     indicates that the image is not an executable.
// @note The returned @p entry_point will have a call-signature taking no
//     arguments.
bool GetExeEntryPoint(block_graph::BlockGraph::Block* dos_header_block,
                      EntryPoint* entry_point);

// Retrieves the image entry point into @p entry_points IFF the image is a
// DLL. If the image is not a DLL, or if the DLL has no entry point, then this
// is a NOP.
// @param dos_header_block the DOS header block of the image.
// @param entry_points the entry-point will be inserted into this set if the
//     image in question is a DLL. Note that the entry-point for a DLL is
//     optional; if the DLL has no entry point, the Block* of the returned
//     EntryPoint structure will be NULL.
// @returns true on success, false otherwise. It is not considered a failure
//     if @p entry_points is left unchanged because @p dos_header_block
//     indicates that the image is not a DLL.
// @note The returned @p entry_point, if any, will have a call-signature
//     matching that of DllMain.
bool GetDllEntryPoint(block_graph::BlockGraph::Block* dos_header_block,
                      EntryPoint* entry_point);

// Retrieves the TLS initializer entry-points into @p entry_points.
// @param dos_header_block the DOS header block of the image.
// @param entry_points the entry-point will be inserted into this set if the
//     image in question is a DLL. If the set already contains elements it will
//     be added to.
// @returns true on success, false otherwise.
// @note The returned @p entry_points, if any, will have a call-signature
//     matching that of DllMain.
// TODO(rogerm): We may want to change this to output to an EntryPointVector
//     instead of to a set. This would be more consistent with the actual
//     representation of the TLS initializers. That said, our actual usage of
//     the returned entry-points would require us to eliminate duplicates after
//     the fact. Left as a set for now, under suspicion of YAGNI.
bool GetTlsInitializers(block_graph::BlockGraph::Block* dos_header_block,
                        EntryPointSet* entry_points);

// Check if an image contains an import entry.
// @param The image's header-block.
// @param dll_name The name of the DLL.
// @param contains_dependence Boolean to indicate if the image contains the
//     import entry.
// @returns true in case of success, false otherwise.
bool HasImportEntry(block_graph::BlockGraph::Block* header_block,
                    const base::StringPiece& dll_name,
                    bool* has_import_entry);
// @}

// Retrieve the blocks containing the headers, symbol and strings tables
// from the block graph. Each of @p headers_block, @p symbols_block and
// @p strings_block may be NULL if the corresponding block needs not be
// retrieved.
//
// @param block_graph the graph to extract blocks from.
// @param headers_block where to store the headers block.
// @param symbols_block where to store the symbol table block.
// @param strings_block where to store the string table block.
// @returns true if all three blocks are found, false otherwise.
bool FindCoffSpecialBlocks(block_graph::BlockGraph* block_graph,
                           block_graph::BlockGraph::Block** headers_block,
                           block_graph::BlockGraph::Block** symbols_block,
                           block_graph::BlockGraph::Block** strings_block);

// A list of known file types.
enum FileType {
  kUnknownFileType,
  kPdbFileType,
  kCoffFileType,
  kPeFileType,
};

// Guesses the type of the given file. This does not do extensive validation.
// There may be false positives, but there will be no false negatives.
// @param path The path of the file whose type is to be determined. This must
//     not be empty.
// @param file_type Will be populated with the type of the file.
// @returns true on success, false on failure.
bool GuessFileType(const base::FilePath& path, FileType* file_type);

// Types used by the redirection primitive.
typedef std::pair<block_graph::BlockGraph::Block*,
                  block_graph::BlockGraph::Offset> ReferenceDest;
typedef std::map<ReferenceDest, ReferenceDest> ReferenceMap;

// Redirect references in a block-graph, except for references originating from
// PE structures. Any non-PE-structure block in src_blocks will have its
// references examined. Any reference found as a key in @p redirects will be
// remapped to its corresponding value.
// @param src The original referred destination that is to be redirected.
// @param dst The redirected destination to be referred to.
// @param redirects A map of original to redirected destinations.
void RedirectReferences(const ReferenceMap& redirects);

}  // namespace pe

#include "syzygy/pe/pe_utils_impl.h"

#endif  // SYZYGY_PE_PE_UTILS_H_
