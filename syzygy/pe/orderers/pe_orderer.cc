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

#include "syzygy/pe/orderers/pe_orderer.h"

#include <windows.h>

#include "base/strings/string_piece.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/pe/pe_utils.h"

namespace pe {
namespace orderers {

namespace {

using base::StringPiece;
using block_graph::OrderedBlockGraph;
using block_graph::BlockGraph;
using block_graph::TypedBlock;

// Ensures that the provided header blocks represent valid PE headers and
// lays them out in the image as the first two blocks (DOS followed by NT)
// outside of any defined sections.
bool ValidateAndLayoutHeaders(OrderedBlockGraph* ordered_block_graph,
                              BlockGraph::Block* dos_header_block,
                              TypedBlock<IMAGE_DOS_HEADER>* dos_header,
                              TypedBlock<IMAGE_NT_HEADERS>* nt_headers) {
  DCHECK(ordered_block_graph != NULL);
  DCHECK(dos_header_block != NULL);
  DCHECK(dos_header != NULL);
  DCHECK(nt_headers != NULL);

  // Validate the headers.
  if (!dos_header->Init(0, dos_header_block)) {
    LOG(ERROR) << "Unable to cast IMAGE_DOS_HEADER.";
    return false;
  }

  if (!IsValidDosHeaderBlock(dos_header_block)) {
    LOG(ERROR) << "Invalid DOS header block.";
    return false;
  }

  if (!dos_header->Dereference((*dos_header)->e_lfanew, nt_headers)) {
    LOG(ERROR) << "Unable to cast IMAGE_NT_HEADERS.";
    return false;
  }

  if (nt_headers->offset() != 0) {
    LOG(ERROR) << "NT headers must start at offset 0.";
    return false;
  }

  if (!IsValidNtHeadersBlock(nt_headers->block())) {
    LOG(ERROR) << "Invalid NT headers block.";
    return false;
  }

  // Move the headers out of any sections, placing them as the first two
  // blocks.
  ordered_block_graph->PlaceAtHead(NULL, nt_headers->block());
  ordered_block_graph->PlaceAtHead(NULL, dos_header->block());

  return true;
}

// Finds the section, and the number of times a section with the given name was
// seen. The returned section will be one of the sections with matching name if
// there are any, NULL otherwise.
size_t FindSection(const StringPiece& section_name,
                   BlockGraph* block_graph,
                   BlockGraph::Section** section) {
  DCHECK(block_graph != NULL);
  DCHECK(section != NULL);

  *section = NULL;

  size_t count = 0;
  BlockGraph::SectionMap::iterator section_it =
      block_graph->sections_mutable().begin();
  for (; section_it != block_graph->sections_mutable().end(); ++section_it) {
    BlockGraph::Section* s = &section_it->second;
    if (s->name() == section_name) {
      *section = s;
      ++count;
    }
  }

  return count;
}

// Looks for the given section by name, returning it via @p section if there
// exists exactly one section with that name. Returns true if no or exactly one
// section with that name was found. Returns false if 2 or more sections with
// the name @p section_name were found.
bool FindZeroOrOneSection(const StringPiece& section_name,
                          BlockGraph* block_graph,
                          BlockGraph::Section** section) {
  DCHECK(block_graph != NULL);
  DCHECK(section != NULL);

  *section = NULL;
  size_t section_count = FindSection(section_name, block_graph, section);
  if (section_count > 1) {
    *section = NULL;
    LOG(ERROR) << "Multiple \"" << section_name << "\" sections exist.";
    return false;
  }

  return true;
}

// The data referred to by some data directories is expected to lay in a
// specific section set aside just for that purpose. This function accomplishes
// the following:
//
// 1. Looks for the section by name. If more than one section with name
//    @p section_name exists, returns false. If exactly one section exists
//    sets the characteristics, places it at the end of the image and continues.
//    If no section is found, continues.
// 2. Looks for the data directory with index @p data_dir_index. If it is not
//    present returns true.
// 3. If no section was found in step 1, returns false.
// 4. Dereferences the data pointed to by the data directory as an instance of
//    @p DataDirEntryType. If this is not possible, returns false.
// 5. Ensures that the block referred to by the data directory lies within the
//    section found in step 1.
template<typename DataDirEntryType>
bool LayoutSectionAndDataDirEntry(
    const StringPiece& section_name,
    uint32 section_characteristics,
    size_t data_dir_index,
    const TypedBlock<IMAGE_NT_HEADERS>& nt_headers,
    OrderedBlockGraph* ordered_block_graph) {
  DCHECK(ordered_block_graph != NULL);

  // If we find more than one section with this name return in error.
  BlockGraph::Section* section = NULL;
  if (!FindZeroOrOneSection(section_name,
                            ordered_block_graph->block_graph(),
                            &section)) {
    return false;
  }

  if (section != NULL) {
    // Set the section characteristics and move it to the end of the image.
    section->set_characteristics(section_characteristics);
    ordered_block_graph->PlaceAtTail(section);
  }

  // Do we have an entry in the |data_dir_index|th data directory?
  if (nt_headers.HasReference(nt_headers->OptionalHeader.DataDirectory[
                                  data_dir_index].VirtualAddress)) {
    // If so, we expect to have found a matching section earlier.
    if (section == NULL) {
      LOG(ERROR) << "Image has data directory " << data_dir_index << " but no "
                 << "\"" << section_name << "\" section.";
      return false;
    }

    // Dereference the data as an instance of DataDirEntryType and ensure that
    // it lies in the appropriate section.
    TypedBlock<DataDirEntryType> data_dir;
    if (!nt_headers.Dereference(nt_headers->OptionalHeader.DataDirectory[
                                    data_dir_index].VirtualAddress,
                                &data_dir)) {
      LOG(ERROR) << "Unable to dereference data directory "
                 << data_dir_index << ".";
      return false;
    }

    // If it lies in another section we put it at the head of the appropriate
    // section.
    if (data_dir.block()->section() != section->id())
      ordered_block_graph->PlaceAtHead(section, data_dir.block());
  }

  return true;
}

}  // namespace

const char PEOrderer::kOrdererName[] = "PEOrderer";

bool PEOrderer::OrderBlockGraph(OrderedBlockGraph* ordered_block_graph,
                                BlockGraph::Block* dos_header_block) {
  DCHECK(ordered_block_graph != NULL);
  DCHECK(dos_header_block != NULL);

  TypedBlock<IMAGE_DOS_HEADER> dos_header;
  TypedBlock<IMAGE_NT_HEADERS> nt_headers;
  if (!ValidateAndLayoutHeaders(ordered_block_graph, dos_header_block,
      &dos_header, &nt_headers)) {
    return false;
  }

  if (!LayoutSectionAndDataDirEntry<IMAGE_RESOURCE_DIRECTORY>(
          kResourceSectionName,
          kReadOnlyDataCharacteristics,
          IMAGE_DIRECTORY_ENTRY_RESOURCE,
          nt_headers,
          ordered_block_graph)) {
    return false;
  }

  if (!LayoutSectionAndDataDirEntry<IMAGE_BASE_RELOCATION>(
          kRelocSectionName,
          kRelocCharacteristics,
          IMAGE_DIRECTORY_ENTRY_BASERELOC,
          nt_headers,
          ordered_block_graph)) {
    return false;
  }

  return true;
}

}  // namespace orderers
}  // namespace pe
