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

#include "syzygy/pe/image_layout.h"

#include <limits>

#include "base/logging.h"
#include "base/files/file_util.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/common/align.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/pe/pe_utils.h"

namespace pe {

using block_graph::BlockGraph;
using block_graph::BlockVector;
using block_graph::ConstTypedBlock;
using core::RelativeAddress;

typedef std::vector<const BlockGraph::Section*> Sections;
typedef std::map<BlockGraph::SectionId, BlockVector> SectionBlocks;

namespace {

// Generates a sorted list of sections. Uses the default block graph ordering,
// but ensures that rsrc and reloc are second-last and last, respectively.
// Also ensures that those two sections are unique.
bool GetOrderedSections(BlockGraph* block_graph,
                        Sections* sections) {
  DCHECK(block_graph != NULL);
  DCHECK(sections != NULL);

  sections->clear();
  sections->reserve(block_graph->sections().size());

  const BlockGraph::Section* rsrc = NULL;
  const BlockGraph::Section* reloc = NULL;
  BlockGraph::SectionMap::const_iterator section_it =
      block_graph->sections().begin();
  for (; section_it != block_graph->sections().end(); ++section_it) {
    const BlockGraph::Section* section = &section_it->second;
    if (section->name() == kResourceSectionName) {
      if (rsrc != NULL) {
        LOG(ERROR) << "Found more than one " << kResourceSectionName
                   << " section.";
        return false;
      }
      rsrc = section;
      continue;
    }
    if (section->name() == kRelocSectionName) {
      if (reloc != NULL) {
        LOG(ERROR) << "Found more than one reloc section.";
        return false;
      }
      reloc = section;
      continue;
    }
    sections->push_back(section);
  }

  sections->push_back(rsrc);
  sections->push_back(reloc);

  DCHECK_EQ(sections->size(), block_graph->sections().size());

  return true;
}

// Lays out a block in the given address space. Takes care of alignment
// and incrementing the insert_at pointer.
bool LayoutBlock(BlockGraph::Block* block,
                 BlockGraph::AddressSpace* address_space,
                 RelativeAddress* insert_at) {
  DCHECK(block != NULL);
  DCHECK(address_space != NULL);
  DCHECK(insert_at != NULL);

  RelativeAddress aligned = insert_at->AlignUp(block->alignment());
  if (!address_space->InsertBlock(aligned, block)) {
    LOG(ERROR) << "Failed to insert block \"" << block->name() << "\" at "
               << *insert_at << ".";
    return false;
  }

  *insert_at = aligned + block->size();
  return true;
}

// Returns true if the block contains only zeros, and may safely be left
// implicitly initialized.
bool BlockIsZeros(const BlockGraph::Block* block) {
  if (block->references().size() != 0)
    return false;
  const uint8_t* data = block->data();
  if (data == NULL)
    return true;
  for (size_t i = 0; i < block->data_size(); ++i, ++data) {
    if (*data != 0)
      return false;
  }
  return true;
}

// Compares two blocks. Uses the source address of the first byte of each block.
// If one or both of the blocks has no such address then we sort such that empty
// (blocks that are all zeros and may be safely initialized) are pushed to the
// end of the section. Finally, we break ties using the block id.
bool BlockCompare(const BlockGraph::Block* block1,
                  const BlockGraph::Block* block2) {
  const BlockGraph::Block::SourceRanges::RangePair* pair1 =
      block1->source_ranges().FindRangePair(0, 1);
  const BlockGraph::Block::SourceRanges::RangePair* pair2 =
      block2->source_ranges().FindRangePair(0, 1);

  // If we have addresses, sort using them first.
  if (pair1 != NULL && pair2 != NULL) {
    RelativeAddress addr1 = pair1->second.start();
    RelativeAddress addr2 = pair2->second.start();
    if (addr1 < addr2)
      return true;
    if (addr2 < addr1)
      return false;
  }

  // Next, sort based on the contents. Blocks containing all zeros get pushed
  // to the end of the section.
  bool is_zeros1 = BlockIsZeros(block1);
  bool is_zeros2 = BlockIsZeros(block2);
  if (is_zeros1 != is_zeros2)
    return is_zeros2;

  // Finally we break ties using the block ID.
  return block1->id() < block2->id();
}

// Returns the length of data in a block that must be explicitly specified.
// Any data after this length may be implicitly initialized as zeroes.
size_t GetExplicitLength(const BlockGraph::Block* block) {
  size_t length = 0;

  // Get the offset of the last byte of the last reference, if there are any.
  if (block->references().size() > 0) {
    BlockGraph::Block::ReferenceMap::const_reverse_iterator last_ref =
        block->references().rbegin();
    length = last_ref->first + last_ref->second.size();
  }

  // If there is any explicit data beyond the last reference we need to
  // manually check it.
  if (block->data_size() > length) {
    const uint8_t* data = block->data();
    DCHECK(data != NULL);

    // Walk the data backwards from the end looking for the first non-zero byte.
    size_t i = block->data_size();
    data += i - 1;
    while (i > length && *data == 0) {
      --i;
      --data;
    }
    length = i;
  }

  return length;
}

}  // namespace

void CopySectionHeadersToImageLayout(
    size_t num_sections,
    const IMAGE_SECTION_HEADER* section_headers,
    std::vector<ImageLayout::SectionInfo>* sections) {
  DCHECK(num_sections > 0);
  DCHECK(section_headers != NULL);
  DCHECK(sections != NULL);

  sections->clear();
  sections->reserve(num_sections);
  for (size_t i = 0; i < num_sections; ++i) {
    sections->push_back(pe::ImageLayout::SectionInfo());
    pe::ImageLayout::SectionInfo& section = sections->back();

    section.name = PEFile::GetSectionName(section_headers[i]);
    section.addr.set_value(section_headers[i].VirtualAddress);
    section.size = section_headers[i].Misc.VirtualSize;
    section.data_size = section_headers[i].SizeOfRawData;
    section.characteristics = section_headers[i].Characteristics;
  }
}

bool CopyHeaderToImageLayout(const BlockGraph::Block* nt_headers_block,
                             ImageLayout* layout) {
  ConstTypedBlock<IMAGE_NT_HEADERS> nt_headers;
  if (!nt_headers.Init(0, nt_headers_block)) {
    LOG(ERROR) << "NT Headers too short.";
    return false;
  }

  ConstTypedBlock<IMAGE_SECTION_HEADER> section_headers;
  size_t size = sizeof(IMAGE_SECTION_HEADER) *
      nt_headers->FileHeader.NumberOfSections;
  if (!section_headers.InitWithSize(sizeof(IMAGE_NT_HEADERS),
                                    size,
                                    nt_headers_block)) {
    LOG(ERROR) << "NT Headers too short to contain section headers.";
    return false;
  }

  CopySectionHeadersToImageLayout(nt_headers->FileHeader.NumberOfSections,
                                  section_headers.Get(),
                                  &layout->sections);
  return true;
}

ImageLayout::ImageLayout(BlockGraph* block_graph)
    : blocks(block_graph) {
}

bool BuildCanonicalImageLayout(ImageLayout* image_layout) {
  DCHECK(image_layout != NULL);

  BlockGraph* block_graph = image_layout->blocks.graph();

  // First, create an ordering for the sections. This will be the same as
  // the ordering in the underlying block graph, but we enforce that
  // .rsrc and .reloc come second last and last.
  Sections sections;
  if (!GetOrderedSections(block_graph, &sections))
    return false;

  // Get a list of all of the blocks for each section, and find the header
  // blocks.
  SectionBlocks section_blocks;
  BlockGraph::Block* dos_header_block = NULL;
  BlockGraph::Block* nt_headers_block = NULL;
  BlockGraph::BlockMap::iterator block_it =
      block_graph->blocks_mutable().begin();
  for (; block_it != block_graph->blocks_mutable().end(); ++block_it) {
    BlockGraph::Block* block = &block_it->second;

    // Block has no section? Identify it as a header block.
    if (block->section() == BlockGraph::kInvalidSectionId) {
      if (dos_header_block == NULL && IsValidDosHeaderBlock(block)) {
        dos_header_block = block;
      } else if (nt_headers_block == NULL && IsValidNtHeadersBlock(block)) {
        nt_headers_block = block;
      } else {
        LOG(ERROR) << "Found invalid header block.";
        return false;
      }
    } else {
      section_blocks[block->section()].push_back(block);
    }
  }

  // Ensure we found both header blocks.
  if (dos_header_block == NULL || nt_headers_block == NULL) {
    LOG(ERROR) << "Missing one or both header blocks.";
    return false;
  }

  // Output the header blocks.
  RelativeAddress insert_at(0);
  if (!LayoutBlock(dos_header_block, &image_layout->blocks, &insert_at) ||
      !LayoutBlock(nt_headers_block, &image_layout->blocks, &insert_at)) {
    return false;
  }

  // Get the section alignment from the headers.
  ConstTypedBlock<IMAGE_DOS_HEADER> dos_header;
  if (!dos_header.Init(0, dos_header_block)) {
    LOG(ERROR) << "Failed to cast dos_header_block to IMAGE_DOS_HEADER.";
    return false;
  }
  ConstTypedBlock<IMAGE_NT_HEADERS> nt_header;
  if (!dos_header.Dereference(dos_header->e_lfanew, &nt_header)) {
    LOG(ERROR) << "Failed to cast nt_headers_block to IMAGE_NT_HEADERS.";
    return false;
  }
  size_t section_alignment = nt_header->OptionalHeader.SectionAlignment;
  size_t file_alignment = nt_header->OptionalHeader.FileAlignment;

  image_layout->sections.clear();
  image_layout->sections.reserve(sections.size());

  // Output the sections one at a time.
  for (size_t i = 0; i < sections.size(); ++i) {
    BlockVector& blocks = section_blocks[sections[i]->id()];

    // NOTE: BlockCompare uses BlockIsZeros, which is a slightly simpler
    //     version of GetExplicitLength (checks for explicit length == 0).
    //     This called for both blocks in each block comparison while sorting,
    //     and then explicitly again during layout. It may be worthwhile to
    //     precalculate and cache the explicit length values.

    // Sort the blocks for the section. This sorts based on the source address
    // if the block has a single source, then based on content (empty blocks
    // pushed to the end of the section), and finally by block id.
    std::sort(blocks.begin(), blocks.end(), &BlockCompare);

    // Align up for the section.
    insert_at = insert_at.AlignUp(section_alignment);
    RelativeAddress section_start = insert_at;
    RelativeAddress section_data_end = insert_at;

    // Layout the blocks. Keep track of the end of any blocks that aren't
    // strictly full of zeroes, in order to determine the data size.
    for (size_t j = 0; j < blocks.size(); ++j) {
      BlockGraph::Block* block = blocks[j];
      if (!LayoutBlock(block, &image_layout->blocks, &insert_at))
        return false;

      // Get the explicit length of this block. If it is non-zero update the
      // end of the explicit data for this section.
      size_t explicit_length = GetExplicitLength(block);
      if (explicit_length > 0)
        section_data_end = insert_at - block->size() + explicit_length;
    }

    // Add this section to the image layout.
    ImageLayout::SectionInfo section_info;
    section_info.name = sections[i]->name();
    section_info.addr = section_start;
    section_info.size = insert_at - section_start;
    section_info.data_size = common::AlignUp(section_data_end - section_start,
                                             file_alignment);
    section_info.characteristics = sections[i]->characteristics();
    image_layout->sections.push_back(section_info);
  }

  return true;
}

bool CopyImageLayoutWithoutPadding(const ImageLayout& input_image_layout,
                                   ImageLayout* output_image_layout) {
  DCHECK(output_image_layout != NULL);
  DCHECK_EQ(input_image_layout.blocks.graph(),
            output_image_layout->blocks.graph());
  DCHECK_EQ(0u, output_image_layout->blocks.size());

  output_image_layout->sections = input_image_layout.sections;
  BlockGraph* block_graph = output_image_layout->blocks.graph();

  // Remove the padding blocks from the decomposition. We also need to create
  // a new version of the image layout not containing those blocks.
  BlockGraph::AddressSpace::RangeMapConstIter block_it =
      input_image_layout.blocks.begin();
  for (; block_it != input_image_layout.blocks.end(); ++block_it) {
    BlockGraph::Block* block = block_it->second;

    // If it's a padding block, remove it from the block-graph and leave it
    // out of the new image layout.
    if ((block->attributes() & BlockGraph::PADDING_BLOCK)) {
      if (!block_graph->RemoveBlock(block)) {
        return false;
      }
    } else {
      // If it's not a padding block, copy it over to the new image layout.
      if (!output_image_layout->blocks.InsertBlock(block_it->first.start(),
                                                   block)) {
        return false;
      }
    }
  }

  return true;
}

}  // namespace pe
