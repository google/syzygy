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

#include "syzygy/relink/relinker.h"
#include <algorithm>
#include <ctime>
#include <objbase.h>
#include "base/file_util.h"
#include "base/json/json_reader.h"
#include "base/values.h"
#include "syzygy/pdb/pdb_util.h"
#include "syzygy/pe/pe_data.h"
#include "syzygy/pe/pe_file_writer.h"

using core::BlockGraph;
using core::RelativeAddress;
using pe::PEFileWriter;

namespace {

// This is a linear congruent pseuodo random generator.
// See: http://en.wikipedia.org/wiki/Linear_congruential_generator.
class RandomNumberGenerator {
 public:
  explicit RandomNumberGenerator(int seed) : seed_(seed) {
  }

  int operator()(int n) {
    seed_ = seed_ * kA + kC;
    int ret = seed_ % n;
    DCHECK(ret >= 0 && ret < n);
    return ret;
  }

 private:
  static const int kA = 1103515245;
  static const int kC = 12345;

  // The generator is g(N + 1) = (g(N) * kA + kC) mod 2^32.
  // The unsigned 32 bit seed yields the mod 2^32 for free.
  uint32 seed_;
};

void AddOmapForBlockRange(
    const BlockGraph::AddressSpace::RangeMapConstIterPair& original,
    const BlockGraph::AddressSpace& remapped,
    std::vector<OMAP>* omap) {
  BlockGraph::AddressSpace::RangeMapConstIter it;

  for (it = original.first; it != original.second; ++it) {
    const BlockGraph::Block* block = it->second;
    DCHECK(block != NULL);

    RelativeAddress to_addr;
    if (remapped.GetAddressOf(block, &to_addr)) {
      OMAP entry = { it->first.start().value(), to_addr.value() };
      omap->push_back(entry);
    }
  }
}

void AddOmapForAllSections(size_t num_sections,
                           const IMAGE_SECTION_HEADER* sections,
                           const BlockGraph::AddressSpace& from,
                           const BlockGraph::AddressSpace& to,
                           std::vector<OMAP>* omap) {
  for (size_t i = 0; i < num_sections; ++i) {
    BlockGraph::AddressSpace::RangeMapConstIterPair range =
        from.GetIntersectingBlocks(RelativeAddress(sections[i].VirtualAddress),
                                   sections[i].Misc.VirtualSize);

    AddOmapForBlockRange(range, to, omap);
  }
}

}  // namespace

RelinkerBase::RelinkerBase(const BlockGraph::AddressSpace& original_addr_space,
                           BlockGraph* block_graph)
    : original_num_sections_(NULL),
      original_sections_(NULL),
      original_addr_space_(original_addr_space),
      builder_(block_graph) {
  DCHECK_EQ(block_graph, original_addr_space.graph());
}

RelinkerBase::~RelinkerBase() {
}

bool RelinkerBase::Initialize(const BlockGraph::Block* original_nt_headers) {
  // Retrieve the NT and image section headers.
  if (original_nt_headers == NULL ||
      original_nt_headers->size() < sizeof(IMAGE_NT_HEADERS) ||
      original_nt_headers->data_size() != original_nt_headers->size()) {
    LOG(ERROR) << "Missing or corrupt NT header in decomposed image.";
    return false;
  }
  const IMAGE_NT_HEADERS* nt_headers =
      reinterpret_cast<const IMAGE_NT_HEADERS*>(
          original_nt_headers->data());
  DCHECK(nt_headers != NULL);

  size_t num_sections = nt_headers->FileHeader.NumberOfSections;
  size_t nt_headers_size = sizeof(IMAGE_NT_HEADERS) +
      num_sections * sizeof(IMAGE_SECTION_HEADER);
  if (original_nt_headers->data_size() != nt_headers_size) {
    LOG(ERROR) << "Missing or corrupt image section headers "
        "in decomposed image.";
    return false;
  }

  // Store the number of sections and the section headers in the original image.
  original_num_sections_ = num_sections;
  original_sections_ =
      reinterpret_cast<const IMAGE_SECTION_HEADER*>(nt_headers + 1);

  // Retrieve the original image's entry point.
  BlockGraph::Reference entry_point;
  size_t entrypoint_offset =
      FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader.AddressOfEntryPoint);
  if (!original_nt_headers->GetReference(entrypoint_offset, &entry_point)) {
    LOG(ERROR) << "Unable to get entrypoint.";
    return false;
  }
  builder_.set_entry_point(entry_point);

  return true;
}

bool RelinkerBase::CopyDataDirectory(PEFileParser::PEHeader* original_header) {
  DCHECK(original_header != NULL);

  // Copy the data directory from the old image.
  for (size_t i = 0; i < arraysize(original_header->data_directory); ++i) {
    BlockGraph::Block* block = original_header->data_directory[i];

    // We don't want to copy the relocs entry over as the relocs are recreated.
    if (block != NULL && i != IMAGE_DIRECTORY_ENTRY_BASERELOC) {
      if (!builder_.SetDataDirectoryEntry(i, block)) {
        return false;
      }
    }
  }

  return true;
}

bool RelinkerBase::FinalizeImageHeaders(
    BlockGraph::Block* original_dos_header) {
  if (!builder_.CreateRelocsSection())  {
    LOG(ERROR) << "Unable to create new relocations section";
    return false;
  }

  if (!builder_.FinalizeHeaders()) {
    LOG(ERROR) << "Unable to finalize header information";
    return false;
  }

  // Make sure everyone who previously referred the original
  // DOS header is redirected to the new one.
  if (!original_dos_header->TransferReferrers(0, builder_.dos_header())) {
    LOG(ERROR) << "Unable to redirect DOS header references.";
    return false;
  }

  return true;
}

bool RelinkerBase::WriteImage(const FilePath& output_path) {
  PEFileWriter writer(builder_.address_space(),
                      &builder_.nt_headers(),
                      builder_.section_headers());

  if (!writer.WriteImage(output_path)) {
    LOG(ERROR) << "Unable to write new executable";
    return false;
  }

  return true;
}

bool RelinkerBase::CopySection(const IMAGE_SECTION_HEADER& section) {
  BlockGraph::AddressSpace::Range section_range(
      RelativeAddress(section.VirtualAddress), section.Misc.VirtualSize);
  const char* name = reinterpret_cast<const char*>(section.Name);
  std::string name_str(name, strnlen(name, arraysize(section.Name)));

  // Duplicate the section in the new image.
  RelativeAddress start = builder().AddSegment(name_str.c_str(),
                                               section.Misc.VirtualSize,
                                               section.SizeOfRawData,
                                               section.Characteristics);
  BlockGraph::AddressSpace::RangeMapConstIterPair section_blocks =
      original_addr_space().GetIntersectingBlocks(section_range.start(),
                                                  section_range.size());

  // Copy the blocks.
  if (!CopyBlocks(section_blocks, start)) {
    LOG(ERROR) << "Unable to copy blocks to new image";
    return false;
  }

  return true;
}

bool RelinkerBase::CopyBlocks(
    const AddressSpace::RangeMapConstIterPair& iter_pair,
    RelativeAddress insert_at) {
  AddressSpace::RangeMapConstIter it = iter_pair.first;
  const AddressSpace::RangeMapConstIter& end = iter_pair.second;
  for (; it != end; ++it) {
    BlockGraph::Block* block = it->second;
    if (!builder().address_space().InsertBlock(insert_at, block)) {
      LOG(ERROR) << "Failed to insert block '" << block->name() <<
          "' at " << insert_at;
      return false;
    }

    insert_at += block->size();
  }

  return true;
}

Relinker::Relinker(const BlockGraph::AddressSpace& original_addr_space,
                   BlockGraph* block_graph)
    : RelinkerBase(original_addr_space, block_graph) {
}

Relinker::~Relinker() {
}

bool Relinker::Initialize(const BlockGraph::Block* original_nt_headers) {
  if (!RelinkerBase::Initialize(original_nt_headers))
    return false;

  if (FAILED(::CoCreateGuid(&new_image_guid_))) {
    LOG(ERROR) << "Oh, no, we're fresh out of GUIDs! "
        "Quick, hand me an IPv6 address...";
    return false;
  }

  return true;
}

bool Relinker::ReorderCode(const FilePath& order_file_path) {
  std::string file_string;
  if (!file_util::ReadFileToString(order_file_path, &file_string)) {
    LOG(ERROR) << "Unable to read order file to string";
    return false;
  }

  scoped_ptr<Value> value(base::JSONReader::Read(file_string, false));
  ListValue* order;
  if (value.get() == NULL || !value->GetAsList(&order)) {
    LOG(ERROR) << "Order file does not contain a valid JSON list";
    return false;
  }

  RelativeAddress start = builder().next_section_address();
  RelativeAddress insert_at = start;
  std::set<BlockGraph::Block*> inserted_blocks;

  // Insert the ordered blocks into the new address space.
  for (ListValue::iterator iter = order->begin(); iter < order->end(); ++iter) {
    int address;
    if (!(*iter)->GetAsInteger(&address)) {
      LOG(ERROR) << "Unable to read address value from order list";
      return false;
    }

    BlockGraph::Block* block = original_addr_space().GetBlockByAddress(
        RelativeAddress(address));
    if (!block) {
      LOG(ERROR) << "Unable to get block at address " << address;
      return false;
    }
    // Two separate RVAs may point to the same block, so make sure we only
    // insert each block once.
    if (inserted_blocks.find(block) != inserted_blocks.end())
      continue;

    if (!builder().address_space().InsertBlock(insert_at, block)) {
      LOG(ERROR) << "Unable to insert block '" << block->name() << "' at "
          << insert_at;
    }
    insert_at += block->size();
    inserted_blocks.insert(block);
  }

  // Insert the remaining unordered blocks into the new address space.
  for (size_t i = 0; i < original_num_sections() - 1; ++i) {
    const IMAGE_SECTION_HEADER& section = original_sections()[i];
    if (section.Characteristics & IMAGE_SCN_CNT_CODE) {
      BlockGraph::AddressSpace::Range section_range(
          RelativeAddress(section.VirtualAddress), section.Misc.VirtualSize);
      AddressSpace::RangeMapConstIterPair section_blocks =
          original_addr_space().GetIntersectingBlocks(section_range.start(),
                                                      section_range.size());

      AddressSpace::RangeMapConstIter& section_it = section_blocks.first;
      for (; section_it != section_blocks.second; ++section_it) {
        BlockGraph::Block* block = section_it->second;
        if (inserted_blocks.find(block) != inserted_blocks.end())
          continue;

        if (!builder().address_space().InsertBlock(insert_at, block)) {
          LOG(ERROR) << "Unable to insert block '" << block->name() << "' at "
              << insert_at;
        }
        insert_at += block->size();
        inserted_blocks.insert(block);
      }
    }
  }

  // Create the code section.
  uint32 code_size = insert_at - start;
  builder().AddSegment(".text",
                       code_size,
                       code_size,
                       IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE |
                       IMAGE_SCN_MEM_READ);

  // Copy the non-code sections, skipping the .relocs section.
  for (size_t i = 0; i < original_num_sections() - 1; ++i) {
    const IMAGE_SECTION_HEADER& section = original_sections()[i];
    if (!(section.Characteristics & IMAGE_SCN_CNT_CODE)) {
      if (!CopySection(section)) {
        LOG(ERROR) << "Unable to copy section";
        return false;
      }
    }
  }

  return true;
}

bool Relinker::RandomlyReorderCode(unsigned int seed) {
  // We use a private pseudo random number generator to allow consistent
  // results across different CRTs and CRT versions.
  RandomNumberGenerator random_generator(seed);

  // Copy the sections from the decomposed image to the new one, save for
  // the .relocs section. Code sections are passed through a reordering
  // phase before copying.
  for (size_t i = 0; i < original_num_sections() - 1; ++i) {
    const IMAGE_SECTION_HEADER& section = original_sections()[i];
    BlockGraph::AddressSpace::Range section_range(
        RelativeAddress(section.VirtualAddress), section.Misc.VirtualSize);
    const char* name = reinterpret_cast<const char*>(section.Name);
    std::string name_str(name, strnlen(name, arraysize(section.Name)));

    // Duplicate the section in the new image.
    RelativeAddress start = builder().AddSegment(name_str.c_str(),
                                                 section.Misc.VirtualSize,
                                                 section.SizeOfRawData,
                                                 section.Characteristics);
    AddressSpace::RangeMapConstIterPair section_blocks =
        original_addr_space().GetIntersectingBlocks(section_range.start(),
                                                    section_range.size());

    if (section.Characteristics & IMAGE_SCN_CNT_CODE) {
      // Hold back the blocks within the section for reordering.
      // typedef BlockGraph::AddressSpace AddressSpace;

      AddressSpace::RangeMapConstIter& section_it = section_blocks.first;
      const AddressSpace::RangeMapConstIter& section_end =
          section_blocks.second;
      std::vector<BlockGraph::Block*> code_blocks;
      for (; section_it != section_end; ++section_it) {
        BlockGraph::Block* block = section_it->second;
        DCHECK_EQ(BlockGraph::CODE_BLOCK, block->type());
        code_blocks.push_back(block);
      }

      // Now reorder the code blocks and insert them into the
      // code segment in the new order.
      std::random_shuffle(code_blocks.begin(),
                          code_blocks.end(),
                          random_generator);
      RelativeAddress insert_at = start;
      for (size_t i = 0; i < code_blocks.size(); ++i) {
        BlockGraph::Block* block = code_blocks[i];

        if (!builder().address_space().InsertBlock(insert_at, block)) {
          LOG(ERROR) << "Unable to insert block '" << block->name()
              << "' at " << insert_at;
        }

        insert_at += block->size();
      }
    } else if (!CopyBlocks(section_blocks, start)) {
      LOG(ERROR) << "Unable to copy blocks to new image";
      return false;
    }
  }

  return true;
}

bool Relinker::UpdateDebugInformation(
    BlockGraph::Block* debug_directory_block) {
  // TODO(siggi): This is a bit of a hack, but in the interest of expediency
  //     we simply reallocate the data the existing debug directory references,
  //     and update the GUID and timestamp therein.
  //     It would be better to simply junk the debug info block, and replace it
  //     with a block that contains the new GUID, timestamp and PDB path.
  IMAGE_DEBUG_DIRECTORY debug_dir;
  if (debug_directory_block->data_size() != sizeof(debug_dir)) {
    LOG(ERROR) << "Debug directory is unexpected size.";
    return false;
  }
  memcpy(&debug_dir, debug_directory_block->data(), sizeof(debug_dir));
  if (debug_dir.Type != IMAGE_DEBUG_TYPE_CODEVIEW) {
    LOG(ERROR) << "Debug directory with unexpected type.";
    return false;
  }

  // Update the timestamp.
  debug_dir.TimeDateStamp = static_cast<uint32>(time(NULL));
  if (debug_directory_block->CopyData(sizeof(debug_dir), &debug_dir) == NULL) {
    LOG(ERROR) << "Unable to copy debug directory data";
    return false;
  }

  // Now get the contents.
  BlockGraph::Reference ref;
  if (!debug_directory_block->GetReference(
          FIELD_OFFSET(IMAGE_DEBUG_DIRECTORY, AddressOfRawData), &ref) ||
      ref.offset() != 0 ||
      ref.referenced()->size() < sizeof(pe::CvInfoPdb70)) {
    LOG(ERROR) << "Unexpected or no data in debug directory.";
    return false;
  }

  BlockGraph::Block* debug_info_block = ref.referenced();
  DCHECK(debug_info_block != NULL);

  // Copy the debug info data.
  pe::CvInfoPdb70* debug_info =
      reinterpret_cast<pe::CvInfoPdb70*>(
          debug_info_block->CopyData(debug_info_block->data_size(),
                                     debug_info_block->data()));

  if (debug_info == NULL) {
    LOG(ERROR) << "Unable to copy debug info";
    return false;
  }

  // Stash the new GUID.
  debug_info->signature = new_image_guid_;

  return true;
}

bool Relinker::WritePDBFile(const BlockGraph::AddressSpace& original,
                            const FilePath& input_path,
                            const FilePath& output_path) {
  // Generate the map data for both directions.
  std::vector<OMAP> omap_to;
  AddOmapForAllSections(builder().nt_headers().FileHeader.NumberOfSections - 1,
                        builder().section_headers(),
                        builder().address_space(),
                        original,
                        &omap_to);

  std::vector<OMAP> omap_from;
  AddOmapForAllSections(original_num_sections() - 1,
                        original_sections(),
                        original,
                        builder().address_space(),
                        &omap_from);

  if (!pdb::AddOmapStreamToPdbFile(input_path,
                                   output_path,
                                   new_image_guid_,
                                   omap_to,
                                   omap_from)) {
    LOG(ERROR) << "Unable to add OMAP data to PDB";
    return false;
  }

  return true;
}
