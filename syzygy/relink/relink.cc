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

#include <algorithm>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <objbase.h>
#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/file_path.h"
#include "base/file_util.h"
#include "base/logging.h"
#include "base/logging_win.h"
#include "syzygy/pdb/pdb_util.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/pe_data.h"
#include "syzygy/pe/pe_file_builder.h"
#include "syzygy/pe/pe_file_writer.h"

using core::BlockGraph;
using core::RelativeAddress;
using pe::Decomposer;
using pe::PEFileBuilder;
using pe::PEFileParser;
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

// This class keeps track of data we need around during reordering
// and after reordering for PDB rewriting.
// TODO(siggi): Move this to a separate file.
class Relinker {
 public:
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

Relinker::Relinker(const BlockGraph::AddressSpace& original_addr_space,
                   BlockGraph* block_graph)
    : original_num_sections_(NULL),
      original_sections_(NULL),
      original_addr_space_(original_addr_space),
      builder_(block_graph) {
  DCHECK_EQ(block_graph, original_addr_space.graph());
}

bool Relinker::Initialize(const BlockGraph::Block* original_nt_headers) {
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
  if (!original_nt_headers->GetReference(entrypoint_offset, &entry_point) ||
      !builder_.SetEntryPoint(entry_point)) {
    LOG(ERROR) << "Unable to set entrypoint.";
    return false;
  }

  if (FAILED(::CoCreateGuid(&new_image_guid_))) {
    LOG(ERROR) << "Oh, no, we're fresh out of GUIDs! "
        "Quick, hand me an IPv6 address...";
    return false;
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

bool Relinker::CopyBlocks(
    const AddressSpace::RangeMapConstIterPair& iter_pair,
    RelativeAddress insert_at) {
  AddressSpace::RangeMapConstIter it = iter_pair.first;
  const AddressSpace::RangeMapConstIter& end = iter_pair.second;
  for (; it != end; ++it) {
    BlockGraph::Block* block = it->second;
    if (!builder_.address_space().InsertBlock(insert_at, block)) {
      LOG(ERROR) << "Failed to insert block '" << block->name() <<
          "' at " << insert_at;
      return false;
    }

    insert_at += block->size();
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
  for (size_t i = 0; i < original_num_sections_ - 1; ++i) {
    const IMAGE_SECTION_HEADER& section = original_sections_[i];
    BlockGraph::AddressSpace::Range section_range(
        RelativeAddress(section.VirtualAddress), section.Misc.VirtualSize);
    const char* name = reinterpret_cast<const char*>(section.Name);
    std::string name_str(name, strnlen(name, arraysize(section.Name)));

    // Duplicate the section in the new image.
    RelativeAddress start = builder_.AddSegment(name_str.c_str(),
                                                section.Misc.VirtualSize,
                                                section.SizeOfRawData,
                                                section.Characteristics);
    AddressSpace::RangeMapConstIterPair section_blocks =
        original_addr_space_.GetIntersectingBlocks(section_range.start(),
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

        if (!builder_.address_space().InsertBlock(insert_at, block)) {
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

bool Relinker::CopyDataDirectory(PEFileParser::PEHeader* original_header) {
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

bool Relinker::FinalizeImageHeaders(BlockGraph::Block* original_dos_header) {
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
  if (!original_dos_header->TransferReferers(0, builder_.dos_header())) {
    LOG(ERROR) << "Unable to redirect DOS header references.";
    return false;
  }

  return true;
}

bool Relinker::WriteImage(const FilePath& output_path) {
  PEFileWriter writer(builder_.address_space(),
                      &builder_.nt_headers(),
                      builder_.section_headers());

  if (!writer.WriteImage(output_path)) {
    LOG(ERROR) << "Unable to write new executable";
    return false;
  }

  return true;
}

bool Relinker::WritePDBFile(const BlockGraph::AddressSpace& original,
                            const FilePath& input_path,
                            const FilePath& output_path) {
  // Generate the map data for both directions.
  std::vector<OMAP> omap_to;
  AddOmapForAllSections(builder_.nt_headers().FileHeader.NumberOfSections - 1,
                        builder_.section_headers(),
                        builder_.address_space(),
                        original,
                        &omap_to);

  std::vector<OMAP> omap_from;
  AddOmapForAllSections(original_num_sections_ - 1,
                        original_sections_,
                        original,
                        builder_.address_space(),
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

// {E6FF7BFB-34FE-42a3-8993-1F477DC36247}
const GUID kRelinkLogProviderName = { 0xe6ff7bfb, 0x34fe, 0x42a3,
    { 0x89, 0x93, 0x1f, 0x47, 0x7d, 0xc3, 0x62, 0x47 } };

static const char kUsage[] =
  "Usage: relink [options]\n"
  "  Required Options:\n"
  "    --input-dll=<path> the input DLL to relink\n"
  "    --input-pdb=<path> the PDB file associated with the input DLL\n"
  "    --output-dll=<path> the relinked output DLL\n"
  "    --output-pdb=<path> the rewritten PDB file for the output DLL\n"
  "  Optional Options:\n"
  "    --seed=<integer> provides a seed for the random reordering strategy\n";

static int Usage(const char* message) {
  std::cerr << message << std::endl << kUsage;

  return 1;
}

int main(int argc, char** argv) {
  base::AtExitManager at_exit_manager;
  CommandLine::Init(argc, argv);

  if (!logging::InitLogging(L"", logging::LOG_ONLY_TO_SYSTEM_DEBUG_LOG,
      logging::DONT_LOCK_LOG_FILE, logging::APPEND_TO_OLD_LOG_FILE,
      logging::ENABLE_DCHECK_FOR_NON_OFFICIAL_RELEASE_BUILDS)) {
    return 1;
  }
  logging::LogEventProvider::Initialize(kRelinkLogProviderName);

  CommandLine* cmd_line = CommandLine::ForCurrentProcess();
  DCHECK(cmd_line != NULL);

  FilePath input_dll_path = cmd_line->GetSwitchValuePath("input-dll");
  FilePath input_pdb_path = cmd_line->GetSwitchValuePath("input-pdb");
  FilePath output_dll_path = cmd_line->GetSwitchValuePath("output-dll");
  FilePath output_pdb_path = cmd_line->GetSwitchValuePath("output-pdb");

  if (input_dll_path.empty() || input_pdb_path.empty() ||
      output_dll_path.empty() || output_pdb_path.empty()) {
    return Usage("You must provide input and output file names.");
  }

  // Read and decompose the input image for starters.
  pe::PEFile input_dll;
  if (!input_dll.Init(input_dll_path))
    return Usage("Unable to read input image");

  Decomposer decomposer(input_dll, input_dll_path);
  Decomposer::DecomposedImage decomposed;
  if (!decomposer.Decompose(&decomposed))
    return Usage("Unable to decompose input image");

  // Construct and initialize our relinker.
  Relinker relinker(decomposed.address_space, &decomposed.image);
  if (!relinker.Initialize(decomposed.header.nt_headers)) {
    return Usage("Unable to initialize relinker.");
  }

  // Randomize and write the image.
  unsigned int seed = atoi(cmd_line->GetSwitchValueASCII("seed").c_str());
  if (!relinker.RandomlyReorderCode(seed)) {
    return Usage("Unable reorder the input image.");
  }
  if (!relinker.UpdateDebugInformation(
          decomposed.header.data_directory[IMAGE_DIRECTORY_ENTRY_DEBUG])) {
    return Usage("Unable to update debug information.");
  }
  if (!relinker.CopyDataDirectory(&decomposed.header)) {
    return Usage("Unable to copy the input image's data directory.");
  }
  if (!relinker.FinalizeImageHeaders(decomposed.header.dos_header)) {
    return Usage("Unable to finalize image headers.");
  }
  if (!relinker.WriteImage(output_dll_path)) {
    return Usage("Unable to write the ouput image.");
  }

  if (!relinker.WritePDBFile(decomposed.address_space,
                             input_pdb_path,
                             output_pdb_path)) {
    return Usage("Unable to write new PDB file.");
  }

  return 0;
}
