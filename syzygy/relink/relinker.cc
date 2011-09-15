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

#include <ctime>

#include "base/file_util.h"
#include "base/lazy_instance.h"
#include "base/string_util.h"
#include "base/utf_string_conversions.h"
#include "syzygy/common/defs.h"
#include "syzygy/common/syzygy_version.h"
#include "syzygy/core/serialization.h"
#include "syzygy/pdb/pdb_util.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/metadata.h"
#include "syzygy/pe/pe_data.h"
#include "syzygy/pe/pe_file_writer.h"

using core::BlockGraph;
using core::RelativeAddress;
using pe::Decomposer;
using pe::PEFileWriter;

namespace {

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

struct PaddingData {
  enum {
      length = 8192,  // The maximum amount of padding (2 * page_size).
      value  = 0xCC   // The Int3 instruction
  };

  PaddingData() {
    memset(buffer, value, sizeof(buffer));
  }

  uint8 buffer[length];
};

base::LazyInstance<PaddingData> kPaddingData(base::LINKER_INITIALIZED);

}  // namespace

namespace relink {

RelinkerBase::RelinkerBase()
    : original_num_sections_(NULL),
      original_sections_(NULL),
      original_addr_space_(NULL) {
}

RelinkerBase::~RelinkerBase() {
}

bool RelinkerBase::Initialize(Decomposer::DecomposedImage & decomposed) {
  const BlockGraph::Block* original_nt_headers = decomposed.header.nt_headers;
  DCHECK_EQ(decomposed.address_space.graph(), &decomposed.image);
  original_addr_space_ = &decomposed.address_space;
  builder_.reset(new PEFileBuilder(&decomposed.image));

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

  // Grab the image characteristics, base and other properties from the
  // original image and propagate them to the new image headers.
  builder().nt_headers().FileHeader.Characteristics =
      nt_headers->FileHeader.Characteristics;

  // Grab the optional header fields that are specific to the original
  // image and propagate them to the new image's optional headers.
  // The remaining values are initialized/calculated by the PEBuilder.
  const IMAGE_OPTIONAL_HEADER& src_hdr = nt_headers->OptionalHeader;
  IMAGE_OPTIONAL_HEADER& dst_hdr = builder().nt_headers().OptionalHeader;
  dst_hdr.ImageBase = src_hdr.ImageBase;
  dst_hdr.MajorOperatingSystemVersion = src_hdr.MajorOperatingSystemVersion;
  dst_hdr.MinorOperatingSystemVersion = src_hdr.MinorOperatingSystemVersion;
  dst_hdr.MajorImageVersion = src_hdr.MajorImageVersion;
  dst_hdr.MinorImageVersion = src_hdr.MinorImageVersion;
  dst_hdr.MajorSubsystemVersion = src_hdr.MajorSubsystemVersion;
  dst_hdr.MinorSubsystemVersion = src_hdr.MinorSubsystemVersion;
  dst_hdr.Win32VersionValue = src_hdr.Win32VersionValue;
  dst_hdr.Subsystem = src_hdr.Subsystem;
  dst_hdr.DllCharacteristics = src_hdr.DllCharacteristics;
  dst_hdr.SizeOfStackReserve = src_hdr.SizeOfStackReserve;
  dst_hdr.SizeOfStackCommit = src_hdr.SizeOfStackCommit;
  dst_hdr.SizeOfHeapReserve = src_hdr.SizeOfHeapReserve;
  dst_hdr.SizeOfHeapCommit = src_hdr.SizeOfHeapCommit;
  dst_hdr.LoaderFlags = src_hdr.LoaderFlags;

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
  builder().set_entry_point(entry_point);

  return true;
}

bool RelinkerBase::CopyDataDirectory(
    const PEFileParser::PEHeader& original_header) {
  // Copy the data directory from the old image.
  for (size_t i = 0; i < arraysize(original_header.data_directory); ++i) {
    BlockGraph::Block* block = original_header.data_directory[i];

    // We don't want to copy the relocs entry over as the relocs are recreated.
    if (block != NULL && i != IMAGE_DIRECTORY_ENTRY_BASERELOC) {
      if (!builder().SetDataDirectoryEntry(i, block)) {
        return false;
      }
    }
  }

  return true;
}

bool RelinkerBase::FinalizeImageHeaders(
    const PEFileParser::PEHeader& original_header) {
  if (!builder().CreateRelocsSection())  {
    LOG(ERROR) << "Unable to create new relocations section";
    return false;
  }

  if (!builder().FinalizeHeaders()) {
    LOG(ERROR) << "Unable to finalize header information";
    return false;
  }

  // Make sure everyone who previously referred the original
  // DOS header is redirected to the new one.
  if (!original_header.dos_header->TransferReferrers(0,
          builder().dos_header_block())) {
    LOG(ERROR) << "Unable to redirect DOS header references.";
    return false;
  }

  // And ditto for the original NT headers.
  if (!original_header.nt_headers->TransferReferrers(0,
          builder().nt_headers_block())) {
    LOG(ERROR) << "Unable to redirect NT headers references.";
    return false;
  }

  return true;
}

bool RelinkerBase::WriteImage(const FilePath& output_path) {
  PEFileWriter writer(builder().address_space(),
                      &builder().nt_headers(),
                      builder().section_headers());

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
  size_t bytes_copied = 0;
  if (!CopyBlocks(section_blocks, start, &bytes_copied)) {
    LOG(ERROR) << "Unable to copy blocks to new image";
    return false;
  }

  DCHECK(bytes_copied == section.Misc.VirtualSize);
  return true;
}

bool RelinkerBase::CopyBlocks(
    const AddressSpace::RangeMapConstIterPair& iter_pair,
    RelativeAddress insert_at,
    size_t* bytes_copied) {
  DCHECK(bytes_copied != NULL);
  RelativeAddress start = insert_at;
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

  (*bytes_copied) = insert_at - start;
  return true;
}

Relinker::Relinker()
    : padding_length_(0),
      resource_section_id_(pe::kInvalidSection) {
}

size_t Relinker::max_padding_length() {
  return PaddingData::length;
}

void Relinker::set_padding_length(size_t length) {
  DCHECK_LE(length, max_padding_length());
  padding_length_ = std::min<size_t>(length, max_padding_length());
}

const uint8* Relinker::padding_data() {
  return kPaddingData.Get().buffer;
}

bool Relinker::Relink(const FilePath& input_dll_path,
                      const FilePath& input_pdb_path,
                      const FilePath& output_dll_path,
                      const FilePath& output_pdb_path,
                      bool output_metadata) {
  DCHECK(!input_dll_path.empty());
  DCHECK(!input_pdb_path.empty());
  DCHECK(!output_dll_path.empty());
  DCHECK(!output_pdb_path.empty());

  // Read and decompose the input image for starters.
  LOG(INFO) << "Reading input image.";
  pe::PEFile input_dll;
  if (!input_dll.Init(input_dll_path)) {
    LOG(ERROR) << "Unable to read " << input_dll_path.value() << ".";
    return false;
  }

  LOG(INFO) << "Decomposing input image.";
  Decomposer decomposer(input_dll, input_dll_path);
  Decomposer::DecomposedImage decomposed;
  if (!decomposer.Decompose(&decomposed, NULL,
                            Decomposer::STANDARD_DECOMPOSITION)) {
    LOG(ERROR) << "Unable to decompose " << input_dll_path.value() << ".";
    return false;
  }

  LOG(INFO) << "Initializing relinker.";
  if (!Initialize(decomposed)) {
    LOG(ERROR) << "Unable to initialize the relinker.";
    return false;
  }

  LOG(INFO) << "Setting up the new ordering.";
  Reorderer::Order order(input_dll, decomposed);
  if (!SetupOrdering(order)) {
    LOG(ERROR) << "Unable to setup the ordering.";
    return false;
  }

  // Reorder code sections and copy non-code sections.
  for (size_t i = 0; i < original_num_sections() - 1; ++i) {
    const IMAGE_SECTION_HEADER& section = original_sections()[i];
    const std::string name(pe::PEFile::GetSectionName(section));

    // Skip the resource section if we encounter it.
    if (name == common::kResourceSectionName) {
      // We should only ever come across one of these, and it should be
      // second to last.
      DCHECK_EQ(i, original_num_sections() - 2);
      DCHECK_EQ(pe::kInvalidSection, resource_section_id_);
      resource_section_id_ = i;
      continue;
    }

    LOG(INFO) << "Reordering section " << i << " (" << name << ").";
    if (!ReorderSection(i, section, order)) {
      LOG(ERROR) << "Unable to reorder the '" << name << "' section.";
      return false;
    }
  }

  // Update the debug info and copy the data directory.
  LOG(INFO) << "Updating debug information.";
  if (!UpdateDebugInformation(
          decomposed.header.data_directory[IMAGE_DIRECTORY_ENTRY_DEBUG],
          output_pdb_path)) {
    LOG(ERROR) << "Unable to update debug information.";
    return false;
  }

  // Create the metadata section if we're been requested to.
  if (output_metadata && !WriteMetadataSection(input_dll))
    return false;

  // We always want the resource section to be next to last (before .relocs).
  // We currently do not support ordering of the resource section, even if
  // ordering information was provided!
  if (!CopyResourceSection())
    return false;

  LOG(INFO) << "Copying the data directories.";
  if (!CopyDataDirectory(decomposed.header)) {
    LOG(ERROR) << "Unable to copy the input image's data directory.";
    return false;
  }

  // Finalize the headers and write the image and pdb.
  LOG(INFO) << "Finalizing the image headers.";
  if (!FinalizeImageHeaders(decomposed.header)) {
    LOG(ERROR) << "Unable to finalize image headers.";
    return false;
  }

  // Write the new PE Image file.
  LOG(INFO) << "Writing the new image file.";
  if (!WriteImage(output_dll_path)) {
    LOG(ERROR) << "Unable to write " << output_dll_path.value();
    return false;
  }

  // Write the new PDB file.
  LOG(INFO) << "Writing the new PDB file.";
  if (!WritePDBFile(input_pdb_path, output_pdb_path)) {
    LOG(ERROR) << "Unable to write " << output_pdb_path.value();
    return false;
  }

  return true;
}

bool Relinker::Initialize(Decomposer::DecomposedImage & decomposed) {
  if (!RelinkerBase::Initialize(decomposed))
    return false;

  if (FAILED(::CoCreateGuid(&new_image_guid_))) {
    LOG(ERROR) << "Failed to create image GUID!";
    return false;
  }

  return true;
}

bool Relinker::InsertPaddingBlock(BlockGraph::BlockType block_type,
                                  size_t size,
                                  RelativeAddress* insert_at) {
  DCHECK(insert_at != NULL);
  DCHECK(size <= max_padding_length());

  if (size == 0)
    return true;

  BlockGraph::Block* new_block = builder().address_space().AddBlock(
      block_type, *insert_at, size, "Padding block");

  if (new_block == NULL) {
    LOG(ERROR) << "Failed to allocate padding block at " << insert_at << ".";
    return false;
  }

  new_block->set_data(padding_data());
  new_block->set_data_size(size);
  new_block->set_owns_data(false);
  *insert_at += size;

  return true;
}

bool Relinker::UpdateDebugInformation(
    BlockGraph::Block* debug_directory_block,
    const FilePath& output_pdb_path) {
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

  // Calculate the new debug info size (note that the trailing NUL character is
  // already accounted for in the structure).
  std::string new_pdb_path;
  if (!WideToUTF8(output_pdb_path.value().c_str(),
                  output_pdb_path.value().length(),
                  &new_pdb_path)) {
    LOG(ERROR) << "Failed to convert the PDB path to UTF8.";
    return false;
  }
  size_t new_debug_info_size = sizeof(pe::CvInfoPdb70) + new_pdb_path.length();

  // Update the timestamp.
  debug_dir.TimeDateStamp = static_cast<uint32>(time(NULL));
  debug_dir.SizeOfData = new_debug_info_size;

  // Update the debug directory block.
  if (debug_directory_block->CopyData(sizeof(debug_dir), &debug_dir) == NULL) {
    LOG(ERROR) << "Unable to copy debug directory data";
    return false;
  }

  // Get the current debug info.
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

  const pe::CvInfoPdb70* debug_info =
      reinterpret_cast<const pe::CvInfoPdb70*>(debug_info_block->data());
  DCHECK(debug_info != NULL);

  // Allocate a new debug info block.
  // TODO(rogerm): Remove the old (and now orphaned) debug info block once
  //    we have generic layout implemented.
  RelativeAddress new_debug_block_addr = builder().AddSegment(
      ".pdbinfo", new_debug_info_size, new_debug_info_size,
      IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ);

  BlockGraph::Block* new_debug_info_block =
      builder().address_space().AddBlock(BlockGraph::DATA_BLOCK,
                                         new_debug_block_addr,
                                         new_debug_info_size,
                                         "New Debug Info");
  DCHECK(new_debug_info_block != NULL);

  pe::CvInfoPdb70* new_debug_info =
      reinterpret_cast<pe::CvInfoPdb70*>(
          new_debug_info_block->AllocateData(new_debug_info_size));
  if (debug_info == NULL) {
    LOG(ERROR) << "Unable to allocate new debug info.";
    return false;
  }

  // Populate the new debug info block.
  new_debug_info->cv_signature = debug_info->cv_signature;
  new_debug_info->pdb_age = debug_info->pdb_age;
  new_debug_info->signature = new_image_guid_;
  base::strlcpy(&new_debug_info->pdb_file_name[0],
                new_pdb_path.c_str(),
                new_pdb_path.length() + 1);

  // Transfer pointers from the old debug info block to the new.
  if (!debug_info_block->TransferReferrers(0, new_debug_info_block)) {
    LOG(ERROR) << "Unable to update references to new PDB info block.";
    return false;
  }

  return true;
}

bool Relinker::WritePDBFile(const FilePath& input_path,
                            const FilePath& output_path) {
  // Generate the map data for both directions.
  std::vector<OMAP> omap_to;
  AddOmapForAllSections(builder().nt_headers().FileHeader.NumberOfSections - 1,
                        builder().section_headers(),
                        builder().address_space(),
                        original_addr_space(),
                        &omap_to);

  std::vector<OMAP> omap_from;
  AddOmapForAllSections(original_num_sections() - 1,
                        original_sections(),
                        original_addr_space(),
                        builder().address_space(),
                        &omap_from);

  FilePath temp_pdb;
  if (!file_util::CreateTemporaryFileInDir(output_path.DirName(), &temp_pdb)) {
    LOG(ERROR) << "Unable to create working file in \""
        << output_path.DirName().value() << "\".";
    return false;
  }

  if (!pdb::AddOmapStreamToPdbFile(input_path,
                                   temp_pdb,
                                   new_image_guid_,
                                   omap_to,
                                   omap_from)) {
    LOG(ERROR) << "Unable to add OMAP data to PDB";
    file_util::Delete(temp_pdb, false);
    return false;
  }

  if (!file_util::ReplaceFile(temp_pdb, output_path)) {
    LOG(ERROR) << "Unable to write PDB file to \""
        << output_path.value() << "\".";
    file_util::Delete(temp_pdb, false);
    return false;
  }

  return true;
}

bool Relinker::WriteMetadataSection(const pe::PEFile& input_dll) {
  LOG(INFO) << "Writing metadata.";
  pe::Metadata metadata;
  pe::PEFile::Signature input_dll_sig;
  input_dll.GetSignature(&input_dll_sig);
  if (!metadata.Init(input_dll_sig) ||
      !metadata.SaveToPE(&builder())) {
    LOG(ERROR) << "Unable to write metadata.";
    return false;
  }

  return true;
}

bool Relinker::CopyResourceSection() {
  if (resource_section_id_ == pe::kInvalidSection)
    return true;

  const IMAGE_SECTION_HEADER& section =
      original_sections()[resource_section_id_];

  std::string name = pe::PEFile::GetSectionName(section);
  LOG(INFO) << "Copying section " << resource_section_id_ << " (" << name
      << ").";
  if (!CopySection(section)) {
    LOG(ERROR) << "Unable to copy section.";
    return false;
  }

  return true;
}

}  // namespace relink
