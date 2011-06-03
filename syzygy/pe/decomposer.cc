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
#include "syzygy/pe/decomposer.h"

#include <algorithm>
#include <cvconst.h>
#include <diacreate.h>
#include "base/file_path.h"
#include "base/path_service.h"
#include "base/logging.h"
#include "base/scoped_ptr.h"
#include "base/string_util.h"
#include "base/stringprintf.h"
#include "base/utf_string_conversions.h"
#include "base/win/scoped_bstr.h"
#include "base/win/scoped_comptr.h"
#include "sawbuck/common/com_utils.h"
#include "sawbuck/sym_util/types.h"
#include "syzygy/pe/pe_file_parser.h"

using base::win::ScopedBstr;
using base::win::ScopedComPtr;

namespace {

using core::AbsoluteAddress;
using core::BlockGraph;
using core::Disassembler;
using core::RelativeAddress;
using pe::Decomposer;

const size_t kPointerSize = sizeof(AbsoluteAddress);
const DWORD kDataCharacteristics =
    IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_CNT_UNINITIALIZED_DATA;

// Converts from PdbFixup::Type to BlockGraph::ReferenceType.
BlockGraph::ReferenceType PdbFixupTypeToReferenceType(
    pdb::PdbFixup::Type type) {
  switch (type) {
    case pdb::PdbFixup::TYPE_ABSOLUTE:
      return BlockGraph::ABSOLUTE_REF;

    case pdb::PdbFixup::TYPE_RELATIVE:
      return BlockGraph::RELATIVE_REF;

    case pdb::PdbFixup::TYPE_PC_RELATIVE:
      return BlockGraph::PC_RELATIVE_REF;

    default:
      NOTREACHED() << "Invalid PdbFixup::Type.";
      // The return type here is meaningless.
      return BlockGraph::ABSOLUTE_REF;
  }
}

// This reads a given debug stream into the provided vector. The type T
// must be the same size as the debug stream record size.
template<typename T> bool LoadDebugStream(IDiaEnumDebugStreamData* stream,
                                          std::vector<T>* list) {
  DCHECK(stream != NULL);
  DCHECK(list != NULL);

  LONG count = 0;
  if (FAILED(stream->get_Count(&count))) {
    LOG(ERROR) << "Failed to get stream count.";
    return false;
  }

  // Get the length of the debug stream, and ensure it is the expected size.
  DWORD bytes_read = 0;
  ULONG count_read = 0;
  HRESULT hr = stream->Next(count, 0, &bytes_read, NULL, &count_read);
  if (FAILED(hr)) {
    LOG(ERROR) << "Unable to get debug stream length: " << com::LogHr(hr);
    return false;
  }
  DCHECK_EQ(count * sizeof(T), bytes_read);

  // Actually read the stream.
  list->resize(count);
  bytes_read = 0;
  count_read = 0;
  hr = stream->Next(count, count * sizeof(T), &bytes_read,
                    reinterpret_cast<BYTE*>(&list->at(0)),
                    &count_read);
  if (FAILED(hr)) {
    LOG(ERROR) << "Unable to read debug stream: " << com::LogHr(hr);
    return false;
  }
  DCHECK_EQ(count * sizeof(T), bytes_read);
  DCHECK_EQ(count, static_cast<LONG>(count_read));

  return true;
}

// A comparison functor, for comparing two OMAP entries based on 'rva'.
struct OmapCompareFunctor {
  bool operator()(const OMAP& omap1, const OMAP& omap2) {
    return omap1.rva < omap2.rva;
  }
};

// Maps an address through the given OMAP information. Assumes the address
// is within the bounds of the image.
RelativeAddress TranslateAddressViaOmap(const std::vector<OMAP>& omap,
                                        RelativeAddress address) {
  OMAP omap_address = { address.value(), 0 };

  // Find the first element that is > than omap_address.
  std::vector<OMAP>::const_iterator it =
      std::upper_bound(omap.begin(), omap.end(), omap_address,
                       OmapCompareFunctor());

  // If we are at the first OMAP entry, the address is before any addresses
  // that are OMAPped. Thus, we return the same address.
  if (it == omap.begin())
    return address;

  // Otherwise, the previous OMAP entry tells us where we lie.
  --it;
  return RelativeAddress(it->rvaTo) + (address - RelativeAddress(it->rva));
}

// Adds a reference to the provided intermediate reference map. If one already
// exists, will validate that they are consistent.
bool AddReference(RelativeAddress src_addr,
                  BlockGraph::ReferenceType type,
                  BlockGraph::Size size,
                  RelativeAddress dst_base,
                  BlockGraph::Offset dst_offset,
                  const char* name,
                  Decomposer::IntermediateReferenceMap* references) {
  DCHECK(references != NULL);

  // If we ge t an iterator to a reference and it has the same source address
  // then ensure that we are consistent with it.
  Decomposer::IntermediateReferenceMap::iterator it =
      references->lower_bound(src_addr);
  if (it != references->end() && it->first == src_addr) {
    if (type != it->second.type || size != it->second.size ||
        dst_base != it->second.base || dst_offset != it->second.offset) {
      LOG(ERROR) << "Trying to insert inconsistent and colliding intermediate "
                    "references.";
      return false;
    }

    // Found existing and consistent intermediate reference. Change the name
    // if one is provided.
    if (name != NULL)
      it->second.name = name;
    return true;
  }

  Decomposer::IntermediateReference ref = { type,
                                            size,
                                            dst_base,
                                            dst_offset,
                                            name == NULL ? "" : name };

  // Since we used lower_bound above, we can use it as a hint for the
  // insertion. This saves us from incurring the lookup cost twice.
  references->insert(it, std::make_pair(src_addr, ref));
  return true;
}

// Validates the given reference against the given fixup map entry. If they
// are consistent, marks the fixup as having been visited.
bool ValidateReference(RelativeAddress src_addr,
                       BlockGraph::ReferenceType type,
                       BlockGraph::Size size,
                       Decomposer::FixupMap::iterator fixup_it) {
  if (type != fixup_it->second.type || size != kPointerSize) {
    LOG(ERROR) << "Reference at RVA "
        << StringPrintf("0x%08X", src_addr.value())
        << " not consistent with corresponding fixup.";
    return false;
  }

  // Mark this fixup as having been visited.
  fixup_it->second.visited = true;

  return true;
}

enum ValidateOrAddReferenceMode {
  // Look for an existing fixup. If we find one, validate against it,
  // otherwise create a new intermediate reference.
  FIXUP_MAY_EXIST,
  // Compare against an existing fixup, bailing if there is none. Does not
  // create a new intermediate reference.
  FIXUP_MUST_EXIST,
  // Look for an existing fixup, and fail if one exists. Otherwise, create
  // a new intermediate reference.
  FIXUP_MUST_NOT_EXIST
};
bool ValidateOrAddReference(ValidateOrAddReferenceMode mode,
                            RelativeAddress src_addr,
                            BlockGraph::ReferenceType type,
                            BlockGraph::Size size,
                            RelativeAddress dst_base,
                            BlockGraph::Offset dst_offset,
                            const char* name,
                            Decomposer::FixupMap* fixup_map,
                            Decomposer::IntermediateReferenceMap* references) {
  DCHECK(fixup_map != NULL);
  DCHECK(references != NULL);

  Decomposer::FixupMap::iterator it = fixup_map->find(src_addr);

  switch (mode) {
    case FIXUP_MAY_EXIST: {
      if (it != fixup_map->end() &&
          !ValidateReference(src_addr, type, size, it))
        return false;
      return AddReference(src_addr, type, size, dst_base, dst_offset, name,
                          references);
    }

    case FIXUP_MUST_EXIST: {
      if (it == fixup_map->end()) {
        LOG(ERROR) << "Reference at RVA "
            << StringPrintf("0x%08X", src_addr.value())
            << " has no matching fixup.";
        return false;
      }
      if (!ValidateReference(src_addr, type, size, it))
        return false;
      // Do not create a new intermediate reference.
      return true;
    }

    case FIXUP_MUST_NOT_EXIST: {
      if (it != fixup_map->end()) {
        LOG(ERROR) << "Reference at RVA "
            << StringPrintf("0x%08X", src_addr.value())
            << " collides with an existing fixup.";
        return false;
      }
      return AddReference(src_addr, type, size, dst_base, dst_offset, name,
                          references);
    }

    default: {
      NOTREACHED() << "Invalid ValidateOrAddReferenceMode.";
      return false;
    }
  }
}

bool GetSymTag(IDiaSymbol* symbol, DWORD* sym_tag) {
  DCHECK(sym_tag != NULL);
  *sym_tag = SymTagNull;
  HRESULT hr = symbol->get_symTag(sym_tag);
  if (FAILED(hr)) {
    LOG(ERROR) << "Error getting sym tag.";
    return false;
  }
  return true;
}

bool GetTypeInfo(IDiaSymbol* symbol, size_t* length) {
  DCHECK(symbol != NULL);
  DCHECK(length != NULL);

  *length = 0;
  ScopedComPtr<IDiaSymbol> type;
  HRESULT hr = symbol->get_type(type.Receive());
  if (FAILED(hr)) {
    LOG(ERROR) << "Failed to get type symbol: " << hr;
    return false;
  }
  // This happens if the symbol has no type information.
  if (hr == S_FALSE)
    return true;

  ULONGLONG ull_length = 0;
  if (FAILED(type->get_length(&ull_length))) {
    LOG(ERROR) << "Failed to retrieve type length properties.";
    return false;
  }
  *length = ull_length;

  return true;
}

enum SectionType {
  kSectionCode,
  kSectionData,
  kSectionUnknown
};

SectionType GetSectionType(const IMAGE_SECTION_HEADER* header) {
  DCHECK(header != NULL);
  if ((header->Characteristics & IMAGE_SCN_CNT_CODE) != 0)
    return kSectionCode;
  if ((header->Characteristics & kDataCharacteristics) != 0)
    return kSectionData;
  return kSectionUnknown;
}

bool IsSymTag(IDiaSymbol* symbol, DWORD expected_sym_tag) {
  DWORD sym_tag = SymTagNull;
  if (!GetSymTag(symbol, &sym_tag))
    return false;

  return sym_tag == expected_sym_tag;
}

bool CreateDiaSource(IDiaDataSource** created_source) {
  ScopedComPtr<IDiaDataSource> dia_source;
  if (SUCCEEDED(dia_source.CreateInstance(CLSID_DiaSource))) {
    *created_source = dia_source.Detach();
    return true;
  }

  if (SUCCEEDED(NoRegCoCreate(L"msdia90.dll",
                              CLSID_DiaSource,
                              IID_IDiaDataSource,
                              reinterpret_cast<void**>(&dia_source)))) {
    *created_source = dia_source.Detach();
    return true;
  }

  return false;
}

void UpdateSectionStats(
    const IMAGE_SECTION_HEADER* header,
    Decomposer::CoverageStatistics::SectionStatistics* stats) {
  DCHECK(header != NULL);
  DCHECK(stats != NULL);
  ++stats->section_count;
  stats->virtual_size += header->Misc.VirtualSize;
  stats->data_size += header->SizeOfRawData;
}

void UpdateSimpleBlockStats(
    const BlockGraph::Block* block,
    Decomposer::CoverageStatistics::SimpleBlockStatistics* stats) {
  DCHECK(block != NULL);
  DCHECK(stats != NULL);
  stats->virtual_size += block->size();
  stats->data_size += block->data_size();
  ++stats->block_count;
}

void UpdateBlockStats(
    const BlockGraph::Block* block,
    Decomposer::CoverageStatistics::BlockStatistics* stats) {
  DCHECK(block != NULL);
  DCHECK(stats != NULL);

  UpdateSimpleBlockStats(block, &stats->summary);
  if (block->attributes() & BlockGraph::GAP_BLOCK)
    UpdateSimpleBlockStats(block, &stats->gap);
  else
    UpdateSimpleBlockStats(block, &stats->normal);
}

void CalcDetailedCodeBlockStats(
    const BlockGraph::Block* block,
    const Disassembler& disasm,
    const Decomposer::DataSpace& data_space,
    Decomposer::DetailedCodeBlockStatistics* stats) {
  DCHECK(block != NULL);
  DCHECK(stats != NULL);

  typedef Decomposer::DataSpace DataSpace;

  memset(stats, 0, sizeof(*stats));

  // Walk through the code and data address spaces simultaneously.
  Disassembler::VisitedSpace::RangeMapConstIter code_it =
      disasm.visited().begin();
  DataSpace::Range block_range(block->addr(), block->size());
  DataSpace::RangeMapConstIterPair data_its =
      data_space.FindIntersecting(block_range);
  DataSpace::RangeMapConstIter data_it = data_its.first;
  for (; data_it != data_its.second; ++data_it) {
    stats->data_bytes += data_it->first.size();
    ++stats->data_count;

    size_t data_block_rel_pos = data_it->first.start() - block->addr();
    AbsoluteAddress data_abs(disasm.code_addr() + data_block_rel_pos);
    Disassembler::VisitedSpace::Range data_range(data_abs,
                                                 data_it->first.size());

    // Catch the code pointer up to the data pointer.
    Disassembler::VisitedSpace::RangeMapConstIter code_last_it = code_it;
    while (code_it != disasm.visited().end() && code_it->first < data_range) {
      stats->code_bytes += code_it->first.size();
      ++stats->code_count;
      code_last_it = code_it;
      ++code_it;
    }

    // If we have a code block immediately before this data block and the
    // space between them is less than the alignment of the data block, then
    // we can count these bytes as padding.
    if (code_last_it != disasm.visited().end() &&
        code_last_it->first < data_range) {
      size_t padding = data_range.start().value() -
          code_last_it->first.end().value();
      if (padding < kPointerSize &&
          (data_range.start().value() & (kPointerSize - 1)) == 0) {
        stats->padding_bytes += padding;
        ++stats->padding_count;
      }
    }
  }

  // Consume any remaining code ranges.
  for (; code_it != disasm.visited().end(); ++code_it) {
    stats->code_bytes += code_it->first.size();
    ++stats->code_count;
  }

  size_t total = stats->code_bytes + stats->data_bytes + stats->padding_bytes;
  DCHECK(total <= block->size());
  stats->unknown_bytes = block->size() - total;
}

void UpdateDetailedCodeBlockStats(
    const BlockGraph::Block* block,
    const Decomposer::DetailedCodeBlockStatistics* detail,
    Decomposer::DetailedCodeBlockStatistics* stats) {
  DCHECK(block != NULL);
  DCHECK(stats != NULL);

  if (detail != NULL) {
    stats->code_bytes += detail->code_bytes;
    stats->data_bytes += detail->data_bytes;
    stats->padding_bytes += detail->padding_bytes;
    stats->unknown_bytes += detail->unknown_bytes;
    stats->code_count += detail->code_count;
    stats->data_count += detail->data_count;
    stats->padding_count += detail->padding_count;
  } else {
    stats->unknown_bytes += block->size();
  }
}

void CalcSectionStats(
    const IMAGE_SECTION_HEADER* header,
    Decomposer::CoverageStatistics* stats) {
  DCHECK(header != NULL);
  DCHECK(stats != NULL);

  UpdateSectionStats(header, &stats->sections.summary);
  SectionType type = GetSectionType(header);
  switch (type) {
    case kSectionCode:
      UpdateSectionStats(header, &stats->sections.code);
      break;

    case kSectionData:
      UpdateSectionStats(header, &stats->sections.data);
      break;

    case kSectionUnknown:
      UpdateSectionStats(header, &stats->sections.unknown);
      break;
  }
}

}  // namespace

namespace pe {

using core::AbsoluteAddress;
using core::BlockGraph;

Decomposer::Decomposer(const PEFile& image_file,
                       const FilePath& file_path)
    : image_(NULL),
      image_file_(image_file),
      file_path_(file_path),
      current_block_(NULL) {
  // Register static initializer patterns that we know are always present.
  bool success =
      RegisterStaticInitializerPatterns("(__x.*)_a", "(__x.*)_z") &&
      RegisterStaticInitializerPatterns("(__rtc_[it])aa", "(__rtc_[it])zz");
  CHECK(success);
}

bool Decomposer::Decompose(DecomposedImage* decomposed_image,
                           CoverageStatistics* stats,
                           Mode decomposition_mode) {
  // Start by instantiating and initializing our Debug Interface Access session.
  ScopedComPtr<IDiaDataSource> dia_source;
  if (!CreateDiaSource(dia_source.Receive())) {
    LOG(ERROR) << "Failed to create DIA source object.";
    return false;
  }

  HRESULT hr = dia_source->loadDataForExe(file_path_.value().c_str(),
                                          NULL,
                                          NULL);
  if (FAILED(hr)) {
    LOG(ERROR) << "Failed to load DIA data for image file: " << hr;
    return false;
  }

  ScopedComPtr<IDiaSession> dia_session;
  hr = dia_source->openSession(dia_session.Receive());
  if (FAILED(hr)) {
    LOG(ERROR) << "Failed to open DIA session: " << hr;
    return false;
  }

  hr = dia_session->put_loadAddress(
      image_file_.nt_headers()->OptionalHeader.ImageBase);
  if (FAILED(hr)) {
    LOG(ERROR) << "Failed to set the DIA load address: " << hr;
    return false;
  }

  ScopedComPtr<IDiaSymbol> global;
  hr = dia_session->get_globalScope(global.Receive());
  if (FAILED(hr)) {
    LOG(ERROR) << "Failed to get the DIA global scope: " << hr;
    return false;
  }

  image_ = &decomposed_image->address_space;

  // Load OMAP and FIXUP information from the PDB file. We do this first
  // so that we can do accounting with references that are created later
  // on.
  bool success = LoadDebugStreams(dia_session,
                                  &decomposed_image->omap_to,
                                  &decomposed_image->omap_from);

  // Create intermediate references for each fixup entry.
  if (success)
    success = CreateReferencesFromFixups();

  // Chunk out important PE image structures, like the headers and such.
  if (success)
    success = CreatePEImageBlocksAndReferences(&decomposed_image->header);

  // Parse and validate the relocation entries.
  if (success)
    success = ParseRelocs();

  // Chunk out blocks for each function and thunk in the image.
  if (success)
    success = CreateCodeBlocks(global);

  // Chunk out data blocks.
  if (success)
    success = CreateDataBlocks(global);

  // Create labels in code blocks. These are created first so that the
  // labels will have meaningful names.
  if (success)
    success = CreateGlobalLabels(global);

  // Now we use fixup information to create further code labels.
  if (success)
    success = CreateCodeLabelsFromFixups();

  // Disassemble code blocks and create PC-relative references
  if (success)
    success = CreateCodeReferences();

  // TODO(chrisha): Verify the destinations of all unreferenced labels.
  //     They should either have been disassembled in the regular course
  //     of disassembly, or they should point to no-ops. To do this, we'll
  //     need to keep around the visited_ address-space of each code block.

  // Turn the address->address format references we've created into
  // block->block references on the blocks in the image.
  if (success)
    success = FinalizeIntermediateReferences();

  // One way of ensuring full coverage is to check that all of the fixups
  // were visited during decomposition.
  if (success)
    success = ConfirmFixupsVisited();

  // Once the above steps are complete, we will now have a function-level
  // granularity of blocks for code-type blocks and those blocks will contain
  // ALL inbound and out-bound references. Now it's time to break up those
  // blocks into their basic sub-components.
  if (success && decomposition_mode == BASIC_BLOCK_DECOMPOSITION)
    success = BuildBasicBlockGraph(decomposed_image);

  if (stats != NULL)
    CalcCoverageStatistics(stats);
  code_block_stats_.clear();
  image_ = NULL;

  return success;
}

void Decomposer::CalcCoverageStatistics(CoverageStatistics* stats) const {
  DCHECK(image_ != NULL);
  DCHECK(stats != NULL);

  memset(stats, 0, sizeof(*stats));

  // Iterate over all sections.
  size_t num_sections = image_file_.nt_headers()->FileHeader.NumberOfSections;
  for (size_t i = 0; i < num_sections; ++i)
    CalcSectionStats(image_file_.section_header(i), stats);

  // Iterate over all blocks.
  BlockGraph::AddressSpace::RangeMapConstIter it = image_->begin();
  BlockGraph::AddressSpace::RangeMapConstIter it_end = image_->end();
  for (; it != it_end; ++it) {
    const BlockGraph::Block* block = it->second;
    CalcBlockStats(block, stats);
  }
}

void Decomposer::CalcBlockStats(const BlockGraph::Block* block,
                                CoverageStatistics* stats) const {
  DCHECK(block != NULL);
  DCHECK(stats != NULL);

  // Blocks that don't belong to any section get special-cased.
  if (block->section() == core::kInvalidSection) {
    UpdateSimpleBlockStats(block, &stats->blocks.no_section);
    return;
  }

  // Update the per-block-type information.
  switch (block->type()) {
    case BlockGraph::CODE_BLOCK: {
      UpdateBlockStats(block, &stats->blocks.code);

      const DetailedCodeBlockStatistics* detail = NULL;
      DetailedCodeBlockStatsMap::const_iterator stats_it =
          code_block_stats_.find(block->id());
      if (stats_it != code_block_stats_.end())
        detail = &stats_it->second;
      UpdateDetailedCodeBlockStats(block, detail, &stats->blocks.code.detail);
      break;
    }

    case BlockGraph::DATA_BLOCK:
      UpdateBlockStats(block, &stats->blocks.data);
      break;

    default:
      NOTREACHED();
  }
}

bool Decomposer::CreateCodeBlocks(IDiaSymbol* global) {
  HANDLE process = reinterpret_cast<HANDLE>(this);

  if (!CreateFunctionBlocks(global))
    return false;
  if (!CreateThunkBlocks(global))
    return false;

  size_t num_sections = image_file_.nt_headers()->FileHeader.NumberOfSections;
  for (size_t i = 0; i < num_sections; ++i)  {
    const IMAGE_SECTION_HEADER* header = image_file_.section_header(i);
    // Skip non-code sections.
    if ((header->Characteristics & IMAGE_SCN_CNT_CODE) != 0) {
      if (!CreateSectionGapBlocks(header, BlockGraph::CODE_BLOCK)) {
        LOG(ERROR) << "Failed to create gap blocks for code section "
            << header->Name;
        return false;
      }
    }
  }

  return true;
}

bool Decomposer::CreateFunctionBlocks(IDiaSymbol* global) {
  DCHECK(IsSymTag(global, SymTagExe));

  // Otherwise enumerate its offspring.
  ScopedComPtr<IDiaEnumSymbols> dia_enum_symbols;
  HRESULT hr = global->findChildren(SymTagFunction,
                                    NULL,
                                    nsNone,
                                    dia_enum_symbols.Receive());
  if (FAILED(hr)) {
    LOG(ERROR) << "Failed to get the DIA function enumerator: " << hr;
    return false;
  }

  while (true) {
    ScopedComPtr<IDiaSymbol> function;
    ULONG fetched = 0;
    hr = dia_enum_symbols->Next(1, function.Receive(), &fetched);
    if (FAILED(hr)) {
      LOG(ERROR) << "Failed to enumerate functions.";
      return false;
    }
    if (hr != S_OK || fetched == 0)
      break;

    // Create the block representing the function.
    DCHECK(IsSymTag(function, SymTagFunction));
    if (!CreateFunctionBlock(function))
      return false;
  }

  return true;
}

bool Decomposer::CreateFunctionBlock(IDiaSymbol* function) {
  DCHECK(IsSymTag(function, SymTagFunction) || IsSymTag(function, SymTagThunk));

  DWORD location_type = LocIsNull;
  if (FAILED(function->get_locationType(&location_type))) {
    LOG(ERROR) << "Failed to retrieve function address type.";
    return false;
  }
  if (location_type != LocIsStatic) {
    DCHECK_EQ(static_cast<DWORD>(LocIsNull), location_type);
    return true;
  }

  DWORD rva = 0;
  ULONGLONG length = 0;
  ScopedBstr name;
  BOOL no_return = FALSE;
  if (FAILED(function->get_relativeVirtualAddress(&rva)) ||
      FAILED(function->get_length(&length)) ||
      FAILED(function->get_name(name.Receive())) ||
      FAILED(function->get_noReturn(&no_return))) {
    LOG(ERROR) << "Failed to retrieve function information.";
    return false;
  }

  std::string block_name;
  if (!WideToUTF8(name, name.Length(), &block_name)) {
    LOG(ERROR) << "Failed to convert symbol name to UTF8.";
    return false;
  }

  BlockGraph::Block* block =
      FindOrCreateBlock(BlockGraph::CODE_BLOCK,
                        RelativeAddress(rva),
                        static_cast<BlockGraph::Size>(length),
                        block_name.c_str());
  if (block == NULL)
    return false;

  DCHECK(block->data() != NULL);

  block->SetLabel(0, block_name.c_str());
  if (no_return == TRUE)
    block->set_attribute(BlockGraph::NON_RETURN_FUNCTION);

  return CreateLabelsForFunction(function, block);
}

bool Decomposer::CreateLabelsForFunction(IDiaSymbol* function,
                                         BlockGraph::Block* block) {
  // Enumerate the label offspring of function.
  ScopedComPtr<IDiaEnumSymbols> dia_enum_symbols;
  HRESULT hr = function->findChildren(SymTagLabel,
                                      NULL,
                                      nsNone,
                                      dia_enum_symbols.Receive());
  if (FAILED(hr)) {
    LOG(ERROR) << "Failed to get the DIA label enumerator: " << hr;
    return false;
  }

  while (true) {
    ScopedComPtr<IDiaSymbol> symbol;
    ULONG fetched = 0;
    hr = dia_enum_symbols->Next(1, symbol.Receive(), &fetched);
    if (FAILED(hr)) {
      LOG(ERROR) << "Failed to enumerate the DIA symbol.";
      return false;
    }
    if (hr != S_OK || fetched == 0)
      break;

    DCHECK(IsSymTag(symbol, SymTagLabel));
    DWORD rva = 0;
    ScopedBstr name;
    if (FAILED(symbol->get_relativeVirtualAddress(&rva)) ||
        FAILED(symbol->get_name(name.Receive()))) {
      LOG(ERROR) << "Failed to retrieve function information.";
      return false;
    }

    RelativeAddress addr;
    if (!image_->GetAddressOf(block, &addr)) {
      NOTREACHED() << "Block " << block->name() << " has no address.";
      return false;
    }

    RelativeAddress label_rva(rva);
    if (label_rva < addr && label_rva >= addr + block->size()) {
      LOG(ERROR) << "Label outside function.";
      return false;
    }

    std::string label_name;
    if (!WideToUTF8(name, name.Length(), &label_name)) {
      LOG(ERROR) << "Failed to convert label name to UTF8.";
      return false;
    }

    AddLabelToCodeBlock(label_rva, label_name, block);
  }

  return true;
}

bool Decomposer::CreateThunkBlocks(IDiaSymbol* globals) {
  ScopedComPtr<IDiaEnumSymbols> enum_compilands;
  HRESULT hr = globals->findChildren(SymTagCompiland,
                                     NULL,
                                     nsNone,
                                     enum_compilands.Receive());
  if (FAILED(hr)) {
    LOG(ERROR) << "Failed to retrieve compiland enumerator: " << hr;
    return false;
  }

  while (true) {
    ScopedComPtr<IDiaSymbol> compiland;
    ULONG fetched = 0;
    hr = enum_compilands->Next(1, compiland.Receive(), &fetched);
    if (FAILED(hr)) {
      LOG(ERROR) << "Failed to enumerate compiland enumerator.";
      return false;
    }
    if (hr != S_OK || fetched == 0)
      break;

    ScopedComPtr<IDiaEnumSymbols> enum_thunks;
    hr = compiland->findChildren(SymTagThunk,
                                 NULL,
                                 nsNone,
                                 enum_thunks.Receive());
    if (FAILED(hr)) {
      LOG(ERROR) << "Failed to retrieve thunk enumerator: " << hr;
      return false;
    }

    while (true) {
      ScopedComPtr<IDiaSymbol> thunk;
      hr = enum_thunks->Next(1, thunk.Receive(), &fetched);
      if (FAILED(hr)) {
        LOG(ERROR) << "Failed to enumerate thunk enumerator: " << hr;
        return false;
      }
      if (hr != S_OK || fetched == 0)
        break;


      DCHECK(IsSymTag(thunk, SymTagThunk));

      if (!CreateFunctionBlock(thunk))
        return false;
    }
  }

  return true;
}

bool Decomposer::CreateGlobalLabels(IDiaSymbol* globals) {
  ScopedComPtr<IDiaEnumSymbols> enum_compilands;
  HRESULT hr = globals->findChildren(SymTagCompiland,
                                     NULL,
                                     nsNone,
                                     enum_compilands.Receive());
  if (FAILED(hr)) {
    LOG(ERROR) << "Failed to retrieve compiland enumerator: " << hr;
    return false;
  }

  while (true) {
    ScopedComPtr<IDiaSymbol> compiland;
    ULONG fetched = 0;
    hr = enum_compilands->Next(1, compiland.Receive(), &fetched);
    if (FAILED(hr)) {
      LOG(ERROR) << "Failed to enumerate compiland enumerator.";
      return false;
    }
    if (hr != S_OK || fetched == 0)
      break;

    ScopedComPtr<IDiaEnumSymbols> enum_labels;
    hr = compiland->findChildren(SymTagLabel,
                                 NULL,
                                 nsNone,
                                 enum_labels.Receive());
    if (FAILED(hr)) {
      LOG(ERROR) << "Failed to retrieve label enumerator: " << hr;
      return false;
    }

    while (true) {
      ScopedComPtr<IDiaSymbol> label;
      hr = enum_labels->Next(1, label.Receive(), &fetched);
      if (FAILED(hr)) {
        LOG(ERROR) << "Failed to enumerate label enumerator.";
        return false;
      }
      if (hr != S_OK || fetched == 0)
        break;

      DCHECK(IsSymTag(label, SymTagLabel));

      DWORD addr = 0;
      ScopedBstr name;
      if (FAILED(label->get_relativeVirtualAddress(&addr)) ||
          FAILED(label->get_name(name.Receive()))) {
        LOG(ERROR) << "Failed to retrieve label address or name.";
        return false;
      }

      RelativeAddress label_addr(addr);
      BlockGraph::Block* block = image_->GetBlockByAddress(label_addr);
      if (block == NULL) {
        LOG(ERROR) << "No block for label " << name << " at " << addr;
        return false;
      }

      std::string label_name;
      if (!WideToUTF8(name, name.Length(), &label_name)) {
        LOG(ERROR) << "Failed to convert label name to UTF8.";
        return false;
      }

      RelativeAddress block_addr;
      if (!image_->GetAddressOf(block, &block_addr)) {
        NOTREACHED() << "Block " << block->name() << " has no address.";
        return false;
      }

      AddLabelToCodeBlock(label_addr, label_name, block);
    }
  }

  return true;
}

bool Decomposer::CreateSectionGapBlocks(const IMAGE_SECTION_HEADER* header,
                                        BlockGraph::BlockType block_type) {
  RelativeAddress section_begin(header->VirtualAddress);
  RelativeAddress section_end(section_begin + header->Misc.VirtualSize);
  RelativeAddress image_end(
      image_file_.nt_headers()->OptionalHeader.SizeOfImage);

  // Search for the first and last blocks interesting from the start and end
  // of the section to the end of the image.
  BlockGraph::AddressSpace::RangeMap::const_iterator it(
      image_->address_space_impl().FindFirstIntersection(
          BlockGraph::AddressSpace::Range(section_begin,
                                          image_end - section_begin)));
  BlockGraph::AddressSpace::RangeMap::const_iterator end(
      image_->address_space_impl().FindFirstIntersection(
          BlockGraph::AddressSpace::Range(section_end,
                                          image_end - section_end)));

  if (it == end) {
    // No block for the section, map the whole thing.
    BlockGraph::Block* section = FindOrCreateBlock(
        block_type, section_begin, section_end - section_begin,
        StringPrintf("Gap Section %s", header->Name).c_str());
    DCHECK(section != NULL);
    section->set_attribute(BlockGraph::GAP_BLOCK);
    if (section->data() == NULL) {
      // The section is only partially defined.
      const uint8* data = image_file_.GetImageData(section_begin,
                                                   header->SizeOfRawData);
      DCHECK(data != NULL);
      section->set_data(data);
      section->set_data_size(header->SizeOfRawData);
    }

    return true;
  }

  // Do we need to fill in the start?
  if (section_begin < it->first.start()) {
    BlockGraph::Block* added = FindOrCreateBlock(block_type, section_begin,
        it->first.start() - section_begin, "Gap Start Block");
    added->set_attribute(BlockGraph::GAP_BLOCK);
    if (!added) {
      LOG(ERROR) << "Failed to create block for start of code section "
          << header->Name;
      return false;
    }
  }

  // Now iterate the blocks and fill in gaps.
  for (; it != end; ++it) {
    const BlockGraph::Block* block = it->second;
    DCHECK(block != NULL);
    RelativeAddress block_end = it->first.start() + block->size();
    if (block_end >= section_end)
      break;

    // Walk to the next address in turn.
    BlockGraph::AddressSpace::RangeMap::const_iterator next = it;
    ++next;
    if (next == end) {
      // We're at the end of the list.
      DCHECK(block_end < section_end);
      BlockGraph::Block* added = FindOrCreateBlock(block_type,
                                                   block_end,
                                                   section_end - block_end,
                                                   "Gap Tail Block");
      DCHECK(added != NULL);
      added->set_attribute(BlockGraph::GAP_BLOCK);
      break;
    }

    if (block_end < next->first.start()) {
      BlockGraph::Block* added = FindOrCreateBlock(
          block_type, block_end, next->first.start() - block_end,
          StringPrintf("Gap Block 0x%08X", block_end).c_str());
      DCHECK(added != NULL);
      added->set_attribute(BlockGraph::GAP_BLOCK);
    }
  }

  return true;
}

void Decomposer::AddLabelToCodeBlock(RelativeAddress addr,
                                     const std::string& name,
                                     BlockGraph::Block* block) {
  // This only makes sense for code blocks that contain the given label
  // address.
  DCHECK(block != NULL);
  DCHECK(block->type() == BlockGraph::CODE_BLOCK);
  DCHECK(addr >= block->addr());
  // This is '<= size' because we legitimately get function labels that
  // land at the end of the function.
  DCHECK(addr <= block->addr() + block->size());

  // Only add referenced labels to the block. Unreferenced labels do
  // not get used as disassembly starting points.
  bool referenced = reloc_refs_.find(addr) != reloc_refs_.end();
  if (referenced)
    block->SetLabel(addr - block->addr(), name.c_str());
  else
    unreferenced_labels_.insert(std::make_pair(addr, name));
}

void Decomposer::AddReferenceCallback(RelativeAddress src_addr,
                                      BlockGraph::ReferenceType type,
                                      BlockGraph::Size size,
                                      RelativeAddress dst_addr,
                                      const char* name) {
  // This is only called by the PEFileParser, and it creates some references
  // for which there are no corresponding fixup entries.
  // TODO(chrisha): Add a 'success' output parameter to the callback so
  //     that we can interrupt the PEFileParser if this fails. Currently,
  //     it'll simply log an error message.
  ValidateOrAddReference(FIXUP_MAY_EXIST, src_addr, type, size, dst_addr,
                         0, name, &fixup_map_, &references_);
}

bool Decomposer::ParseRelocs() {
  if (!image_file_.DecodeRelocs(&reloc_set_)) {
    LOG(ERROR) << "Unable to decode image relocs.";
    return false;
  }

  PEFile::RelocMap reloc_map;
  if (!image_file_.ReadRelocs(reloc_set_, &reloc_map)) {
    LOG(ERROR) << "Unable to read image relocs.";
    return false;
  }

  // Get a set of relocation destinations. These are effectively 'references'
  // to labels, and will be used to weed out unreferenced labels.
  PEFile::RelocMap::const_iterator it = reloc_map.begin();
  for (; it != reloc_map.end(); ++it) {
    RelativeAddress rva;
    if (!image_file_.Translate(it->second, &rva)) {
      LOG(ERROR) << "Unable to translate absolute address to relative: "
          << it->second;
      return false;
    }
    reloc_refs_.insert(rva);
  }

  // Validate each relocation entry against the corresponding fixup entry.
  if (!ValidateRelocs(reloc_map))
    return false;

  return true;
}

bool Decomposer::CreateReferencesFromFixups() {
  FixupMap::const_iterator it(fixup_map_.begin());
  for (; it != fixup_map_.end(); ++it) {
    RelativeAddress src_addr(it->second.location);
    uint32 data = 0;
    if (!image_file_.ReadImage(src_addr, &data, sizeof(data))) {
      LOG(ERROR) << "Unable to read image data for fixup with source at RVA "
          << StringPrintf("0x%08X.", src_addr.value());
      return false;
    }

    RelativeAddress dst_addr;
    switch (it->second.type) {
      case BlockGraph::PC_RELATIVE_REF: {
        dst_addr = src_addr + kPointerSize + data;
        break;
      }

      case BlockGraph::ABSOLUTE_REF: {
        AbsoluteAddress dst_addr_abs(data);
        bool success = image_file_.Translate(dst_addr_abs, &dst_addr);
        DCHECK_EQ(true, success);
        break;
      }

      case BlockGraph::RELATIVE_REF: {
        dst_addr = RelativeAddress(data);
        break;
      }

      default: {
        NOTREACHED() << "Invalid reference type.";
        break;
      }
    }

    RelativeAddress dst_base(it->second.base);
    BlockGraph::Offset dst_offset = dst_addr - dst_base;
    std::string label(StringPrintf("From 0x%08X", src_addr.value()));
    if (!AddReference(src_addr, it->second.type, kPointerSize, dst_base,
                      dst_offset, label.c_str(), &references_))
      return false;
  }

  return true;
}

bool Decomposer::ValidateRelocs(const PEFile::RelocMap& reloc_map) {
  PEFile::RelocMap::const_iterator it(reloc_map.begin());
  PEFile::RelocMap::const_iterator end(reloc_map.end());
  for (; it != end; ++it) {
    RelativeAddress src(it->first);
    RelativeAddress dst;
    if (!image_file_.Translate(it->second, &dst)) {
      LOG(ERROR) << "Unable to translate relocation destination.";
      return false;
    }

    if (!ValidateOrAddReference(FIXUP_MUST_EXIST, src, BlockGraph::ABSOLUTE_REF,
                                sizeof(dst), dst, 0, NULL, &fixup_map_,
                                &references_))
      return false;
  }

  return true;
}

bool Decomposer::ProcessDataAndPublicSymbols(IDiaSymbol* global,
                                             DataLabels* data_labels) {
  ScopedComPtr<IDiaEnumSymbols> enum_data;
  HRESULT hr = global->findChildren(SymTagData,
                                    NULL,
                                    nsNone,
                                    enum_data.Receive());
  if (FAILED(hr)) {
    LOG(ERROR) << "Failed to get the DIA data enumerator: " << hr;
    return false;
  }

  while (true) {
    ScopedComPtr<IDiaSymbol> data;
    ULONG fetched = 0;
    hr = enum_data->Next(1, data.Receive(), &fetched);
    if (FAILED(hr)) {
      LOG(ERROR) << "Failed to enumerate data: " << hr;
      return false;
    }
    if (hr != S_OK || fetched == 0)
      break;

    DCHECK(IsSymTag(data, SymTagData));

    if (!ProcessDataOrPublicSymbol(data, data_labels))
      return false;
  }

  ScopedComPtr<IDiaEnumSymbols> enum_public_symbols;
  hr = global->findChildren(SymTagPublicSymbol,
                            NULL,
                            nsNone,
                            enum_public_symbols.Receive());
  if (FAILED(hr)) {
    LOG(ERROR) << "Failed to get the DIA public symbols enumerator: " << hr;
    return false;
  }

  while (true) {
    ScopedComPtr<IDiaSymbol> public_symbol;
    ULONG fetched = 0;
    hr = enum_public_symbols->Next(1, public_symbol.Receive(), &fetched);
    if (FAILED(hr)) {
      LOG(ERROR) << "Failed to enumerate public symbols: " << hr;
      return false;
    }
    if (hr != S_OK || fetched == 0)
      break;

    DCHECK(IsSymTag(public_symbol, SymTagPublicSymbol));

    if (!ProcessDataOrPublicSymbol(public_symbol, data_labels))
      return false;
  }

  return true;
}

bool Decomposer::ProcessDataOrPublicSymbol(IDiaSymbol* data,
                                           DataLabels* data_labels) {
  DWORD sym_tag = SymTagNull;
  if (!GetSymTag(data, &sym_tag))
    return false;
  DCHECK(sym_tag == SymTagData || sym_tag == SymTagPublicSymbol);

  DWORD location_type = LocIsNull;
  if (FAILED(data->get_locationType(&location_type))) {
    LOG(ERROR) << "Failed to retrieve data address type.";
    return false;
  }
  if (location_type != LocIsStatic) {
    return true;
  }

  DWORD rva = 0;
  ScopedBstr name;
  if (FAILED(data->get_relativeVirtualAddress(&rva)) ||
      FAILED(data->get_name(name.Receive()))) {
    LOG(ERROR) << "Failed to retrieve data information.";
    return false;
  }

  // Get the section containing this address.
  RelativeAddress addr(rva);
  const IMAGE_SECTION_HEADER* section_header =
      image_file_.GetSectionHeader(addr, 1);
  // Skip symbols that lie outside of any known sections. This can happen
  // for symbols that lie within the headers.
  if (section_header == NULL)
    return true;
  // Skip the section if it's not code or data.
  SectionType section_type = GetSectionType(section_header);
  if (section_type == kSectionUnknown)
    return true;

  std::string data_name;
  if (!WideToUTF8(name, name.Length(), &data_name)) {
    LOG(ERROR) << "Failed to convert label name to UTF8.";
    return false;
  }

  // PublicSymbols contain meaningless length information so we can only
  // really use them as labels. In the case of labels into data, we store them
  // in a temporary structure before using them to chunk out blocks. For
  // code, we add them as labels to existing code blocks.
  if (sym_tag == SymTagPublicSymbol) {
    // Public symbol names are mangled. Remove leading '_' as per
    // http://msdn.microsoft.com/en-us/library/00kh39zz(v=vs.80).aspx
    if (data_name[0] == '_')
      data_name = data_name.substr(1);

    if (section_type == kSectionData) {
      data_labels->insert(std::make_pair(addr, data_name));
    } else if (section_type == kSectionCode) {
      BlockGraph::Block* block = image_->GetContainingBlock(addr, 1);
      if (block != NULL) {
        BlockGraph::Offset offset = addr - block->addr();
        if (offset)
          block->SetLabel(offset, data_name.c_str());
      } else {
        LOG(ERROR) << "Code PublicSymbol does not land in a code block.";
        return false;
      }
    }
    return true;
  }

  size_t length = 0;
  if (!GetTypeInfo(data, &length))
    return false;

  // Zero length Data symbols act as 'forward declares' in some sense. They
  // appear to always be followed by a non-zero length Data symbol with the
  // same name and location.
  if (length == 0)
    return true;

  // TODO(chrisha): The NativeClient bits of chrome.dll consists of hand-written
  //     assembly that are compiled using a custom non-Microsoft toolchain.
  //     Unfortunately for us this toolchain emits 1-byte data symbols instead
  //     of code labels. Thus, we mark valid code as data and it eventually
  //     gets trampled on by the disassembler.
  // TODO(chrisha): Maybe output these as code labels for the appropriate
  //     block?
  static const char kNaClPrefix[] = "NaCl";
  if (length == 1 &&
      data_name.compare(0, arraysize(kNaClPrefix) - 1, kNaClPrefix) == 0)
    return true;

  // If this is in a code block, push it to the data-space.
  if (section_type == kSectionCode) {
    if (!data_space_.SubsumeInsert(DataSpace::Range(addr, length), data_name)) {
      LOG(ERROR) << "Data-space insertion failed.";
      return false;
    }
    return true;
  }

  // Create the data block.
  BlockGraph::Block* block = FindOrCreateBlock(BlockGraph::DATA_BLOCK,
                                               addr,
                                               length,
                                               data_name.c_str());
  if (block == NULL) {
    LOG(ERROR) << "Unable to create data-block.";
    return false;
  }
  // Sometimes we get the same block referred to by multiple names. Add the
  // other names as labels.
  if (data_name != block->name())
    block->SetLabel(0, data_name.c_str());

  return true;
}

bool Decomposer::ProcessStaticInitializers() {
  typedef std::pair<RelativeAddress, RelativeAddress> AddressPair;
  typedef std::map<std::string, AddressPair> AddressPairMap;

  const RelativeAddress kNull(0);

  // This stores pairs of addresses, representing the beginning and the end
  // of each static initializer block. It is keyed with a string, which is
  // returned by the match group of the corresponding initializer pattern.
  // The key is necessary to correlate matching labels (as multiple pairs
  // of labels may match through a single pattern).
  AddressPairMap addr_pair_map;

  // Used for keeping track of which label, if any, we matched.
  enum MatchType {
    kMatchNone,
    kMatchBeginLabel,
    kMatchEndLabel
  };

  // Iterate through all data blocks, looking for known initializer labels.
  BlockGraph::AddressSpace::RangeMapConstIter block_it = image_->begin();
  for (; block_it != image_->end(); ++block_it) {
    const BlockGraph::Block* block = block_it->second;
    // Skip non-data blocks.
    if (block->type() != BlockGraph::DATA_BLOCK)
      continue;

    // Check the block name against each of the initializer patterns.
    MatchType match = kMatchNone;
    std::string block_name = block->name();
    std::string name;
    for (size_t i = 0; i < static_initializer_patterns_.size(); ++i) {
      REPair& re_pair(static_initializer_patterns_[i]);
      if (re_pair.first.FullMatch(block_name, &name))
        match = kMatchBeginLabel;
      else if (re_pair.second.FullMatch(block_name, &name))
        match = kMatchEndLabel;

      if (match != kMatchNone)
        break;
    }

    // No pattern matched this symbol? Continue to the next one.
    if (match == kMatchNone)
      continue;

    // Ensure this symbol exists in the map. Thankfully, addresses default
    // construct to NULL.
    AddressPair& addr_pair = addr_pair_map[name];

    // Update the bracketing symbol endpoint. Make sure each symbol endpoint
    // is only seen once.
    RelativeAddress* addr = NULL;
    RelativeAddress new_addr;
    if (match == kMatchBeginLabel) {
      addr = &addr_pair.first;
      new_addr = block->addr();
    } else {
      addr = &addr_pair.second;
      new_addr = block->addr() + block->size();
    }
    if (*addr != kNull) {
      LOG(ERROR) << "Bracketing symbol appears multiple times: "
          << block_name;
      return false;
    }
    *addr = new_addr;
  }

  // Use the bracketing symbols to make the initializers contiguous.
  AddressPairMap::const_iterator init_it = addr_pair_map.begin();
  for (; init_it != addr_pair_map.end(); ++init_it) {
    RelativeAddress begin_addr = init_it->second.first;
    if (begin_addr == kNull) {
      LOG(ERROR) << "Bracketing start symbol missing: " << init_it->first;
      return false;
    }

    RelativeAddress end_addr = init_it->second.second;
    if (end_addr == kNull) {
      LOG(ERROR) << "Bracketing end symbol missing: " << init_it->first;
      return false;
    }

    if (begin_addr > end_addr) {
      LOG(ERROR) << "Bracketing symbols out of order: " << init_it->first;
      return false;
    }

    // Merge the initializers.
    DataSpace::Range range(begin_addr, end_addr - begin_addr);
    BlockGraph::Block* merged = image_->MergeIntersectingBlocks(range);
    std::string name = StringPrintf("Bracketed Initializers: %s",
                                    init_it->first.c_str());
    merged->set_name(name.c_str());
    DCHECK(merged != NULL);
  }

  return true;
}

bool Decomposer::ExtendDataLabels(const DataLabels& data_labels) {
  // We are only interested in labels in data sections, so iterate through
  // the sections and only process data sections.
  size_t section_count = image_file_.nt_headers()->FileHeader.NumberOfSections;
  for (size_t section_id = 0; section_id < section_count; ++section_id) {
    const IMAGE_SECTION_HEADER* header = image_file_.section_header(section_id);
    if (GetSectionType(header) != kSectionData)
      continue;

    RelativeAddress section_begin(header->VirtualAddress);
    RelativeAddress section_end(header->VirtualAddress +
                                header->Misc.VirtualSize);

    // Get the range of labels that lie in this section.
    DataLabels::const_iterator it = data_labels.lower_bound(section_begin);
    DataLabels::const_iterator it_end = data_labels.lower_bound(section_end);

    // Extend any data labels at previously unseen locations until the next
    // known end of section, label or block.
    for (; it != it_end; ++it) {
      // Skip labels that lie within any blocks we already know about.
      BlockGraph::Block* block = image_->GetContainingBlock(it->first, 1);
      if (block != NULL) {
        // We often get many (sometimes hundreds) of labels into a single
        // block, so it's more efficient to iterate labels until the block
        // is exhausted.
        RelativeAddress block_end = block->addr() + block->size();
        while (it != it_end && it->first < block_end) {
          // We only stored labels in data sections, so this should never
          // happen.
          DCHECK(block->type() != BlockGraph::CODE_BLOCK);
          BlockGraph::Offset offset = it->first - block->addr();
          // If the label is at offset 0 and has the same value as the
          // block name, don't add it (it's simply duplicate information).
          if (offset != 0 || it->second != block->name())
            block->SetLabel(offset, it->second.c_str());
          ++it;
        }
        --it;
        continue;
      }

      // Use the end of the section as our first upper bound for the end
      // of the new block.
      RelativeAddress end = section_end;

      // Find the next known data label and use it to lower bound the end of
      // the new block.
      DataLabels::const_iterator next_it = it;
      ++next_it;
      if (next_it != it_end) {
        if (next_it->first < end)
          end = next_it->first;
      }

      // Find the next known block and use it to lower bound the end of the
      // new block.
      block = image_->GetFirstIntersectingBlock(it->first, end - it->first);
      if (block != NULL && block->addr() < end)
        end = block->addr();

      block = CreateBlock(BlockGraph::DATA_BLOCK,
                          it->first,
                          end - it->first,
                          it->second.c_str());
      DCHECK(block != NULL);
    }
  }

  return true;
}

// Extends/creates a data block using reloc information.
void Decomposer::ExtendOrCreateDataRangeUsingRelocs(
    const std::string& name, RelativeAddress addr, size_t min_size) {
  DCHECK(min_size > 0);

  // We only extend data elements that lie within a code block.
  const BlockGraph::Block* block = image_->GetContainingBlock(addr, 1);
  if (block == NULL || block->type() != BlockGraph::CODE_BLOCK)
    return;

  // Use the end of the block as a first upper bound.
  RelativeAddress end = block->addr() + block->size();

  // Get the item in the data-space that is immediately after any intersecting
  // range. This will be used as another upper bound.
  DataSpace::Range data_range(addr, min_size);
  DataSpace::RangeMapConstIter data_it =
      data_space_.ranges().lower_bound(data_range);
  if (data_it != data_space_.end() && data_it->first.Intersects(data_range))
    ++data_it;
  if (data_it != data_space_.end() && data_it->first.end() < end)
      end = data_it->first.end();

  // Find the length of the run of relocs starting at this address,
  // stopping ourselves at the upper bound we determined earlier.
  size_t count = 0;
  RelativeAddress data_end = addr;
  PEFile::RelocSet::const_iterator reloc_it = reloc_set_.find(addr);
  while (true) {
    if (reloc_it == reloc_set_.end() || data_end + kPointerSize > end)
      break;
    ++count;
    data_end += kPointerSize;

    // Advance to the next reloc. Only continue if it's contiguous.
    ++reloc_it;
    if (*reloc_it != data_end)
      break;
  }

  // Only create the entry if it meets the minimum size.
  if (count * kPointerSize > min_size) {
    DataSpace::Range range(addr, count * kPointerSize);
    // This should never fail because of our earlier calculations of 'end'.
    bool success = data_space_.SubsumeInsert(range, name);
    DCHECK(success);
  }
}

bool Decomposer::ExtendDataRangesUsingRelocs() {
  // Extend any data-within-code-blocks that consist of runs of relocs. We
  // do this because we occasionally (in hand-crafted assembly) see DD lookup
  // table symbols that are reported as being 1 DWORD in length, rather than
  // reporting their true length.
  DataSpace::RangeMapIter next_data_it = data_space_.begin();
  while (next_data_it != data_space_.end()) {
    DataSpace::RangeMapIter data_it = next_data_it;
    ++next_data_it;

    // This may invalidate the iterator to data_it, hence the reason we
    // keep around next_data_it. Also the reason why we create a copy of the
    // name.
    std::string name(data_it->second);
    ExtendOrCreateDataRangeUsingRelocs(
        name, data_it->first.start(), data_it->first.size());
  }

  return true;
}

bool Decomposer::CreateDataGapBlocks() {
  size_t num_sections = image_file_.nt_headers()->FileHeader.NumberOfSections;
  // Iterate through all the image sections.
  for (size_t i = 0; i < num_sections; ++i) {
    const IMAGE_SECTION_HEADER* header = image_file_.section_header(i);
    DCHECK(header != NULL);

    // And create a block for any gaps in data sections.
    if (GetSectionType(header) != kSectionData)
      continue;
    if (!CreateSectionGapBlocks(header, BlockGraph::DATA_BLOCK)) {
      LOG(ERROR) << "Unable to create gap blocks for data section "
          << header->Name;
      return false;
    }
  }

  return true;
}

bool Decomposer::CreateDataBlocks(IDiaSymbol* global) {
  // Process data symbols and public symbols.
  DataLabels data_labels;
  if (!ProcessDataAndPublicSymbols(global, &data_labels))
    return false;

  // Now that we have data sets and relocation entries, we can extend some
  // data blocks. Doing this is necessary because some in-function jump tables
  // are reported with too-short lengths (only seen for hand-written assembly
  // thus far). After this, data_space_ contains ranges marking in-code data.
  if (!ExtendDataRangesUsingRelocs())
    return false;

  // Some data (that indicated by public symbols) has uncertain length. We
  // extend the length of these data blocks to the next known label/block in
  // order not to subdivide data elements. After this, data_labels may be
  // discarded.
  // TODO(chrisha): Investigate chunking using the SectionContributions table
  //     provided by DIA. This seems to give us much finer grained information
  //     regarding padding bytes, etc, and it can then be refined using
  //     symbol information.
  if (!ExtendDataLabels(data_labels))
    return false;

  // Flesh out the data sections with gap blocks.
  if (!CreateDataGapBlocks())
    return false;

  // Parse initialization bracketing symbols.
  if (!ProcessStaticInitializers())
    return false;

  return true;
}

bool Decomposer::CreateCodeLabelsFromFixups() {
  // We iterate through all intermediate references, and create code labels
  // for those references we know to be pointing directly to code.
  IntermediateReferenceMap::const_iterator ref_it(references_.begin());
  for (; ref_it != references_.end(); ++ref_it) {
    const RelativeAddress& src = ref_it->first;
    const IntermediateReference& ref = ref_it->second;
    BlockGraph::Block* src_block = image_->GetContainingBlock(src, 1);
    BlockGraph::Block* dst_block =
        image_->GetContainingBlock(ref.base, 1);
    DCHECK(src_block != NULL);
    DCHECK(dst_block != NULL);

    if (dst_block->type() != BlockGraph::CODE_BLOCK)
      continue;

    BlockGraph::Offset src_offset = ref_it->first - src_block->addr();
    BlockGraph::Offset dst_offset = ref.base - dst_block->addr();

    if (dst_block->HasLabel(dst_offset))
      continue;

    FixupMap::const_iterator it = fixup_map_.find(ref_it->first);
    DCHECK(it != fixup_map_.end());

    // Only add labels for PC_RELATIVE references or references that are
    // directly labelled as pointing to code.
    if (it->second.type != BlockGraph::PC_RELATIVE_REF &&
        !it->second.refers_to_code)
      continue;

    // If it had no label here, we add one.
    std::string label(base::StringPrintf("From %s +0x%x",
                                         src_block->name(),
                                         src_offset));
    dst_block->SetLabel(dst_offset, label.c_str());
  }

  return true;
}

bool Decomposer::CreateCodeReferences() {
  // Queue all blocks for disassembly.
  BlockGraph::BlockMap::iterator it(image_->graph()->blocks_mutable().begin());
  BlockGraph::BlockMap::iterator end(image_->graph()->blocks_mutable().end());
  for (; it != end; ++it) {
    BlockGraph::Block* block = &it->second;
    if (block->type() == BlockGraph::CODE_BLOCK)
      to_disassemble_.insert(block);
  }

  // Disassemble all blocks, note that this process is potentially iterative,
  // as if disassembly turns up a PC-relative reference to another function
  // (block) at a location that didn't already have a label, it'll label that
  // location and re-queue the destination function for disassembly.
  DCHECK(to_merge_.empty());
  while (!to_disassemble_.empty()) {
    while (!to_disassemble_.empty()) {
      BlockSet::iterator it = to_disassemble_.begin();
      BlockGraph::Block* block = *it;
      to_disassemble_.erase(it);

      if (!CreateCodeReferencesForBlock(block)) {
        return false;
      }
    }

    DCHECK(to_disassemble_.empty());

    // Merge any ranges scheduled for merging, then re-schedule the
    // merged blocks for disassembly. Doing this outside the above loop
    // avoids orphaning scheduled blocks as we merge them together,
    // and is slightly more efficient as we may merge larger clusters
    // of blocks and avoid some disassembly/merging iterations.
    if (!to_merge_.empty()) {
      RangeSet::const_iterator it = to_merge_.begin();
      BlockGraph::AddressSpace::Range range(*it);
      to_merge_.erase(it);

      BlockGraph::Block* merged = image_->MergeIntersectingBlocks(range);
      DCHECK(merged != NULL);
      to_disassemble_.insert(merged);
    }
  }

  return true;
}

bool Decomposer::CreateCodeReferencesForBlock(BlockGraph::Block* block) {
  DCHECK(current_block_ == NULL);
  current_block_ = block;

  RelativeAddress block_addr;
  if (!image_->GetAddressOf(block, &block_addr)) {
    LOG(ERROR) << "Block " << block->name() << " has no address.";
    return false;
  }

  AbsoluteAddress abs_block_addr;
  if (!image_file_.Translate(block_addr, &abs_block_addr)) {
    LOG(ERROR) << "Unable to get absolute address for " << block_addr;
    return false;
  }

  scoped_ptr<Disassembler::InstructionCallback> on_instruction(
      NewCallback(this, &Decomposer::OnInstruction));

  // Use block labels as starting points for disassembly. Any labels that
  // lie within a known data block or reloc should not be added.
  // TODO(chrisha): Should we actually remove these from the Block?
  BlockGraph::Block::LabelMap::const_iterator it(block->labels().begin());
  Disassembler::AddressSet labels;
  for (; it != block->labels().end(); ++it) {
    BlockGraph::Offset label = it->first;
    DCHECK(label >= 0 && static_cast<size_t>(label) <= block->size());

    RelativeAddress addr(block->addr() + static_cast<size_t>(label));
    DataSpace::Range range(addr, 1);

    bool is_reloc = reloc_set_.find(addr) != reloc_set_.end();
    bool in_data = data_space_.Intersects(range);
    bool at_end = static_cast<size_t>(label) == block->size();

    // Labels that lie within a reloc, known data, or the end of the function
    // should not be used as starting points for disassembly.
    if (!is_reloc && !in_data && !at_end)
      labels.insert(abs_block_addr + it->first);
  }

  Disassembler disasm(block->data(),
                      block->data_size(),
                      abs_block_addr,
                      labels,
                      on_instruction.get());
  Disassembler::WalkResult result = disasm.Walk();
  CalcDetailedCodeBlockStats(
      block, disasm, data_space_, &code_block_stats_[block->id()]);

  DCHECK_EQ(block, current_block_);
  current_block_ = NULL;

  return (result == Disassembler::kWalkSuccess ||
      result == Disassembler::kWalkIncomplete);
}

void Decomposer::ScheduleForMerging(BlockGraph::Block* block1,
                                    BlockGraph::Block* block2) {
  RelativeAddress start(std::min(block1->addr(), block2->addr()));
  RelativeAddress end(std::max(block1->addr() + block1->size(),
                               block2->addr() + block2->size()));

  to_merge_.insert(BlockGraph::AddressSpace::Range(start, end - start));
}

BlockGraph::Block* Decomposer::CreateBlock(BlockGraph::BlockType type,
                                           RelativeAddress address,
                                           BlockGraph::Size size,
                                           const char* name) {
  BlockGraph::Block* block = image_->AddBlock(type, address, size, name);
  if (block == NULL) {
    LOG(ERROR) << "Unable to add block at " << address.value()
        << "(" << size << ").";
    return NULL;
  }

  size_t id = image_file_.GetSectionIndex(address, size);
  block->set_section(id);
  if (id != kInvalidSection) {
    DCHECK(id < image_file_.nt_headers()->FileHeader.NumberOfSections);
    const IMAGE_SECTION_HEADER* header = image_file_.section_header(id);
    RelativeAddress begin(header->VirtualAddress);
    RelativeAddress end(begin + header->Misc.VirtualSize);
    if (address < begin || address + size > end) {
      LOG(ERROR) << "No section contains block at " << address.value()
          << "(" << size << ")";
      return NULL;
    }
  }

  const uint8* data = image_file_.GetImageData(address, size);
  if (data != NULL) {
    block->set_data(data);
    block->set_data_size(size);
  }

  return block;
}

BlockGraph::Block* Decomposer::FindOrCreateBlock(BlockGraph::BlockType type,
                                                 RelativeAddress addr,
                                                 BlockGraph::Size size,
                                                 const char* name) {
  BlockGraph::Block* block = image_->GetBlockByAddress(addr);
  if (block != NULL) {
    RelativeAddress block_addr;
    if (!image_->GetAddressOf(block, &block_addr)) {
      LOG(ERROR) << "No address for block " << block->name();
      return NULL;
    }

    if (block_addr != addr || block->size() != size) {
      LOG(ERROR) << "Block collision for function at "
          << addr.value() << "(" << size << ") with " << block->name();
      return NULL;
    }

    return block;
  }
  DCHECK(block == NULL);

  return CreateBlock(type, addr, size, name);
}

void Decomposer::OnBasicInstruction(
    const Disassembler& walker,
    const _DInst& instruction,
    Disassembler::CallbackDirective* directive) {
  DCHECK(directive != NULL);

  AbsoluteAddress instr_abs(static_cast<uint32>(instruction.addr));
  RelativeAddress instr_rel;
  if (!image_file_.Translate(instr_abs, &instr_rel)) {
    LOG(ERROR) << "Unable to translate instruction address.";
    *directive = Disassembler::kDirectiveAbort;
    return;
  }

  // If this instruction runs over data, bail!
  DataSpace::Range range(instr_rel, instruction.size);
  DataSpace::RangeMapConstIterPair its = data_space_.FindIntersecting(range);
  if (its.first != its.second) {
    LOG(ERROR) << "Trying to disassemble into known data.";
    *directive = Disassembler::kDirectiveAbort;
    return;
  }

  // If this instruction terminates at a data boundary (ie: the *next*
  // instruction will be data or a reloc), indicate that the path should be
  // terminated.
  RelativeAddress after_instr_rel = instr_rel + instruction.size;
  DataSpace::Range next_byte(after_instr_rel, 1);
  bool will_hit_data =
      data_space_.FindContaining(next_byte) != data_space_.end();
  bool will_hit_reloc = reloc_set_.find(after_instr_rel) != reloc_set_.end();
  if (will_hit_data || will_hit_reloc) {
    *directive = Disassembler::kDirectiveTerminatePath;
  }
}

void Decomposer::OnInstruction(const Disassembler& walker,
                               const _DInst& instruction,
                               Disassembler::CallbackDirective* directive) {
  DCHECK(directive != NULL);

  AbsoluteAddress instr_abs(static_cast<uint32>(instruction.addr));
  RelativeAddress instr_rel;
  if (!image_file_.Translate(instr_abs, &instr_rel)) {
    LOG(ERROR) << "Unable to translate instruction address.";
    *directive = Disassembler::kDirectiveAbort;
    return;
  }

  // If this instruction runs over data, bail!
  DataSpace::Range range(instr_rel, instruction.size);
  DataSpace::RangeMapConstIterPair its = data_space_.FindIntersecting(range);
  if (its.first != its.second) {
    LOG(ERROR) << "Trying to disassemble into known data.";
    *directive = Disassembler::kDirectiveAbort;
    return;
  }

  // If this instruction terminates at a data boundary (ie: the *next*
  // instruction will be data or a reloc), indicate that the path should be
  // terminated.
  RelativeAddress after_instr_rel = instr_rel + instruction.size;
  DataSpace::Range next_byte(after_instr_rel, 1);
  bool will_hit_data =
      data_space_.FindContaining(next_byte) != data_space_.end();
  bool will_hit_reloc = reloc_set_.find(after_instr_rel) != reloc_set_.end();
  if (will_hit_data || will_hit_reloc) {
    *directive = Disassembler::kDirectiveTerminatePath;

    // We can be certain that a new lookup table is starting at this address.
    if (!will_hit_data && will_hit_reloc)
      ExtendOrCreateDataRangeUsingRelocs(
          StringPrintf("Inferred Data 0x%08X", after_instr_rel),
          after_instr_rel, kPointerSize);
  }

  int fc = META_GET_FC(instruction.meta);
  // For all branches, calls and conditional branches to PC-relative
  // addresses, record a PC-relative reference.
  if ((fc == FC_BRANCH || fc == FC_CALL || fc == FC_COND_BRANCH) &&
      instruction.ops[0].type == O_PC) {
    DCHECK_EQ(O_PC, instruction.ops[0].type);
    DCHECK_EQ(O_NONE, instruction.ops[1].type);
    DCHECK_EQ(O_NONE, instruction.ops[2].type);
    DCHECK_EQ(O_NONE, instruction.ops[3].type);
    DCHECK(instruction.ops[0].size == 8 ||
        instruction.ops[0].size == 16 ||
        instruction.ops[0].size == 32);
    // Distorm gives us size in bits, we want bytes.
    BlockGraph::Size size = instruction.ops[0].size / 8;

    // Get the reference's address. Note we assume it's in the instruction's
    // tail end - I don't know of a case where a PC-relative offset in a branch
    // or call is not the very last thing in an x86 instruction.
    AbsoluteAddress abs_src = instr_abs + instruction.size - size;
    AbsoluteAddress abs_dst = instr_abs + instruction.size +
        static_cast<size_t>(instruction.imm.addr);

    RelativeAddress src, dst;
    if (!image_file_.Translate(abs_src, &src) ||
        !image_file_.Translate(abs_dst, &dst)) {
      LOG(ERROR) << "Unable to translate absolute to relative addresses.";
      *directive = Disassembler::kDirectiveAbort;
      return;
    }

    // Get the block associated with the destination address. It must exist
    // and be a code block.
    BlockGraph::Block* block = image_->GetContainingBlock(dst, 1);
    DCHECK(block != NULL);
    DCHECK(block->type() == BlockGraph::CODE_BLOCK);

    // If this is a call and the destination is a non-returning function,
    // then indicate that we should terminate this disassembly path.
    if (fc == FC_CALL &&
        (block->attributes() & BlockGraph::NON_RETURN_FUNCTION)) {
      // TODO(chrisha): For now, we enforce that the call be to the beginning
      //    of the function. This may not be necessary, but better safe than
      //    sorry for now.
      if (block->addr() != dst) {
        LOG(ERROR) << "Calling inside the body of a non-returning function: "
            << block->name();
        *directive = Disassembler::kDirectiveAbort;
        return;
      }
      *directive = Disassembler::kDirectiveTerminatePath;
    }

    // This label has been referred to by code, so make sure it is removed from
    // the set of unreferenced labels before we add it to the block.
    LabelMap::iterator it = unreferenced_labels_.find(dst);
    if (it != unreferenced_labels_.end())
      unreferenced_labels_.erase(it);

    // Add the reference. If it's new, make sure to try and add a label
    // and reschedule the block for disassembly again.
    std::string label(StringPrintf("From %s +0x%x",
                                   block->name(),
                                   instr_rel - block->addr()));

    // For short references, we should not see a fixup.
    ValidateOrAddReferenceMode mode = FIXUP_MUST_NOT_EXIST;
    if (size == kPointerSize) {
      // Long PC_RELATIVE reference within a single block?
      if (block->Contains(src, kPointerSize)) {
        mode = FIXUP_MAY_EXIST;
      } else {
        // TODO(chrisha): Currently, we are overly aggressively subdividing
        //     functions. We eventually (try to) patch them through our
        //     ScheduleBlocksForMerging mechanism, but at the time being we
        //     mislabel intra-block jumps as inter-block jumps. It is our
        //     suspicion that FIXUPs are not provided for 4-byte PC_RELATIVE
        //     references that originate and land within the same COMDAT.
        //     This needs to be revisited once we parse SectionContribs as
        //     our initial chunking. When this happens, try
        //     mode = FIXUP_MUST_EXIST here.
        mode = FIXUP_MAY_EXIST;
      }
    }

    // Validate or create the reference, as necessary.
    if (!ValidateOrAddReference(mode, src, BlockGraph::PC_RELATIVE_REF, size,
                                dst, 0, label.c_str(), &fixup_map_,
                                &references_)) {
      *directive = Disassembler::kDirectiveAbort;
      return;
    }

    // See whether the block has a label at the offset.
    BlockGraph::Offset offset = dst - block->addr();
    if (!block->HasLabel(offset)) {
      // If it has no label here, we add one.
      std::string label(base::StringPrintf("From 0x%08X", src.value()));
      block->SetLabel(offset, label.c_str());

      // And then potentially re-schedule the block for disassembly,
      // as we may have turned up another entry to a block we already
      // disassembled.
      to_disassemble_.insert(block);
    }

    // For short references across blocks, we want to make sure we merge
    // the two blocks. AFAICT, this only occurs in hand-coded assembly in
    // the CRT, and the "functions" involved are not independent.
    if (block != current_block_ && size != sizeof(RelativeAddress))
      ScheduleForMerging(current_block_, block);
  }

  // We want to find function blocks where control flow runs off the end
  // of the function into the immediately adjoining block, and schedule
  // the two for merging. AFAICT, this again only occurs in hand-crafted
  // assembly in the CRT.
  if (fc != FC_RET && fc != FC_BRANCH && fc != FC_INT) {
    RelativeAddress instr_end(instr_rel + instruction.size);
    RelativeAddress block_end(current_block_->addr() + current_block_->size());
    if  (instr_end == block_end) {
      // Find the following block.
      BlockGraph::Block* next_block =
          image_->GetFirstIntersectingBlock(block_end, 1);
      DCHECK(next_block != NULL);

      // And schedule the two for merging.
      ScheduleForMerging(current_block_, next_block);
    }
  }

  if (fc == FC_CALL) {
    // TODO(chrisha): For call instructions, see whether they call a
    //     non-returning function. Instruct the disassembler not to continue
    //     disassembly past the instruction in that case.
    //     The case where the address is PC-relative is handled in the above
    //     code. However, the called function could also be at an
    //     indirect absolute address when invoking imported symbols. We do not
    //     currently have meta-data regarding these symbols, so do not know if
    //     they are non-returning.
  }
}

bool Decomposer::CreatePEImageBlocksAndReferences(
    PEFileParser::PEHeader* header) {
  scoped_ptr<PEFileParser::AddReferenceCallback> add_reference(
      NewCallback(this, &Decomposer::AddReferenceCallback));
  PEFileParser parser(image_file_, image_, add_reference.get());

  if (!parser.ParseImage(header)) {
    LOG(ERROR) << "Unable to parse PE image.";
    return false;
  }

  return true;
}

bool Decomposer::FinalizeIntermediateReferences() {
  IntermediateReferenceMap::const_iterator it(references_.begin());
  IntermediateReferenceMap::const_iterator end(references_.end());

  for (; it != end; ++it) {
    RelativeAddress src_addr(it->first);
    BlockGraph::Block* src = image_->GetBlockByAddress(src_addr);
    RelativeAddress dst_base(it->second.base);
    RelativeAddress dst_addr(dst_base + it->second.offset);
    BlockGraph::Block* dst = image_->GetBlockByAddress(dst_base);

    if (src == NULL || dst == NULL) {
      LOG(ERROR) << "Reference source or base destination address is out of "
          << "range, src: " << src << ", dst: " << dst;
      return false;
    }

    RelativeAddress src_start = src->addr();
    RelativeAddress dst_start = dst->addr();

    // Get the offset of the ultimate destination relative to the start of the
    // destination block.
    BlockGraph::Offset dst_offset = dst_addr - dst_start;

    BlockGraph::Reference ref(it->second.type,
                              it->second.size,
                              dst,
                              dst_offset);
    src->SetReference(src_addr - src_start, ref);
  }

  references_.clear();

  return true;
}

bool Decomposer::ConfirmFixupsVisited() const {
  bool success = true;

  // Ideally, all fixups should have been visited during decomposition.
  // TODO(chrisha): Address the root problems underlying the following
  //     temporary fix.
  FixupMap::const_iterator fixup_it = fixup_map_.begin();
  for (; fixup_it != fixup_map_.end(); ++fixup_it) {
    if (fixup_it->second.visited)
      continue;

    const BlockGraph::Block* block =
        image_->GetContainingBlock(fixup_it->first, kPointerSize);
    DCHECK(block != NULL);

    // We know that we currently do not have full disassembly coverage as there
    // are several orphaned pieces of apparently unreachable code in the CRT
    // that we do not disassemble, but which may contain jmp or call commands.
    // Thus, we expect that missed fixups are all PC-relative and lie within
    // code blocks.
    if (block->type() == BlockGraph::CODE_BLOCK &&
        fixup_it->second.type == BlockGraph::PC_RELATIVE_REF)
      continue;

    success = false;
    LOG(ERROR) << "Unexpected unseen fixup at RVA "
        << StringPrintf("0x%08X.", fixup_it->second.location.value());
  }

  return success;
}

bool Decomposer::LoadDebugStreams(IDiaSession* dia_session,
                                  std::vector<OMAP>* omap_to,
                                  std::vector<OMAP>* omap_from) {
  DCHECK(dia_session != NULL);
  DCHECK(omap_to != NULL);
  DCHECK(omap_from != NULL);

  omap_to->clear();
  omap_from->clear();
  PdbFixups pdb_fixups;

  ScopedComPtr<IDiaEnumDebugStreams> debug_streams;
  if (FAILED(dia_session->getEnumDebugStreams(debug_streams.Receive()))) {
    LOG(ERROR) << "Unable to get debug streams.";
    return false;
  }

  bool loaded_fixup_stream = false;

  while (true) {
    ScopedComPtr<IDiaEnumDebugStreamData> debug_stream;
    ULONG count = 0;
    HRESULT hr = debug_streams->Next(1, debug_stream.Receive(), &count);
    if (FAILED(hr) || (hr != S_FALSE && count != 1)) {
      LOG(ERROR) << "Unable to load debug stream: " << hr;
      return false;
    } else if (hr == S_FALSE) {
      // No more records.
      break;
    }

    ScopedBstr name;
    if (FAILED(debug_stream->get_name(name.Receive())) || name == NULL) {
      LOG(ERROR) << "Unable to get debug stream name.";
      return false;
    }

    if (wcscmp(name, L"OMAPTO") == 0 &&
        !LoadDebugStream(debug_stream, omap_to)) {
      LOG(ERROR) << "Unable to load omap to stream.";
      return false;
    } else if (wcscmp(name, L"OMAPFROM") == 0 &&
        !LoadDebugStream(debug_stream, omap_from)) {
      LOG(ERROR) << "Unable to load omap from stream.";
      return false;
    } else if (wcscmp(name, L"FIXUP") == 0) {
      if (LoadDebugStream(debug_stream, &pdb_fixups)) {
        loaded_fixup_stream = true;
      } else {
        LOG(ERROR) << "Unable to load fixup stream.";
        return false;
      }
    }
  }

  if (!loaded_fixup_stream) {
    LOG(ERROR) << "PDB file does not contain a FIXUP stream. Module must be "
                  "linked with '/PROFILE' or '/DEBUGINFO:FIXUP' flag.";
    return false;
  }

  // Translate and validate fixups.
  if (!OmapAndValidateFixups(*omap_from, pdb_fixups))
    return false;

  return true;
}

bool Decomposer::OmapAndValidateFixups(const std::vector<OMAP>& omap_from,
                                       const PdbFixups& pdb_fixups) {
  bool have_omap = omap_from.size() != 0;

  // The resource section in Chrome is modified post-link by a tool that adds a
  // manifest to it. This causes all of the fixups in the resource section (and
  // anything beyond it) to be invalid. As long as the resource section is the
  // last section in the image, this is not a problem (we can safely ignore the
  // .rsrc fixups, which we know how to parse without them). However, if there
  // is a section after the resource section, things will have been shifted
  // and potentially crucial fixups will be invalid.
  RelativeAddress rsrc_start(0xffffffff), max_start;
  static const char kRsrcName[] = ".rsrc";
  size_t num_sections = image_file_.nt_headers()->FileHeader.NumberOfSections;
  for (size_t i = 0; i < num_sections; ++i) {
    const IMAGE_SECTION_HEADER* header = image_file_.section_header(i);
    RelativeAddress start(header->VirtualAddress);
    if (start > max_start)
      max_start = start;
    if (strncmp(kRsrcName,
                reinterpret_cast<const char*>(header->Name),
                IMAGE_SIZEOF_SHORT_NAME) == 0) {
      rsrc_start = start;
      break;
    }
  }

  // Ensure there are no sections after the resource section.
  if (max_start > rsrc_start) {
    LOG(ERROR) << ".rsrc section is not the last section.";
    return false;
  }

  // Ensure the fixups are all valid, and populate the fixup map.
  size_t skipped = 0;
  for (size_t i = 0; i < pdb_fixups.size(); ++i) {
    if (!pdb_fixups[i].ValidHeader()) {
      LOG(ERROR) << "Unknown fixup type: "
          << StringPrintf("0x%08X.", pdb_fixups[i].header);
      return false;
    }

    // Get the original addresses, and map them through OMAP information.
    // Normally DIA takes care of this for us, but there is no API for
    // getting DIA to give us FIXUP information, so we have to do it manually.
    RelativeAddress rva_location(pdb_fixups[i].rva_location);
    RelativeAddress rva_base(pdb_fixups[i].rva_base);
    if (have_omap) {
      rva_location = TranslateAddressViaOmap(omap_from, rva_location);
      rva_base = TranslateAddressViaOmap(omap_from, rva_base);
    }

    // If these are part of the .rsrc section, ignore them.
    if (rva_location >= rsrc_start)
      continue;

    // Ensure they live within the image, and refer to things within the
    // image.
    if (!image_file_.Contains(rva_location, kPointerSize) ||
        !image_file_.Contains(rva_base, 1)) {
      LOG(ERROR) << "Fixup refers to addresses outside of image.";
      return false;
    }

    // Add the fix up, and ensure the source address is unique.
    Fixup fixup = { PdbFixupTypeToReferenceType(pdb_fixups[i].type),
                    pdb_fixups[i].refers_to_code(),
                    pdb_fixups[i].is_data(),
                    false,
                    rva_location,
                    rva_base };
    bool added = fixup_map_.insert(std::make_pair(rva_location, fixup)).second;
    if (!added) {
      LOG(ERROR) << "Colliding fixups at RVA "
          << StringPrintf("0x%08X.", rva_location.value());
      return false;
    }
  }

  return true;
}

bool Decomposer::BuildBasicBlockGraph(DecomposedImage* decomposed_image) {
  DCHECK(image_);
  BlockGraph::AddressSpace::RangeMapConstIter block_iter = image_->begin();

  BlockGraph& basic_blocks = decomposed_image->basic_block_graph;
  BlockGraph::AddressSpace* basic_blocks_image =
      &decomposed_image->basic_block_address_space;
  DCHECK(basic_blocks_image);

  bool success = true;
  for (; block_iter != image_->end(); ++block_iter) {
    const BlockGraph::Block* block = block_iter->second;
    const BlockGraph::Block::ReferenceMap& ref_map = block->references();
    RelativeAddress block_addr;
    if (!image_->GetAddressOf(block, &block_addr)) {
      LOG(DFATAL) << "Block " << block->name() << " has no address, "
          << block->addr() << ":" << block->size();
      // Expect this to be the result of a merge?
      continue;
    }

    if (block->type() != BlockGraph::CODE_BLOCK) {
      // Don't try to break up non-code blocks into basic blocks.
      basic_blocks_image->AddBlock(block->type(),   // Block type
                                   block_addr,      // Range start (rel)
                                   block->size(),   // Range size
                                   block->name());  // Block name

    } else {
      // We have a code block, disassemble it!
      AbsoluteAddress abs_block_addr;
      if (!image_file_.Translate(block_addr, &abs_block_addr)) {
        LOG(ERROR) << "Unable to get absolute address for " << block_addr;
        return false;
      }

      // Build the set of labels that are points we want to disassemble from.
      // For now we continue to use the that point into the function block.
      // TODO(robertshield): See if we would be better served by considering all
      // inbound references we have discovered in the previous traversal
      // instead.
      BlockGraph::Block::LabelMap::const_iterator it(block->labels().begin());
      Disassembler::AddressSet labels;
      for (; it != block->labels().end(); ++it) {
        BlockGraph::Offset label = it->first;
        DCHECK(label >= 0 && static_cast<size_t>(label) <= block->size());

        // Some labels are addressed at the end of the function, but we don't
        // want to disassemble from there.
        if (static_cast<size_t>(label) != block->size())
          labels.insert(abs_block_addr + it->first);
      }

      scoped_ptr<Disassembler::InstructionCallback> on_basic_instruction(
          NewCallback(this, &Decomposer::OnBasicInstruction));

      BasicBlockDisassembler disasm(block->data(),
                                    block->data_size(),
                                    abs_block_addr,
                                    labels,
                                    block->name(),
                                    on_basic_instruction.get());
      Disassembler::WalkResult result = disasm.Walk();

      if (result == Disassembler::kWalkSuccess ||
          result == Disassembler::kWalkIncomplete) {
        BasicBlockDisassembler::BBAddressSpace basic_blocks(
            disasm.GetBasicBlockRanges());

        BasicBlockDisassembler::RangeMapConstIter iter(
            basic_blocks.begin());
        for (; iter != basic_blocks.end(); ++iter) {
          RelativeAddress rva_start;
          if (!image_file_.Translate(iter->first.start(), &rva_start)) {
            LOG(ERROR) << "Unable to get absolute address for " << block_addr;
            return false;
          }

          basic_blocks_image->AddBlock(
              iter->second.type(),   // Block type
              rva_start,             // Range start (rel)
              iter->first.size(),    // Range size
              iter->second.name());  // Block name
        }
      } else {
        LOG(ERROR) << "Failed to disassemble block at "
            << abs_block_addr.value();
        success = false;
        break;
      }
    }
  }

  return success;
}

bool Decomposer::RegisterStaticInitializerPatterns(const char* begin,
                                                   const char* end) {
  // Ensuring the patterns each have exactly one capturing group.
  REPair re_pair = std::make_pair(RE(begin), RE(end));
  if (re_pair.first.NumberOfCapturingGroups() != 1 ||
      re_pair.second.NumberOfCapturingGroups() != 1)
    return false;

  static_initializer_patterns_.push_back(re_pair);

  return true;
}

}  // namespace pe
