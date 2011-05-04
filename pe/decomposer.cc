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
#include "sawbuck/sym_util/types.h"
#include "syzygy/pe/pe_file_parser.h"

using base::win::ScopedBstr;
using base::win::ScopedComPtr;

namespace {

using core::AbsoluteAddress;
using core::BlockGraph;
using core::Disassembler;
using pe::Decomposer;

const size_t kPointerSize = sizeof(AbsoluteAddress);

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

const DWORD kDataCharacteristics =
    IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_CNT_UNINITIALIZED_DATA;

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

// Given a symbol @p symbol, this will inspect its type information
// to determine its length. If the symbol has no type information, sets @p size
// to zero. Returns true on success, false otherwise.
bool GetTypeSize(IDiaSymbol* symbol, size_t* size) {
  DCHECK(symbol != NULL);
  DCHECK(size != NULL);

  *size = 0;
  ScopedComPtr<IDiaSymbol> type;
  HRESULT hr = symbol->get_type(type.Receive());
  if (FAILED(hr)) {
    LOG(ERROR) << "Failed to get type symbol: " << hr;
    return false;
  }
  if (hr == S_FALSE)
    return true;

  ULONGLONG length = 0;
  if (FAILED(type->get_length(&length))) {
    LOG(ERROR) << "Failed to retrieve type length.";
    return false;
  }

  *size = static_cast<size_t>(length);
  return true;
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
}

bool Decomposer::Decompose(DecomposedImage* decomposed_image,
                           CoverageStatistics* stats) {
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

  // Chunk out important PE image structures, like the headers and such.
  bool success = CreatePEImageBlocksAndReferences(&decomposed_image->header);

  PEFile::RelocMap reloc_map;
  if (success)
    success = ParseRelocs(&reloc_map);

  // Chunk out blocks for each function and thunk in the image.
  if (success)
    success = CreateCodeBlocks(global);

  // Chunk out data blocks.
  if (success)
    success = CreateDataBlocks(global);

  // Create labels in code blocks. These are created first so that the
  // labels will keep the more meaningful label names. We pass in the
  // relocation entries in order to keep track of those labels that are
  // unreferenced.
  // TODO(chrisha): Should we also be using relocation destinations as
  //     labels into code blocks?
  if (success)
    success = CreateGlobalLabels(global);

  // Create absolute references for each relocation entry.
  if (success)
    success = CreateRelocationReferences(reloc_map);
  // This is no longer needed.
  reloc_map.clear();

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

  if (success)
    success = LoadOmapInformation(dia_session,
                                  &decomposed_image->omap_to,
                                  &decomposed_image->omap_from);

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

    case BlockGraph::READONLY_BLOCK:
      UpdateBlockStats(block, &stats->blocks.read_only);
      break;
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
    section->set_attribute(section->attributes() | BlockGraph::GAP_BLOCK);
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
    added->set_attribute(added->attributes() | BlockGraph::GAP_BLOCK);
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
      added->set_attribute(added->attributes() | BlockGraph::GAP_BLOCK);
      break;
    }

    if (block_end < next->first.start()) {
      BlockGraph::Block* added = FindOrCreateBlock(
          block_type, block_end, next->first.start() - block_end,
          StringPrintf("Gap Block 0x%08X", block_end).c_str());
      DCHECK(added != NULL);
      added->set_attribute(added->attributes() | BlockGraph::GAP_BLOCK);
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

bool Decomposer::AddReference(RelativeAddress src_addr,
                              BlockGraph::ReferenceType type,
                              BlockGraph::Size size,
                              RelativeAddress dst_addr,
                              const char* name) {
  IntermediateReference ref = { type,
                                size,
                                dst_addr,
                                name == NULL ? "" : name };
  bool added = references_.insert(std::make_pair(src_addr, ref)).second;
  return added;
}

void Decomposer::AddReferenceCallback(RelativeAddress src_addr,
                                      BlockGraph::ReferenceType type,
                                      BlockGraph::Size size,
                                      RelativeAddress dst_addr,
                                      const char* name) {
  AddReference(src_addr, type, size, dst_addr, name);
}

bool Decomposer::ParseRelocs(PEFile::RelocMap* reloc_map) {
  if (!image_file_.DecodeRelocs(&reloc_set_)) {
    LOG(ERROR) << "Unable to decode image relocs.";
    return false;
  }

  if (!image_file_.ReadRelocs(reloc_set_, reloc_map)) {
    LOG(ERROR) << "Unable to read image relocs.";
    return false;
  }

  // Get a set of relocation destinations. These are effectively 'references'
  // to labels, and will be used to weed out unreferenced labels.
  PEFile::RelocMap::const_iterator it = reloc_map->begin();
  for (; it != reloc_map->end(); ++it) {
    RelativeAddress rva;
    if (!image_file_.Translate(it->second, &rva)) {
      LOG(ERROR) << "Unable to translate absolute address to relative: "
          << it->second;
      return false;
    }
    reloc_refs_.insert(rva);
  }

  return true;
}

bool Decomposer::CreateRelocationReferences(const PEFile::RelocMap& reloc_map) {
  PEFile::RelocMap::const_iterator it(reloc_map.begin());
  PEFile::RelocMap::const_iterator end(reloc_map.end());
  for (; it != end; ++it) {
    RelativeAddress src(it->first);
    RelativeAddress dst;
    if (!image_file_.Translate(it->second, &dst)) {
      LOG(ERROR) << "Unable to translate relocation destination.";
      return false;
    }

    AddReference(src, BlockGraph::ABSOLUTE_REF, sizeof(dst), dst, "");
  }

  return true;
}

bool Decomposer::ProcessDataSymbols(IDiaSymbol* global,
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

    if (!ProcessDataSymbol(data, data_labels))
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

    if (!ProcessDataSymbol(public_symbol, data_labels))
      return false;
  }

  return true;
}

bool Decomposer::ProcessDataSymbol(IDiaSymbol* data, DataLabels* data_labels) {
  DWORD sym_tag = SymTagNull;
  if (!GetSymTag(data, &sym_tag))
    return false;
  DCHECK(sym_tag == SymTagData || sym_tag == SymTagPublicSymbol);

  // We can safely skip PublicSymbols for code blocks.
  if (sym_tag == SymTagPublicSymbol) {
    BOOL code = false;
    if (FAILED(data->get_code(&code))) {
      LOG(ERROR) << "Failed to retrieve code flag.";
      return false;
    }
    if (code)
      return true;
  }

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

  std::string data_name;
  if (!WideToUTF8(name, name.Length(), &data_name)) {
    LOG(ERROR) << "Failed to convert label name to UTF8.";
    return false;
  }

  // PublicSymbols contain meaningless length information so we store them
  // as labels and deal with them later.
  RelativeAddress addr(rva);
  if (sym_tag == SymTagPublicSymbol) {
    data_labels->insert(std::make_pair(addr, data_name));
    return true;
  }

  size_t length = 0;
  if (!GetTypeSize(data, &length))
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

  if (!data_space_.SubsumeInsert(DataSpace::Range(addr, length), data_name)) {
    LOG(ERROR) << "Data-space insertion failed.";
    return false;
  }

  return true;
}

bool Decomposer::ExtendDataLabels(const DataLabels& data_labels) {
  // Extend any data labels at previously unseen locations until the next known
  // end of section, data range, data label or code block.
  DataLabels::const_iterator it = data_labels.begin();
  for (; it != data_labels.end(); ++it) {
    // Skip labels that lie within data ranges we already know about.
    if (data_space_.Contains(it->first))
      continue;

    // Skip labels that lie within any blocks we already know about.
    const BlockGraph::Block* block = image_->GetBlockByAddress(it->first);
    if (block != NULL)
      continue;

    // TODO(chrisha): Does it only make sense to process labels that lie
    //     within a data section?
    const IMAGE_SECTION_HEADER* header =
        image_file_.GetSectionHeader(it->first, 1);
    // Skip labels that lie outside of known sections.
    if (header == NULL) {
      LOG(ERROR) << "Data label lies outside of known sections.";
      return false;
    }
    RelativeAddress end(header->VirtualAddress + header->Misc.VirtualSize);

    // Find the next known data label and use it to lower bound the end of this
    // label.
    DataLabels::const_iterator next_it = it;
    ++next_it;
    if (next_it != data_labels.end()) {
      if (next_it->first < end)
        end = next_it->first;
    }

    // Find the next known code block and use it to lower bound the end of this
    // label.
    // TODO(chrisha): Is this necessary? No code blocks should lie within
    //     data sections, and data labels should only lie within data sections.
    //     Maybe keep this as a sanity check and fire an error if we do find
    //     an intersecting block?
    block = image_->GetFirstIntersectingBlock(it->first, end - it->first);
    if (block != NULL && block->addr() < end)
      end = block->addr();

    // See if there's an intersection of the extended label and the data
    // space. If so, truncate the label at the next data-space range.
    DataSpace::Range range(it->first, end - it->first);
    DataSpace::RangeMapConstIter data_it =
        data_space_.FindFirstIntersection(range);
    if (data_it != data_space_.end()) {
      end = data_it->first.start();
      range = DataSpace::Range(it->first, end - it->first);
    }

    // This should never fail as we've taken care to make sure we don't
    // intersect with anything.
    bool inserted = data_space_.Insert(range, it->second);
    DCHECK(inserted) << "data_space_.Insert should never fail here.";
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

bool Decomposer::CreateDataBlocksFromDataSpace() {
  // Iterate through all data ranges.
  DataSpace::RangeMapIter data_next_it = data_space_.begin();
  DataSpace::RangeMapIter data_it = data_next_it;
  while (data_next_it != data_space_.end()) {
    data_it = data_next_it;
    ++data_next_it;

    // We do not process any data ranges that lie within any existing blocks.
    // If they lie within a code block, we keep them in the data-space to guide
    // the disassembly, otherwise we simply delete them as there's already a
    // DATA or READONLY block containing them (this happens for header
    // information).
    const BlockGraph::Block* old_block = image_->GetContainingBlock(
        data_it->first.start(), data_it->first.size());
    if (old_block != NULL) {
      if (old_block->type() != BlockGraph::CODE_BLOCK)
        data_space_.Remove(data_it);
      continue;
    }

    // Create the data block.
    BlockGraph::Block* block = CreateBlock(BlockGraph::DATA_BLOCK,
                                           data_it->first.start(),
                                           data_it->first.size(),
                                           data_it->second.c_str());
    if (block == NULL) {
      // If we get here, it's because no block exists that contains
      // us, but a block exists that intersects with us.
      LOG(ERROR) << "Unable to create data-block.";
      return false;
    }

    // Remove it from the data space, leaving behind only those data
    // ranges that lie within existing blocks.
    data_space_.Remove(data_it);
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
    const DWORD kDataCharacteristics =
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_CNT_UNINITIALIZED_DATA;
    if (header->Characteristics & kDataCharacteristics) {
      if (!CreateSectionGapBlocks(header, BlockGraph::DATA_BLOCK)) {
        LOG(ERROR) << "Unable to create gap blocks for data section "
            << header->Name;
        return false;
      }
    }
  }

  return true;
}

bool Decomposer::CreateDataBlocks(IDiaSymbol* global) {
  // Process data symbols and public symbols.
  DataLabels data_labels;
  if (!ProcessDataSymbols(global, &data_labels))
    return false;

  // Some data (that indicated by public symbols) has uncertain length. We
  // extend the length of these data blocks to the next known label/block in
  // order not to subdivide data elements.
  if (!ExtendDataLabels(data_labels))
    return false;

  // Now that we have data sets and relocation entries, we can extend some
  // data blocks. Doing this is necessary because some in-function jump tables
  // are reported with too-short lengths (only seen for hand-written assembly
  // thus far).
  if (!ExtendDataRangesUsingRelocs())
    return false;

  // Use data_space_ to create data blocks.
  if (!CreateDataBlocksFromDataSpace())
    return false;

  // Flesh out the data sections with gap blocks.
  if (!CreateDataGapBlocks())
    return false;

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

  scoped_ptr<Disassembler::InstructionCallback> on_instruction(
      NewCallback(this, &Decomposer::OnInstruction));

  // First we iterate all intermediate references and label all un-labeled
  // locations in functions we find referred.
  IntermediateReferenceMap::const_iterator ref_it(references_.begin());
  for (; ref_it != references_.end(); ++ref_it) {
    const RelativeAddress& src = ref_it->first;
    const IntermediateReference& ref = ref_it->second;
    BlockGraph::Block* src_block = image_->GetContainingBlock(src, 1);
    BlockGraph::Block* dst_block =
        image_->GetContainingBlock(ref.destination, 1);
    DCHECK(src_block != NULL);
    DCHECK(dst_block != NULL);

    if (src_block != dst_block && dst_block->type() == BlockGraph::CODE_BLOCK) {
      BlockGraph::Offset offset = ref.destination - dst_block->addr();
      if (!dst_block->HasLabel(offset)) {
        // If it had no label here, we add one.
        std::string label(base::StringPrintf("From 0x%08X",
                                             ref_it->first.value()));
        dst_block->SetLabel(offset, label.c_str());
      }
    }
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

      if (!CreateCodeReferencesForBlock(block, on_instruction.get())) {
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

bool Decomposer::CreateCodeReferencesForBlock(
    BlockGraph::Block* block,
    Disassembler::InstructionCallback *on_instruction) {
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

  Disassembler disasm(block->data(),
                      block->data_size(),
                      abs_block_addr,
                      on_instruction);

  // Use block labels as starting points for disassembly. Any labels that
  // lie within a known data block or reloc should not be added.
  // TODO(chrisha): Should we actually remove these from the Block?
  BlockGraph::Block::LabelMap::const_iterator it(block->labels().begin());
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
      disasm.Unvisited(abs_block_addr + it->first);
  }

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
    bool added = AddReference(src, BlockGraph::PC_RELATIVE_REF, size, dst, "");
    if (added) {
      // See whether the block had a label at the offset.
      BlockGraph::Offset offset = dst - block->addr();
      if (!block->HasLabel(offset)) {
        // If it had no label here, we add one.
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
    RelativeAddress dst_addr(it->second.destination);
    BlockGraph::Block* dst = image_->GetBlockByAddress(dst_addr);

    if (src == NULL || dst == NULL) {
      LOG(ERROR) << "Reference source or destination address is out of "
          << "range, src: " << src << ", dst: " << dst;
      return false;
    }

    RelativeAddress src_start;
    RelativeAddress dst_start;
    if (!image_->GetAddressOf(src, &src_start) ||
        !image_->GetAddressOf(dst, &dst_start)) {
      LOG(ERROR) << "No address for src or dst block.";
      return false;
    }

    BlockGraph::Reference ref(it->second.type,
                              it->second.size,
                              dst,
                              dst_addr - dst_start);
    src->SetReference(src_addr - src_start, ref);
  }

  return true;
}

bool Decomposer::LoadOmapInformation(IDiaSession* dia_session,
                                     std::vector<OMAP>* omap_to,
                                     std::vector<OMAP>* omap_from) {
  DCHECK(dia_session != NULL);
  DCHECK(omap_to != NULL);
  DCHECK(omap_from != NULL);

  omap_to->clear();
  omap_from->clear();

  ScopedComPtr<IDiaEnumDebugStreams> debug_streams;
  if (FAILED(dia_session->getEnumDebugStreams(debug_streams.Receive()))) {
    LOG(ERROR) << "Unable to get debug streams.";
    return false;
  }

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
        !LoadOmapStream(debug_stream, omap_to)) {
      LOG(ERROR) << "Unable to load omap to stream.";
      return false;
    } else if (wcscmp(name, L"OMAPFROM") == 0 &&
        !LoadOmapStream(debug_stream, omap_from)) {
      LOG(ERROR) << "Unable to load omap from stream.";
      return false;
    }
  }

  return true;
}

bool Decomposer::LoadOmapStream(IDiaEnumDebugStreamData* omap_stream,
                                std::vector<OMAP>* omap_list) {
  DCHECK(omap_stream != NULL);
  DCHECK(omap_list != NULL);

  LONG count = 0;
  if (FAILED(omap_stream->get_Count(&count))) {
    LOG(ERROR) << "Failed to get stream count.";
    return false;
  }

  omap_list->resize(count);

  DWORD bytes_read = 0;
  ULONG count_read = 0;
  if (FAILED(omap_stream->Next(count, count * sizeof(OMAP), &bytes_read,
                               reinterpret_cast<BYTE*>(&omap_list->at(0)),
                               &count_read))) {
    LOG(ERROR) << "Unable to read omap stream.";
    return false;
  }
  DCHECK_EQ(count * sizeof(OMAP), bytes_read);
  DCHECK_EQ(count, static_cast<LONG>(count_read));

  return true;
}

}  // namespace pe
