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
#include "syzygy/pe/metadata.h"
#include "syzygy/pe/pe_file_parser.h"

using base::win::ScopedBstr;
using base::win::ScopedComPtr;

namespace {

using core::AbsoluteAddress;
using core::BlockGraph;
using core::Disassembler;
using core::RelativeAddress;
using pe::Decomposer;
using pe::PEFile;

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
  HRESULT hr = E_FAIL;
  if (FAILED(hr = stream->get_Count(&count))) {
    LOG(ERROR) << "Failed to get stream count: " << com::LogHr(hr) << ".";
    return false;
  }

  // Get the length of the debug stream, and ensure it is the expected size.
  DWORD bytes_read = 0;
  ULONG count_read = 0;
  hr = stream->Next(count, 0, &bytes_read, NULL, &count_read);
  if (FAILED(hr)) {
    LOG(ERROR) << "Unable to get debug stream length: "
        << com::LogHr(hr) << ".";
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
    LOG(ERROR) << "Unable to read debug stream: " << com::LogHr(hr) << ".";
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

  // If we get an iterator to a reference and it has the same source address
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
    LOG(ERROR) << "Reference at " << src_addr
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
        LOG(ERROR) << "Reference at " << src_addr << " has no matching fixup.";
        return false;
      }
      if (!ValidateReference(src_addr, type, size, it))
        return false;
      // Do not create a new intermediate reference.
      return true;
    }

    case FIXUP_MUST_NOT_EXIST: {
      if (it != fixup_map->end()) {
        LOG(ERROR) << "Reference at " << src_addr
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
    LOG(ERROR) << "Error getting sym tag: " << com::LogHr(hr) << ".";
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
    LOG(ERROR) << "Failed to get type symbol: " << com::LogHr(hr) << ".";
    return false;
  }
  // This happens if the symbol has no type information.
  if (hr == S_FALSE)
    return true;

  ULONGLONG ull_length = 0;
  if (FAILED(hr = type->get_length(&ull_length))) {
    LOG(ERROR) << "Failed to retrieve type length properties: "
        << com::LogHr(hr) << ".";
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
    AbsoluteAddress block_start,
    const BlockGraph::Block* block,
    const Disassembler& disasm,
    const PEFile::RelocSet& reloc_set,
    Decomposer::DetailedCodeBlockStatistics* stats) {
  DCHECK(block != NULL);
  DCHECK(stats != NULL);

  memset(stats, 0, sizeof(*stats));

  // Count instruction bytes.
  Disassembler::VisitedSpace::RangeMapConstIter code_it =
      disasm.visited().begin();
  for (; code_it != disasm.visited().end(); ++code_it) {
    stats->code_bytes += code_it->first.size();
    ++stats->code_count;
  }

  // Iterate through all relocs that are a part of this code block.
  PEFile::RelocSet::const_iterator reloc_it =
      reloc_set.lower_bound(block->addr());
  PEFile::RelocSet::const_iterator reloc_end =
      reloc_set.lower_bound(block->addr() + block->size());
  for (; reloc_it != reloc_end; ++reloc_it) {
    // Translate the reloc location to an absolute address.
    AbsoluteAddress reloc_abs = block_start + (*reloc_it - block->addr());

    // Skip relocs that are part of an instruction.
    if (disasm.visited().Intersects(reloc_abs, kPointerSize))
      continue;

    // This reloc must be part of a lookup table, or non-disassembled code.
    // TODO(chrisha): This is known to be incorrect right now for
    //     non-disassembled code. We could use fixups to make this accurate,
    //     but our disassembly is going to be revamped in the near future.
    stats->data_bytes += kPointerSize;
  }

  size_t total = stats->code_bytes + stats->data_bytes + stats->padding_bytes;
  DCHECK_GE(block->size(), total);
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

size_t GuessAddressAlignment(RelativeAddress address) {
  // Count the trailing zeros in the original address. We only care
  // about alignment up to 16, so only have to check the first 4 bits.
  // TODO(chrisha): This can be done quite efficiently using various bit
  //     twiddling tricks, and there may very well be a library implementation
  //     of this somewhere (typically named ctz for 'count training zeros').
  size_t i = address.value();
  if ((i & ((1 << 4) - 1)) == 0)
    return (1 << 4);  // 16.

  if ((i & ((1 << 3) - 1)) == 0)
    return (1 << 3);  // 8.

  if ((i & ((1 << 2) - 1)) == 0)
    return (1 << 2);  // 4.

  if ((i & ((1 << 1) - 1)) == 0)
    return (1 << 1);  // 2.

  return 1;
}

void GuessDataBlockAlignment(BlockGraph::Block* block) {
  DCHECK(block != NULL);
  block->set_alignment(GuessAddressAlignment(block->addr()));
}

void SetBlockNameOrAddLabel(BlockGraph::Offset offset,
                            const char* name_or_label,
                            BlockGraph::Block* block) {
  // This only make sense for positions strictly within the block.
  DCHECK(block != NULL);
  DCHECK_LE(0, offset);
  DCHECK_GT(block->size(), unsigned(offset));

  // If the offset is zero, change the block name. Otherwise, add a label.
  if (offset == 0)
    block->set_name(name_or_label);
  else
    block->SetLabel(offset, name_or_label);
}

void AddLabelToCodeBlock(RelativeAddress addr,
                         const std::string& name,
                         BlockGraph::Block* block) {
  // This only makes sense for code blocks that contain the given label
  // address.
  DCHECK(block != NULL);
  DCHECK_EQ(BlockGraph::CODE_BLOCK, block->type());
  DCHECK_LE(block->addr(), addr);
  DCHECK_GT(block->addr() + block->size(), addr);

  block->SetLabel(addr - block->addr(), name.c_str());
}

// Find the table that can be cast to the given type.
template<typename T> bool FindDiaTable(IDiaSession* session,
                                       T** out_table) {
  // Get the table enumerator.
  ScopedComPtr<IDiaEnumTables> enum_tables;
  HRESULT hr = session->getEnumTables(enum_tables.Receive());
  if (FAILED(hr)) {
    LOG(ERROR) << "Failed to get DIA table enumerator: "
        << com::LogHr(hr) << ".";
    return false;
  }

  // Iterate through the tables.
  ScopedComPtr<IDiaEnumSectionContribs> section_contribs;
  while (true) {
    ScopedComPtr<IDiaTable> table;
    ULONG fetched = 0;
    hr = enum_tables->Next(1, table.Receive(), &fetched);
    if (FAILED(hr)) {
      LOG(ERROR) << "Failed to get DIA table: "
          << com::LogHr(hr) << ".";
      return false;
    }
    if (fetched == 0)
      break;

    hr = table.QueryInterface(out_table);
    if (SUCCEEDED(hr))
      return true;
  }

  return false;
}

// The MS linker pads between code blocks with int3s.
static const uint8 kInt3 = 0xCC;

// If the given run of bytes consists of a single value repeated, returns that
// value. Otherwise, returns -1.
int RepeatedValue(const uint8* data, size_t size) {
  DCHECK(data != NULL);
  const uint8* data_end = data + size;
  uint8 value = *(data++);
  for (; data < data_end; ++data) {
    if (*data != value)
      return -1;
  }
  return value;
}

const BlockGraph::BlockId kNullBlockId(-1);

// Given a block pointer, saves it to an OutArchive. Does so using the
// block id, and reserving a special block id as NULL.
bool SaveBlockPointer(const BlockGraph::Block* block,
                      core::OutArchive* out_archive) {
  if (block == NULL)
    return out_archive->Save(kNullBlockId);
  return out_archive->Save(block->id());
}

// Given a block graph and an InArchive, deserializes a block by id
// and converts it to a block pointer.
bool LoadBlockPointer(BlockGraph& block_graph,
                      BlockGraph::Block** block,
                      core::InArchive* in_archive) {
  BlockGraph::BlockId id = 0;
  if (!in_archive->Load(&id))
    return false;
  if (id == kNullBlockId) {
    *block = NULL;
    return true;
  }

  *block = block_graph.GetBlockById(id);
  if (*block == NULL) {
    LOG(ERROR) << "No block exists with given id: " << id << ".";
    return false;
  }

  return true;
}

// After deserialization of a block graph, blocks that did not own the data
// they pointed to may be left with NULL data pointers, but a non-zero
// data-size. These blocks pointed to data in a PEFile, and this function fixes
// these 'missing' data pointers.
bool SetBlockDataPointers(const PEFile& pe_file,
                          BlockGraph* block_graph) {
  DCHECK(block_graph != NULL);
  BlockGraph::BlockMap::iterator it = block_graph->blocks_mutable().begin();
  for (; it != block_graph->blocks().end(); ++it) {
    // Is this block missing a data reference?
    if (it->second.data() == NULL && it->second.data_size() > 0) {
      const uint8* data = pe_file.GetImageData(it->second.original_addr(),
                                               it->second.data_size());
      if (data == NULL) {
        LOG(ERROR) << "Unable to get Block data from PEFile.";
        return false;
      }
      it->second.set_data(data);
    }
  }

  return true;
}

void ClearAttributeRecursively(BlockGraph::BlockAttributes attribute,
                               BlockGraph::Block* block) {
  DCHECK(block != NULL);

  // Don't have these attributes? Nothing to do!
  if ((block->attributes() & attribute) != attribute)
    return;

  block->clear_attribute(attribute);

  // Run through our descendents. Each of those that have all of the
  // attributes, process recursively.
  BlockGraph::Block::ReferenceMap::const_iterator it =
      block->references().begin();
  for (; it != block->references().end(); ++it) {
    BlockGraph::Block* ref = it->second.referenced();
    if ((ref->attributes() & attribute) == attribute)
      ClearAttributeRecursively(attribute, ref);
  }
}

}  // namespace

namespace pe {

using builder::Opt;
using builder::Seq;
using builder::Star;
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
      // CRT C/C++/etc initializers.
      RegisterStaticInitializerPatterns("(__x.*)_a",
                                        "(__x.*)_z") &&
      // RTC (run-time checks) initializers (part of CRT).
      RegisterStaticInitializerPatterns("(__rtc_[it])aa",
                                        "(__rtc_[it])zz") &&
      // ATL object map initializers.
      RegisterStaticInitializerPatterns("(__pobjMapEntry)First",
                                        "(__pobjMapEntry)Last") &&
      // Thread-local storage template.
      RegisterStaticInitializerPatterns("(_tls_)start",
                                        "(_tls_)end");
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
    LOG(ERROR) << "Failed to load DIA data for image file: "
        << com::LogHr(hr) << ".";
    return false;
  }

  ScopedComPtr<IDiaSession> dia_session;
  hr = dia_source->openSession(dia_session.Receive());
  if (FAILED(hr)) {
    LOG(ERROR) << "Failed to open DIA session: "
        << com::LogHr(hr) << ".";
    return false;
  }

  hr = dia_session->put_loadAddress(
      image_file_.nt_headers()->OptionalHeader.ImageBase);
  if (FAILED(hr)) {
    LOG(ERROR) << "Failed to set the DIA load address: "
        << com::LogHr(hr) << ".";
    return false;
  }

  ScopedComPtr<IDiaSymbol> global;
  hr = dia_session->get_globalScope(global.Receive());
  if (FAILED(hr)) {
    LOG(ERROR) << "Failed to get the DIA global scope: "
        << com::LogHr(hr) << ".";
    return false;
  }

  image_ = &decomposed_image->address_space;

  // Load FIXUP information from the PDB file. We do this first so that we
  // can do accounting with references that are created later on.
  bool success = LoadDebugStreams(dia_session);

  // Create intermediate references for each fixup entry.
  if (success)
    success = CreateReferencesFromFixups();

  // Chunk out important PE image structures, like the headers and such.
  if (success)
    success = CreatePEImageBlocksAndReferences(&decomposed_image->header);

  // Parse and validate the relocation entries.
  if (success)
    success = ParseRelocs();

  // Our first round of parsing is using section contributions. This creates
  // both code and data blocks.
  if (success)
    success = CreateBlocksFromSectionContribs(dia_session);

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

  // Parse public symbols, augmenting code and data labels where possible.
  if (success)
    success = ProcessPublicSymbols(global);

  // Parse initialization bracketing symbols. This needs to happen after
  // PublicSymbols have been parsed.
  if (success)
    success = ProcessStaticInitializers();

  // We know that some data blocks need to have alignment precisely preserved.
  // For now, we very conservatively (guaranteed to be correct, but causes many
  // blocks to be aligned that don't strictly need alignment) guess alignment
  // for each block. This must be run after static initializers have been
  // parsed.
  if (success)
    success = GuessDataBlockAlignments();

  // Disassemble code blocks and create PC-relative references
  if (success)
    success = CreateCodeReferences();

  // Turn the address->address format references we've created into
  // block->block references on the blocks in the image.
  if (success)
    success = FinalizeIntermediateReferences();

  // Everything called after this points requires the references to have been
  // finalized.

  // One way of ensuring full coverage is to check that all of the fixups
  // were visited during decomposition.
  if (success)
    success = ConfirmFixupsVisited();

  // Find and label all orphaned blocks.
  if (success)
    success = FindOrphanedBlocks();

  // Now, find and label any padding blocks.
  if (success)
    success = FindPaddingBlocks();

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
    LOG(ERROR) << "Failed to get the DIA function enumerator: "
       << com::LogHr(hr) << ".";
    return false;
  }

  while (true) {
    ScopedComPtr<IDiaSymbol> function;
    ULONG fetched = 0;
    hr = dia_enum_symbols->Next(1, function.Receive(), &fetched);
    if (FAILED(hr)) {
      LOG(ERROR) << "Failed to enumerate functions: "
          << com::LogHr(hr) << ".";
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
  HRESULT hr = E_FAIL;
  if (FAILED(hr = function->get_locationType(&location_type))) {
    LOG(ERROR) << "Failed to retrieve function address type."
        << com::LogHr(hr) << ".";
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
  if (FAILED(hr = function->get_relativeVirtualAddress(&rva)) ||
      FAILED(hr = function->get_length(&length)) ||
      FAILED(hr = function->get_name(name.Receive())) ||
      FAILED(hr = function->get_noReturn(&no_return))) {
    LOG(ERROR) << "Failed to retrieve function information: "
        << com::LogHr(hr) << ".";
    return false;
  }

  std::string block_name;
  if (!WideToUTF8(name, name.Length(), &block_name)) {
    LOG(ERROR) << "Failed to convert symbol name to UTF8.";
    return false;
  }

  RelativeAddress block_addr(rva);
  BlockGraph::Block* block =
      FindOrCreateBlock(BlockGraph::CODE_BLOCK,
                        block_addr,
                        static_cast<BlockGraph::Size>(length),
                        block_name.c_str(),
                        kAllowCoveringBlock);
  if (block == NULL)
    return false;
  DCHECK(block->data() != NULL);

  // We override the name as it may have been created by section contributions
  // before hand. Offset may be non-zero, because FindOrCreateBlock may return a
  // block that is a superset of our range.
  size_t offset = block_addr - block->addr();
  if (offset == 0)
    block->set_name(block_name.c_str());

  // Annotate the block with a label, as this is an entry point to it.
  block->SetLabel(offset, block_name.c_str());

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
    LOG(ERROR) << "Failed to get the DIA label enumerator: "
        << com::LogHr(hr) << ".";
    return false;
  }

  while (true) {
    ScopedComPtr<IDiaSymbol> symbol;
    ULONG fetched = 0;
    hr = dia_enum_symbols->Next(1, symbol.Receive(), &fetched);
    if (FAILED(hr)) {
      LOG(ERROR) << "Failed to enumerate the DIA symbol: "
          << com::LogHr(hr) << ".";
      return false;
    }
    if (hr != S_OK || fetched == 0)
      break;

    DCHECK(IsSymTag(symbol, SymTagLabel));
    DWORD rva = 0;
    ScopedBstr name;
    if (FAILED(hr = symbol->get_relativeVirtualAddress(&rva)) ||
        FAILED(hr = symbol->get_name(name.Receive()))) {
      LOG(ERROR) << "Failed to retrieve function information: "
         << com::LogHr(hr) << ".";
      return false;
    }

    RelativeAddress addr;
    if (!image_->GetAddressOf(block, &addr)) {
      NOTREACHED() << "Block " << block->name() << " has no address.";
      return false;
    }

    // We ignore labels that fall outside of the code block. We sometimes
    // get labels at the end of a code block, and if the binary has any OMAP
    // information these follow the original successor block, and they can
    // end up most anywhere in the binary.
    RelativeAddress label_rva(rva);
    if (label_rva < addr || label_rva >= addr + block->size())
      return true;

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
    LOG(ERROR) << "Failed to retrieve compiland enumerator: "
        << com::LogHr(hr) << ".";
    return false;
  }

  while (true) {
    ScopedComPtr<IDiaSymbol> compiland;
    ULONG fetched = 0;
    hr = enum_compilands->Next(1, compiland.Receive(), &fetched);
    if (FAILED(hr)) {
      LOG(ERROR) << "Failed to enumerate compiland enumerator: "
         << com::LogHr(hr) << ".";
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
      LOG(ERROR) << "Failed to retrieve thunk enumerator: "
          << com::LogHr(hr) << ".";
      return false;
    }

    while (true) {
      ScopedComPtr<IDiaSymbol> thunk;
      hr = enum_thunks->Next(1, thunk.Receive(), &fetched);
      if (FAILED(hr)) {
        LOG(ERROR) << "Failed to enumerate thunk enumerator: "
           << com::LogHr(hr) << ".";
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
    LOG(ERROR) << "Failed to retrieve compiland enumerator: "
        << com::LogHr(hr) << ".";
    return false;
  }

  while (true) {
    ScopedComPtr<IDiaSymbol> compiland;
    ULONG fetched = 0;
    hr = enum_compilands->Next(1, compiland.Receive(), &fetched);
    if (FAILED(hr)) {
      LOG(ERROR) << "Failed to enumerate compiland enumerator: "
         << com::LogHr(hr) << ".";
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
      LOG(ERROR) << "Failed to retrieve label enumerator: "
          << com::LogHr(hr) << ".";
      return false;
    }

    while (true) {
      ScopedComPtr<IDiaSymbol> label;
      hr = enum_labels->Next(1, label.Receive(), &fetched);
      if (FAILED(hr)) {
        LOG(ERROR) << "Failed to enumerate label enumerator: "
           << com::LogHr(hr) << ".";
        return false;
      }
      if (hr != S_OK || fetched == 0)
        break;

      DCHECK(IsSymTag(label, SymTagLabel));

      DWORD addr = 0;
      ScopedBstr name;
      if (FAILED(hr = label->get_relativeVirtualAddress(&addr)) ||
          FAILED(hr = label->get_name(name.Receive()))) {
        LOG(ERROR) << "Failed to retrieve label address or name: "
           << com::LogHr(hr) << ".";
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

      AddLabelToCodeBlock(label_addr, label_name, block);
    }
  }

  return true;
}

bool Decomposer::CreateGapBlock(BlockGraph::BlockType block_type,
                                RelativeAddress address,
                                BlockGraph::Size size) {
  BlockGraph::Block* block = FindOrCreateBlock(block_type, address, size,
      StringPrintf("Gap Block 0x%08X", address.value()).c_str(),
      kExpectNoBlock);
  if (block == NULL) {
    LOG(ERROR) << "Unable to create gap block.";
    return false;
  }
  block->set_attribute(BlockGraph::GAP_BLOCK);

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

  // The whole section is missing. Cover it with one gap block.
  if (it == end)
    return CreateGapBlock(
        block_type, section_begin, section_end - section_begin);

  // Create the head gap block if need be.
  if (section_begin < it->first.start())
    if (!CreateGapBlock(
        block_type, section_begin, it->first.start() - section_begin))
      return false;

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
      // We're at the end of the list. Create the tail gap block.
      DCHECK_GT(section_end, block_end);
      if (!CreateGapBlock(block_type, block_end, section_end - block_end))
        return false;
      break;
    }

    // Create the interstitial gap block.
    if (block_end < next->first.start())
      if (!CreateGapBlock(
          block_type, block_end, next->first.start() - block_end))
        return false;
  }

  return true;
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
      LOG(ERROR) << "Unable to read image data for fixup with source at "
          << src_addr;
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
    std::string label(StringPrintf("From 0x%08X (FIXUP)", src_addr.value()));
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

bool Decomposer::CreateBlocksFromSectionContribs(IDiaSession* session) {
  ScopedComPtr<IDiaEnumSectionContribs> section_contribs;
  if (!FindDiaTable(session, section_contribs.Receive()))
    return false;

  size_t rsrc_id = image_file_.GetSectionIndex(".rsrc");

  while (true) {
    ScopedComPtr<IDiaSectionContrib> section_contrib;
    ULONG fetched = 0;
    HRESULT hr = section_contribs->Next(1, section_contrib.Receive(), &fetched);
    if (FAILED(hr)) {
      LOG(ERROR) << "Failed to get DIA section contribution: "
         << com::LogHr(hr) << ".";
      return false;
    }
    if (fetched == 0)
      break;

    hr = E_FAIL;
    DWORD rva = 0;
    DWORD length = 0;
    DWORD section_id = 0;
    BOOL code = FALSE;
    ScopedComPtr<IDiaSymbol> compiland;
    ScopedBstr bstr_name;
    if (FAILED(hr = section_contrib->get_relativeVirtualAddress(&rva)) ||
        FAILED(hr = section_contrib->get_length(&length)) ||
        FAILED(hr = section_contrib->get_addressSection(&section_id)) ||
        FAILED(hr = section_contrib->get_code(&code)) ||
        FAILED(hr = section_contrib->get_compiland(compiland.Receive())) ||
        FAILED(hr = compiland->get_name(bstr_name.Receive()))) {
      LOG(ERROR) << "Failed to get section contribution properties: "
          << com::LogHr(hr) << ".";
      return false;
    }

    // DIA numbers sections from 1 to n, while we do 0 to n - 1.
    DCHECK_LT(0u, section_id);
    --section_id;

    // We don't parse the resource section, as it is parsed by the PEFileParser.
    if (section_id == rsrc_id)
      continue;

    std::string name;
    if (!WideToUTF8(bstr_name, bstr_name.Length(), &name)) {
      LOG(ERROR) << "Failed to convert compiland name to UTF8.";
      return false;
    }

    // Create the block.
    BlockGraph::BlockType block_type =
        code ? BlockGraph::CODE_BLOCK : BlockGraph::DATA_BLOCK;
    BlockGraph::Block* block = FindOrCreateBlock(block_type,
                                                 RelativeAddress(rva),
                                                 length,
                                                 name.c_str(),
                                                 kExpectNoBlock);
    if (block == NULL) {
      LOG(ERROR) << "Unable to create block.";
      return false;
    }
    block->set_attribute(BlockGraph::SECTION_CONTRIB);
  }

  return true;
}

void Decomposer::OnDataSymbol(const DiaBrowser& dia_browser,
                              const DiaBrowser::SymTagVector& sym_tags,
                              const DiaBrowser::SymbolPtrVector& symbols,
                              DiaBrowser::BrowserDirective* directive) {
  DCHECK_LT(0u, sym_tags.size());
  DCHECK_EQ(sym_tags.size(), symbols.size());
  DCHECK_EQ(SymTagData, sym_tags.back());
  DCHECK(directive != NULL);
  DCHECK_EQ(DiaBrowser::kBrowserContinue, *directive);

  const DiaBrowser::SymbolPtr& data(symbols.back());

  HRESULT hr = E_FAIL;
  DWORD location_type = LocIsNull;
  DWORD rva = 0;
  ScopedBstr name_bstr;
  if (FAILED(hr = data->get_locationType(&location_type)) ||
      FAILED(hr = data->get_relativeVirtualAddress(&rva)) ||
      FAILED(hr = data->get_name(name_bstr.Receive()))) {
    LOG(ERROR) << "Failed to get data properties: " << com::LogHr(hr) << ".";
    *directive = DiaBrowser::kBrowserAbort;
    return;
  }

  // We only parse data symbols with static storage.
  if (location_type != LocIsStatic)
    return;

  // Symbols with an address of zero are essentially invalid. They appear to
  // have been optimized away by the compiler, but they are still reported.
  if (rva == 0)
    return;

  // TODO(chrisha): We eventually want to get alignment info from the type
  //     information. This is strictly a lower bound, however, as certain
  //     data may be used in instructions that impose stricter alignment
  //     requirements.
  size_t length = 0;
  if (!GetTypeInfo(data, &length)) {
    *directive = DiaBrowser::kBrowserAbort;
    return;
  }
  // Zero-length data symbols act as 'forward declares' in some sense. They
  // are always followed by a non-zero length data symbol with the same name
  // and location.
  if (length == 0)
    return;

  RelativeAddress addr(rva);
  std::string name;
  if (!WideToUTF8(name_bstr, name_bstr.Length(), &name)) {
    LOG(ERROR) << "Failed to convert data symbol name to UTF8.";
    *directive = DiaBrowser::kBrowserAbort;
    return;
  }

  // If there is an existing block, and we are completely contained within it,
  // then simply add ourselves as a label.
  BlockGraph::Block* block =
      image_->GetFirstIntersectingBlock(addr, length == 0 ? 1 : length);
  if (block != NULL) {
    if (block->type() == BlockGraph::CODE_BLOCK) {
      // The NativeClient bits of chrome.dll consists of hand-written assembly
      // that is compiled using a custom non-Microsoft toolchain. Unfortunately
      // for us this toolchain emits 1-byte data symbols instead of code labels.
      static const char kNaClPrefix[] = "NaCl";
      if (length == 1 &&
          name.compare(0, arraysize(kNaClPrefix) - 1, kNaClPrefix) == 0) {
        AddLabelToCodeBlock(addr, name, block);
        return;
      }

      // TODO(chrisha): Data in code blocks only occurs with hand-crafted
      //     assembly, such as memmove, memcpy, etc. We have no data-in-code
      //     book-keeping mechanisms for now, so we'll deal with this when we
      //     get around to doing that. (These data are always lookup tables, so
      //     we avoid disassembly collisions simply by checking relocs for now.)
    }

    // Check for symbol conflicts.
    if (addr < block->addr() || addr + length > block->addr() + block->size()) {
      LOG(ERROR) << "Data symbol " << name
          << " in conflict with existing block " << block->name() << ".";
      *directive = DiaBrowser::kBrowserAbort;
      return;
    }

    BlockGraph::Offset offset = addr - block->addr();
    SetBlockNameOrAddLabel(offset, name.c_str(), block);

    return;
  }

  // If we get here, there is no conflicting block and we can create a new one.
  block = CreateBlock(BlockGraph::DATA_BLOCK,
                      addr,
                      length,
                      name.c_str());
  if (block == NULL) {
    LOG(ERROR) << "Unable to create data block.";
    *directive = DiaBrowser::kBrowserAbort;
    return;
  }
}

void Decomposer::OnPublicSymbol(const DiaBrowser& dia_browser,
                                const DiaBrowser::SymTagVector& sym_tags,
                                const DiaBrowser::SymbolPtrVector& symbols,
                                DiaBrowser::BrowserDirective* directive) {
  DCHECK_LT(0u, sym_tags.size());
  DCHECK_EQ(sym_tags.size(), symbols.size());
  DCHECK_EQ(SymTagPublicSymbol, sym_tags.back());
  DCHECK(directive != NULL);
  DCHECK_EQ(DiaBrowser::kBrowserContinue, *directive);

  const DiaBrowser::SymbolPtr& symbol(symbols.back());

  HRESULT hr = E_FAIL;
  DWORD rva = 0;
  ScopedBstr name_bstr;
  if (FAILED(hr = symbol->get_relativeVirtualAddress(&rva)) ||
      FAILED(hr = symbol->get_name(name_bstr.Receive()))) {
    LOG(ERROR) << "Failed to get public symbol properties: "
        << com::LogHr(hr) << ".";
    *directive = DiaBrowser::kBrowserAbort;
    return;
  }

  RelativeAddress addr(rva);
  BlockGraph::Block* block = image_->GetContainingBlock(addr, 1);
  // PublicSymbols are parsed after the sections have been filled out with
  // gap blocks, so they should always land in a code or data block.
  DCHECK(block != NULL);
  DCHECK(block->type() == BlockGraph::CODE_BLOCK ||
         block->type() == BlockGraph::DATA_BLOCK);

  std::string name;
  if (!WideToUTF8(name_bstr, name_bstr.Length(), &name)) {
    LOG(ERROR) << "Failed to convert symbol name to UTF8.";
    *directive = DiaBrowser::kBrowserAbort;
    return;
  }
  // Public symbol names are mangled. Remove leading '_' as per
  // http://msdn.microsoft.com/en-us/library/00kh39zz(v=vs.80).aspx
  if (name[0] == '_')
    name = name.substr(1);

  // Set the block name or add a label. For code blocks these are entry points,
  // while for data blocks these are simply to aid debugging.
  BlockGraph::Offset offset = addr - block->addr();
  SetBlockNameOrAddLabel(offset, name.c_str(), block);
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

bool Decomposer::ProcessDataSymbols(IDiaSymbol* root) {
  scoped_ptr<DiaBrowser::MatchCallback> on_data_symbol(
      NewCallback(this, &Decomposer::OnDataSymbol));

  DiaBrowser dia_browser;
  dia_browser.AddPattern(Seq(Opt(SymTagCompiland), SymTagData),
                         on_data_symbol.get());
  dia_browser.AddPattern(Seq(SymTagCompiland, SymTagFunction,
                             Star(SymTagBlock), SymTagData),
                         on_data_symbol.get());

  return dia_browser.Browse(root);
}

bool Decomposer::ProcessPublicSymbols(IDiaSymbol* root) {
  scoped_ptr<DiaBrowser::MatchCallback> on_public_symbol(
      NewCallback(this, &Decomposer::OnPublicSymbol));

  DiaBrowser dia_browser;
  dia_browser.AddPattern(SymTagPublicSymbol,
                         on_public_symbol.get());

  return dia_browser.Browse(root);
}

bool Decomposer::CreateDataBlocks(IDiaSymbol* global) {
  // Create data blocks using data symbols.
  if (!ProcessDataSymbols(global))
    return false;

  // Flesh out the data sections with gap blocks.
  if (!CreateDataGapBlocks())
    return false;

  return true;
}

bool Decomposer::GuessDataBlockAlignments() {
  size_t num_sections = image_file_.nt_headers()->FileHeader.NumberOfSections;
  // Iterate through all the image sections.
  for (size_t i = 0; i < num_sections; ++i) {
    const IMAGE_SECTION_HEADER* header = image_file_.section_header(i);
    DCHECK(header != NULL);

    // Only iterate through data sections.
    if (GetSectionType(header) != kSectionData)
      continue;

    RelativeAddress section_begin(header->VirtualAddress);
    size_t section_length = header->Misc.VirtualSize;

    // Get the range of blocks in this section.
    BlockGraph::AddressSpace::RangeMapIterPair it_pair =
        image_->GetIntersectingBlocks(section_begin, section_length);

    // Iterate through the blocks in the section, setting their alignment.
    BlockGraph::AddressSpace::RangeMapIter it = it_pair.first;
    for (; it != it_pair.second; ++it) {
      BlockGraph::Block* block = it->second;
      GuessDataBlockAlignment(block);
    }
  }

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
    DCHECK_LE(0, label);
    DCHECK_GT(block->size(), static_cast<size_t>(label));

    // We sometimes receive labels for lookup tables. Thus labels that point
    // directly to a reloc should not be used as a starting point for
    // disassembly.
    RelativeAddress addr(block->addr() + static_cast<size_t>(label));
    if (reloc_set_.find(addr) == reloc_set_.end())
      labels.insert(abs_block_addr + it->first);
  }

  Disassembler disasm(block->data(),
                      block->data_size(),
                      abs_block_addr,
                      labels,
                      on_instruction.get());
  Disassembler::WalkResult result = disasm.Walk();
  CalcDetailedCodeBlockStats(
      abs_block_addr, block, disasm, reloc_set_,
      &code_block_stats_[block->id()]);

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
    DCHECK_LT(id, image_file_.nt_headers()->FileHeader.NumberOfSections);
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

BlockGraph::Block* Decomposer::FindOrCreateBlock(
    BlockGraph::BlockType type,
    RelativeAddress addr,
    BlockGraph::Size size,
    const char* name,
    FindOrCreateBlockDirective directive) {
  BlockGraph::Block* block = image_->GetBlockByAddress(addr);
  if (block != NULL) {
    // Always allow collisions where the new block is a proper subset of
    // an existing PE parsed block. The PE parser often knows more than we do
    // about blocks that need to stick together.
    if (block->attributes() & BlockGraph::PE_PARSED)
      directive = kAllowCoveringBlock;

    bool collision = false;
    switch (directive) {
      case kExpectNoBlock: {
        collision = true;
        break;
      }
      case kAllowIdenticalBlock: {
        collision = (block->addr() != addr || block->size() != size);
        break;
      }
      default: {
        DCHECK(directive == kAllowCoveringBlock);
        collision = block->addr() > addr ||
            (block->addr() + block->size()) < addr + size;
        break;
      }
    }

    if (collision) {
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

  // If this instruction terminates at a data boundary (ie: the *next*
  // instruction will be data or a reloc), indicate that the path should be
  // terminated.
  RelativeAddress after_instr_rel = instr_rel + instruction.size;
  if (reloc_set_.find(after_instr_rel) != reloc_set_.end())
    *directive = Disassembler::kDirectiveTerminatePath;
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

  // If this instruction terminates at a data boundary (ie: the *next*
  // instruction will be data or a reloc), indicate that the path should be
  // terminated.
  RelativeAddress after_instr_rel = instr_rel + instruction.size;
  if (reloc_set_.find(after_instr_rel) != reloc_set_.end()) {
    *directive = Disassembler::kDirectiveTerminatePath;

    // We can be certain that a new lookup table is starting at this address.
    // TODO(chrisha): We can use this to drive the labelling of data blocks
    //     within code sections.
  }

  // TODO(chrisha): Certain instructions require aligned data (ie: MMX/SSE
  //     instructions). We need to follow the data that these instructions
  //     refer to, and set their alignment appropriately. For now, alignment
  //     is simply preserved from the original image.

  int fc = META_GET_FC(instruction.meta);
  // For all branches, calls and conditional branches to PC-relative
  // addresses, record a PC-relative reference.
  if ((fc == FC_UNC_BRANCH || fc == FC_CALL || fc == FC_CND_BRANCH) &&
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
    DCHECK_EQ(BlockGraph::CODE_BLOCK, block->type());

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

    // Add the reference. If it's new, make sure to try and add a label
    // and reschedule the block for disassembly again.
    std::string label(StringPrintf("From %s +0x%x",
                                   block->name(),
                                   instr_rel - block->addr()));

    // For short references, we should not see a fixup.
    ValidateOrAddReferenceMode mode = FIXUP_MUST_NOT_EXIST;
    if (size == kPointerSize) {
      // Long PC_RELATIVE reference within a single block? FIXUPs aren't
      // strictly necessary.
      if (block->Contains(src, kPointerSize))
        mode = FIXUP_MAY_EXIST;
      else
        // But if they're between blocks (section contributions), we expect to
        // find them.
        mode = FIXUP_MUST_EXIST;
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
  if (fc != FC_RET && fc != FC_UNC_BRANCH && fc != FC_INT) {
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
    LOG(ERROR) << "Unexpected unseen fixup at " << fixup_it->second.location;
  }

  return success;
}

bool Decomposer::FindOrphanedBlocks() {
  DCHECK(image_ != NULL);
  DCHECK(image_->graph() != NULL);

  // We first color all blocks as orphans.
  BlockGraph::BlockMap::iterator block_it =
      image_->graph()->blocks_mutable().begin();
  BlockGraph::BlockMap::iterator block_it_end =
      image_->graph()->blocks_mutable().end();
  for (; block_it != block_it_end; ++block_it) {
    BlockGraph::Block& block = block_it->second;
    block.set_attribute(BlockGraph::ORPHANED_BLOCK);
  }

  // Now we remove orphan status from all PE_PARSED-reachable blocks.
  block_it = image_->graph()->blocks_mutable().begin();
  for (; block_it != block_it_end; ++block_it) {
    BlockGraph::Block& block = block_it->second;

    // Any block that is PE parsed is used as a root from which to remove
    // orphan status.
    if ((block.attributes() & BlockGraph::PE_PARSED) != 0)
      ClearAttributeRecursively(BlockGraph::ORPHANED_BLOCK, &block);
  }

  return true;
}

bool Decomposer::FindPaddingBlocks() {
  DCHECK(image_ != NULL);
  DCHECK(image_->graph() != NULL);

  BlockGraph::BlockMap::iterator block_it =
      image_->graph()->blocks_mutable().begin();
  for (; block_it != image_->graph()->blocks_mutable().end(); ++block_it) {
    BlockGraph::Block& block = block_it->second;

    // Padding blocks must not have any symbol information: no labels,
    // no references, no referrers, and they must be a gap block. As a sanity
    // check, they must also be orphans.
    if (block.labels().size() != 0 ||
        block.references().size() != 0 ||
        block.referrers().size() != 0 ||
        (block.attributes() & BlockGraph::GAP_BLOCK) == 0 ||
        (block.attributes() & BlockGraph::ORPHANED_BLOCK) == 0)
      continue;

    switch (block.type()) {
      // Code blocks should be fully defined and consist of only int3s.
      case BlockGraph::CODE_BLOCK: {
        if (block.data_size() != block.size() ||
            RepeatedValue(block.data(), block.data_size()) != kInt3)
          continue;
        break;
      }

      // Data blocks should be uninitialized or have fully defined data
      // consisting only of zeros.
      default: {
        DCHECK_EQ(BlockGraph::DATA_BLOCK, block.type());
        if (block.data_size() == 0)  // Uninitialized data blocks are padding.
          break;
        if (block.data_size() != block.size() ||
            RepeatedValue(block.data(), block.data_size()) != 0)
          continue;
      }
    }

    // If we fall through to this point, then the block is a padding block.
    block.set_attribute(BlockGraph::PADDING_BLOCK);
  }

  return true;
}

bool Decomposer::LoadDebugStreams(IDiaSession* dia_session) {
  DCHECK(dia_session != NULL);

  PdbFixups pdb_fixups;
  HRESULT hr = E_FAIL;
  ScopedComPtr<IDiaEnumDebugStreams> debug_streams;
  if (FAILED(hr = dia_session->getEnumDebugStreams(debug_streams.Receive()))) {
    LOG(ERROR) << "Unable to get debug streams: " << com::LogHr(hr) << ".";
    return false;
  }

  bool loaded_fixup_stream = false;
  std::vector<OMAP> omap_from;
  while (true) {
    ScopedComPtr<IDiaEnumDebugStreamData> debug_stream;
    ULONG count = 0;
    HRESULT hr = debug_streams->Next(1, debug_stream.Receive(), &count);
    if (FAILED(hr) || (hr != S_FALSE && count != 1)) {
      LOG(ERROR) << "Unable to load debug stream: "
          << com::LogHr(hr) << ".";
      return false;
    } else if (hr == S_FALSE) {
      // No more records.
      break;
    }

    ScopedBstr name;
    if (FAILED(hr = debug_stream->get_name(name.Receive()))) {
      LOG(ERROR) << "Unable to get debug stream name: "
          << com::LogHr(hr) << ".";
      return false;
    }

    if (wcscmp(name, L"OMAPFROM") == 0 &&
        !LoadDebugStream(debug_stream, &omap_from)) {
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
  if (!OmapAndValidateFixups(omap_from, pdb_fixups))
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
      LOG(ERROR) << "Unknown fixup header: "
          << StringPrintf("0x%08X.", pdb_fixups[i].header);
      return false;
    }

    // For now, we skip any offset fixups. We've only seen this in the context
    // of TLS data access, and we don't mess with TLS structures.
    if (pdb_fixups[i].is_offset())
      continue;

    // All fixups we handle should be full size pointers.
    DCHECK_EQ(kPointerSize, pdb_fixups[i].size());

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
      LOG(ERROR) << "Colliding fixups at " << rva_location;
      return false;
    }
  }

  return true;
}

bool Decomposer::BuildBasicBlockGraph(DecomposedImage* decomposed_image) {
  DCHECK(image_ != NULL);
  BlockGraph::AddressSpace::RangeMapConstIter block_iter = image_->begin();

  BlockGraph& basic_blocks = decomposed_image->basic_block_graph;
  BlockGraph::AddressSpace* basic_blocks_image =
      &decomposed_image->basic_block_address_space;
  DCHECK(basic_blocks_image != NULL);

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
        DCHECK_LE(0, label);
        DCHECK_GT(block->size(), static_cast<size_t>(label));

        // We sometimes receive labels for lookup tables. Thus labels that point
        // directly to a reloc should not be used as a starting point for
        // disassembly.
        RelativeAddress addr(block->addr() + static_cast<size_t>(label));
        if (reloc_set_.find(addr) == reloc_set_.end())
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

bool SaveDecomposition(const PEFile& pe_file,
                       const Decomposer::DecomposedImage& image,
                       core::OutArchive* out_archive) {
  // Get the metadata for this module and the toolchain. This will
  // allow us to validate input files in other pieces of the toolchain.
  Metadata metadata;
  PEFile::Signature pe_file_signature;
  pe_file.GetSignature(&pe_file_signature);
  if (!metadata.Init(pe_file_signature) || !out_archive->Save(metadata))
    return false;

  // Now write out the DecomposedImage.
  if (!out_archive->Save(image.image) ||
      !out_archive->Save(image.address_space) ||
      !out_archive->Save(image.basic_block_graph) ||
      !out_archive->Save(image.basic_block_address_space)) {
    return false;
  }

  // Now serialize the PEHeader block IDs.
  if (!SaveBlockPointer(image.header.dos_header, out_archive) ||
      !SaveBlockPointer(image.header.nt_headers, out_archive)) {
    return false;
  }

  for (size_t i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i) {
    if (!SaveBlockPointer(image.header.data_directory[i],
                          out_archive))
      return false;
  }

  return true;
}

bool LoadDecomposition(PEFile* pe_file,
                       Decomposer::DecomposedImage* image,
                       core::InArchive* in_archive) {
  DCHECK(pe_file != NULL);
  DCHECK(image != NULL);
  DCHECK(in_archive != NULL);

  // Load the metadata and initialize the PE file decomposition.
  Metadata metadata;
  if (!in_archive->Load(&metadata) ||
      !pe_file->Init(FilePath(metadata.module_signature().path))) {
    return false;
  }

  // Validate the signature of the PE file on disk to make sure its
  // still the same as when the decomposition was serialized.
  PEFile::Signature pe_signature;
  pe_file->GetSignature(&pe_signature);
  if (!metadata.IsConsistent(pe_signature))
    return false;

  // Now deserialize the actual decomposed image.
  if (!in_archive->Load(&image->image) ||
      !in_archive->Load(&image->address_space) ||
      !in_archive->Load(&image->basic_block_graph) ||
      !in_archive->Load(&image->basic_block_address_space)) {
    return false;
  }

  // This sets any missing data pointers in the block graph. These
  // are pointers to data that was not owned by the block graph, but
  // rather by the PEFile.
  if (!SetBlockDataPointers(*pe_file, &image->image) ||
      !SetBlockDataPointers(*pe_file, &image->basic_block_graph)) {
    return false;
  }

  // Populate the PEFile header pointers.
  if (!LoadBlockPointer(image->image, &image->header.dos_header, in_archive) ||
      !LoadBlockPointer(image->image, &image->header.nt_headers, in_archive)) {
    return false;
  }

  for (size_t i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i) {
    if (!LoadBlockPointer(image->image,
                          &image->header.data_directory[i],
                          in_archive)) {
      return false;
    }
  }

  return true;
}

}  // namespace pe
