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

#include "syzygy/pe/new_decomposer.h"

#include "base/bind.h"
#include "base/stringprintf.h"
#include "base/utf_string_conversions.h"
#include "base/win/scoped_bstr.h"
#include "base/win/scoped_comptr.h"
#include "syzygy/core/zstream.h"
#include "syzygy/pdb/omap.h"
#include "syzygy/pdb/pdb_byte_stream.h"
#include "syzygy/pdb/pdb_constants.h"
#include "syzygy/pdb/pdb_file.h"
#include "syzygy/pdb/pdb_reader.h"
#include "syzygy/pdb/pdb_util.h"
#include "syzygy/pe/dia_util.h"
#include "syzygy/pe/find.h"
#include "syzygy/pe/pe_file_parser.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/serialization.h"

namespace pe {

// An intermediate reference representation used while parsing PE blocks.
// This is necessary because at that point we haven't yet chunked the whole
// image into blocks thus some references cannot be resolved.
struct NewDecomposer::IntermediateReference {
  RelativeAddress src_addr;
  BlockGraph::ReferenceType type;
  BlockGraph::Size size;
  RelativeAddress dst_addr;
};

namespace {

using base::win::ScopedBstr;
using base::win::ScopedComPtr;
using block_graph::BlockGraph;
using core::AbsoluteAddress;
using core::RelativeAddress;

typedef BlockGraph::Block Block;
typedef BlockGraph::BlockType BlockType;
typedef BlockGraph::Offset Offset;
typedef BlockGraph::Reference Reference;
typedef BlockGraph::ReferenceType ReferenceType;
typedef core::AddressRange<RelativeAddress, size_t> RelativeRange;
typedef NewDecomposer::IntermediateReference IntermediateReference;
typedef NewDecomposer::IntermediateReferences IntermediateReferences;
typedef std::vector<OMAP> OMAPs;
typedef std::vector<pdb::PdbFixup> PdbFixups;

bool InitializeDia(const PEFile& image_file,
                   const FilePath& pdb_path,
                   IDiaDataSource** dia_source,
                   IDiaSession** dia_session,
                   IDiaSymbol** global) {
  DCHECK(*dia_source == NULL);
  DCHECK(*dia_session == NULL);
  DCHECK(*global == NULL);

  if (!CreateDiaSource(dia_source))
    return false;
  DCHECK(*dia_source != NULL);

  // We create the session using the PDB file directly, as we've already
  // validated that it matches the module.
  if (!CreateDiaSession(pdb_path, *dia_source, dia_session))
    return false;
  DCHECK(*dia_session != NULL);

  HRESULT hr = (*dia_session)->get_globalScope(global);
  if (hr != S_OK) {
    LOG(ERROR) << "Failed to get the DIA global scope: "
               << com::LogHr(hr) << ".";
    return false;
  }

  return true;
}

// Gets the symbol tab associated with the given symbol.
bool GetSymTag(IDiaSymbol* symbol, enum SymTagEnum* sym_tag) {
  DCHECK(sym_tag != NULL);
  DWORD dword = SymTagNull;
  *sym_tag = SymTagNull;
  HRESULT hr = symbol->get_symTag(&dword);
  if (hr != S_OK) {
    LOG(ERROR) << "Error getting sym tag: " << com::LogHr(hr) << ".";
    return false;
  }
  *sym_tag = static_cast<enum SymTagEnum>(dword);
  return true;
}

// Checks to see if the given symbol is of the expected type.
bool IsSymTag(IDiaSymbol* symbol, enum SymTagEnum expected_sym_tag) {
  enum SymTagEnum sym_tag = SymTagNull;
  if (!GetSymTag(symbol, &sym_tag))
    return false;

  return sym_tag == expected_sym_tag;
}

enum SectionType {
  kSectionCode,
  kSectionData,
  kSectionUnknown
};

// Determines the type of a section based on its attributes. This is used to
// tag blocks with an appropriate type.
SectionType GetSectionType(const IMAGE_SECTION_HEADER* header) {
  DCHECK(header != NULL);
  if ((header->Characteristics & IMAGE_SCN_CNT_CODE) != 0)
    return kSectionCode;
  if ((header->Characteristics & kReadOnlyDataCharacteristics) != 0)
    return kSectionData;
  return kSectionUnknown;
}

// Given a compiland, returns its compiland details.
bool GetCompilandDetailsForCompiland(IDiaSymbol* compiland,
                                     IDiaSymbol** compiland_details) {
  DCHECK(compiland != NULL);
  DCHECK(compiland_details != NULL);
  DCHECK(IsSymTag(compiland, SymTagCompiland));
  DCHECK(*compiland_details == NULL);

  // Get the enumeration of compiland details.
  ScopedComPtr<IDiaEnumSymbols> enum_symbols;
  HRESULT hr = compiland->findChildren(SymTagCompilandDetails, NULL, 0,
                                       enum_symbols.Receive());
  DCHECK_EQ(S_OK, hr);

  // We expect there to be compiland details. For compilands built by
  // non-standard toolchains, there usually aren't any.
  LONG count = 0;
  hr = enum_symbols->get_Count(&count);
  DCHECK_EQ(S_OK, hr);
  if (count == 0) {
    // We don't log here because we see this quite often.
    return false;
  }

  // We do sometimes encounter more than one compiland detail. In fact, for
  // import and export tables we get one compiland detail per table entry.
  // They are all marked as having been generated by the linker, so using the
  // first one is sufficient.

  // Get the compiland details.
  ULONG fetched = 0;
  hr = enum_symbols->Next(1, compiland_details, &fetched);
  DCHECK_EQ(S_OK, hr);
  DCHECK_EQ(1u, fetched);

  return true;
}

// Stores information regarding known compilers.
struct KnownCompilerInfo {
  wchar_t* compiler_name;
  bool supported;
};

// A list of known compilers, and their status as being supported or not.
KnownCompilerInfo kKnownCompilerInfos[] = {
  { L"Microsoft (R) Macro Assembler", false },
  { L"Microsoft (R) Optimizing Compiler", true },
  { L"Microsoft (R) LINK", false }
};

// Given a compiland, determines whether the compiler used is one of those that
// we whitelist.
bool IsBuiltBySupportedCompiler(IDiaSymbol* compiland) {
  DCHECK(compiland != NULL);
  DCHECK(IsSymTag(compiland, SymTagCompiland));

  ScopedComPtr<IDiaSymbol> compiland_details;
  if (!GetCompilandDetailsForCompiland(compiland,
                                       compiland_details.Receive())) {
    // If the compiland has no compiland details we assume the compiler is not
    // supported.
    ScopedBstr compiland_name;
    if (compiland->get_name(compiland_name.Receive()) == S_OK) {
      VLOG(1) << "Compiland has no compiland details: "
              << com::ToString(compiland_name);
    }
    return false;
  }
  DCHECK(compiland_details.get() != NULL);

  // Get the compiler name.
  ScopedBstr compiler_name;
  HRESULT hr = compiland_details->get_compilerName(compiler_name.Receive());
  DCHECK_EQ(S_OK, hr);

  // Check the compiler name against the list of known compilers.
  for (size_t i = 0; i < arraysize(kKnownCompilerInfos); ++i) {
    if (::wcscmp(kKnownCompilerInfos[i].compiler_name, compiler_name) == 0) {
      return kKnownCompilerInfos[i].supported;
    }
  }

  // Anything we don't explicitly know about is not supported.
  VLOG(1) << "Encountered unknown compiler: " << compiler_name;
  return false;
}

// Adds an intermediate reference to the provided vector. The vector is
// specified as the first parameter (in slight violation of our coding
// standards) because this function is intended to be used by Bind.
bool AddIntermediateReference(IntermediateReferences* references,
                              RelativeAddress src_addr,
                              ReferenceType type,
                              BlockGraph::Size size,
                              RelativeAddress dst_addr) {
  DCHECK(references != NULL);
  IntermediateReference ref = { src_addr, type, size, dst_addr };
  references->push_back(ref);
  return true;
}

// Create a reference as specified. Ignores existing references if they are of
// the exact same type.
bool CreateReference(RelativeAddress src_addr,
                     BlockGraph::Size ref_size,
                     ReferenceType ref_type,
                     RelativeAddress base_addr,
                     RelativeAddress dst_addr,
                     BlockGraph::AddressSpace* image) {
  DCHECK(image != NULL);

  // Get the source block and offset, and ensure that the reference fits
  // within it.
  Block* src_block = image->GetBlockByAddress(src_addr);
  if (src_block == NULL) {
    LOG(ERROR) << "Unable to find block for reference originating at "
               << src_addr << ".";
    return false;
  }
  RelativeAddress src_block_addr;
  CHECK(image->GetAddressOf(src_block, &src_block_addr));
  Offset src_block_offset = src_addr - src_block_addr;
  if (src_block_offset + ref_size > src_block->size()) {
    LOG(ERROR) << "Reference originating at " << src_addr
               << " extends beyond block \"" << src_block->name() << "\".";
    return false;
  }

  // Get the destination block and offset.
  Block* dst_block = image->GetBlockByAddress(base_addr);
  if (dst_block == NULL) {
    LOG(ERROR) << "Unable to find block for reference pointing at "
                << base_addr << ".";
    return false;
  }
  RelativeAddress dst_block_addr;
  CHECK(image->GetAddressOf(dst_block, &dst_block_addr));
  Offset base = base_addr - dst_block_addr;
  Offset offset = dst_addr - dst_block_addr;

  Reference ref(ref_type, ref_size, dst_block, offset, base);

  // Check if a reference already exists at this offset.
  Block::ReferenceMap::const_iterator ref_it =
      src_block->references().find(src_block_offset);
  if (ref_it != src_block->references().end()) {
    // If an identical reference already exists then we're done.
    if (ref == ref_it->second)
      return true;
    LOG(ERROR) << "Block \"" << src_block->name() << "\" has a conflicting "
                << "reference at offset " << src_block_offset << ".";
    return false;
  }

  CHECK(src_block->SetReference(src_block_offset, ref));

  return true;
}

// Loads FIXUP and OMAP_FROM debug streams.
bool LoadDebugStreams(IDiaSession* dia_session,
                      PdbFixups* pdb_fixups,
                      OMAPs* omap_from) {
  DCHECK(dia_session != NULL);
  DCHECK(pdb_fixups != NULL);
  DCHECK(omap_from != NULL);

  // Load the fixups. These must exist.
  SearchResult search_result = FindAndLoadDiaDebugStreamByName(
      kFixupDiaDebugStreamName, dia_session, pdb_fixups);
  if (search_result != kSearchSucceeded) {
    if (search_result == kSearchFailed) {
      LOG(ERROR) << "PDB file does not contain a FIXUP stream. Module must be "
                    "linked with '/PROFILE' or '/DEBUGINFO:FIXUP' flag.";
    }
    return false;
  }

  // Load the omap_from table. It is not necessary that one exist.
  search_result = FindAndLoadDiaDebugStreamByName(
      kOmapFromDiaDebugStreamName, dia_session, omap_from);
  if (search_result == kSearchErrored) {
    LOG(ERROR) << "Error trying to read " << kOmapFromDiaDebugStreamName
               << " stream.";
    return false;
  }

  return true;
}

bool GetFixupDestinationAndType(const PEFile& image_file,
                                const pdb::PdbFixup& fixup,
                                RelativeAddress* dst_addr,
                                ReferenceType* ref_type) {
  DCHECK(dst_addr != NULL);
  DCHECK(ref_type != NULL);

  RelativeAddress src_addr(fixup.rva_location);

  // Get the destination address from the actual image itself. We only see
  // fixups for 32-bit references.
  uint32 data = 0;
  if (!image_file.ReadImage(src_addr, &data, sizeof(data))) {
    LOG(ERROR) << "Unable to read image data for fixup with source address "
                << "at" << src_addr << ".";
    return false;
  }

  // Translate this to a relative address.
  switch (fixup.type) {
    case pdb::PdbFixup::TYPE_ABSOLUTE: {
      *ref_type = BlockGraph::ABSOLUTE_REF;
      AbsoluteAddress dst_addr_abs(data);
      if (!image_file.Translate(dst_addr_abs, dst_addr)) {
        LOG(ERROR) << "Unable to translate " << dst_addr_abs << ".";
        return false;
      }
      break;
    }

    case pdb::PdbFixup::TYPE_PC_RELATIVE: {
      *ref_type = BlockGraph::PC_RELATIVE_REF;
      *dst_addr = RelativeAddress(fixup.rva_location) + sizeof(data) + data;
      break;
    }

    case pdb::PdbFixup::TYPE_RELATIVE: {
      *ref_type = BlockGraph::RELATIVE_REF;
      *dst_addr = RelativeAddress(data);
      break;
    }

    default: {
      LOG(ERROR) << "Unexpected fixup type (" << fixup.type << ").";
      return false;
    }
  }

  return true;
}

// Creates references from the @p pdb_fixups (translating them via the
// provided @p omap_from information if it is not empty), all while removing the
// corresponding entries from @p reloc_set. If @p reloc_set is not empty after
// this then the PDB fixups are out of sync with the image and we are unable to
// safely decompose.
//
// @note This function deliberately ignores fixup information for the resource
//     section. This is because chrome.dll gets modified by a manifest tool
//     which doesn't update the FIXUPs in the corresponding PDB. They are thus
//     out of sync. Even if they were in sync this doesn't harm us as we have no
//     need to reach in and modify resource data.
bool CreateReferencesFromFixupsImpl(
    const PEFile& image_file,
    const PdbFixups& pdb_fixups,
    const OMAPs& omap_from,
    PEFile::RelocSet* reloc_set,
    BlockGraph::AddressSpace* image) {
  DCHECK(reloc_set != NULL);
  DCHECK(image != NULL);

  bool have_omap = omap_from.size() != 0;
  size_t fixups_used = 0;

  // The resource section in Chrome is modified post-link by a tool that adds a
  // manifest to it. This causes all of the fixups in the resource section (and
  // anything beyond it) to be invalid. As long as the resource section is the
  // last section in the image, this is not a problem (we can safely ignore the
  // .rsrc fixups, which we know how to parse without them). However, if there
  // is a section after the resource section, things will have been shifted
  // and potentially crucial fixups will be invalid.
  const IMAGE_SECTION_HEADER* rsrc_header = image_file.GetSectionHeader(
      kResourceSectionName);
  RelativeAddress rsrc_start(0xffffffff);
  RelativeAddress rsrc_end(0xffffffff);
  if (rsrc_header != NULL) {
    rsrc_start = RelativeAddress(rsrc_header->VirtualAddress);
    rsrc_end = rsrc_start + rsrc_header->Misc.VirtualSize;
  }

  // Ensure the fixups are all valid.
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
    DCHECK_EQ(Reference::kMaximumSize, pdb_fixups[i].size());

    // Get the original addresses, and map them through OMAP information.
    // Normally DIA takes care of this for us, but there is no API for
    // getting DIA to give us FIXUP information, so we have to do it manually.
    RelativeAddress src_addr(pdb_fixups[i].rva_location);
    RelativeAddress base_addr(pdb_fixups[i].rva_base);
    if (have_omap) {
      src_addr = pdb::TranslateAddressViaOmap(omap_from, src_addr);
      base_addr = pdb::TranslateAddressViaOmap(omap_from, base_addr);
    }

    // If the reference originates beyond the .rsrc section then we can't
    // trust it.
    if (src_addr >= rsrc_end) {
      LOG(ERROR) << "Found fixup originating beyond .rsrc section.";
      return false;
    }

    // If the reference originates from a part of the .rsrc section, ignore it.
    if (src_addr >= rsrc_start)
      continue;

    // Get the destination address of the fixup. This logs verbosely for us.
    RelativeAddress dst_addr;
    ReferenceType type = BlockGraph::RELATIVE_REF;
    if (!GetFixupDestinationAndType(image_file, pdb_fixups[i], &dst_addr,
                                    &type)) {
      return false;
    }

    // Finally, create the reference. This logs verbosely for us on failure.
    if (!CreateReference(src_addr, Reference::kMaximumSize, type, base_addr,
                         dst_addr, image)) {
      return false;
    }

    // Remove this reference from the relocs.
    PEFile::RelocSet::iterator reloc_it = reloc_set->find(src_addr);
    if (reloc_it != reloc_set->end()) {
      // We should only find a reloc if the fixup was of absolute type.
      if (type != BlockGraph::ABSOLUTE_REF) {
        LOG(ERROR) << "Found a reloc corresponding to a non-absolute fixup.";
        return false;
      }

      reloc_set->erase(reloc_it);
    }

    ++fixups_used;
  }

  LOG(INFO) << "Used " << fixups_used << " of " << pdb_fixups.size() << ".";

  return true;
}

}  // namespace

NewDecomposer::NewDecomposer(const PEFile& image_file)
    : image_file_(image_file), image_layout_(NULL), image_(NULL) {
}

bool NewDecomposer::Decompose(ImageLayout* image_layout) {
  DCHECK(image_layout != NULL);

  // The temporaries should be NULL.
  DCHECK(image_layout_ == NULL);
  DCHECK(image_ == NULL);

  // We start by finding the PDB path.
  if (!FindAndValidatePdbPath())
    return false;
  DCHECK(!pdb_path_.empty());

  // Load the serialized block-graph from the PDB if it exists. This allows
  // round-trip decomposition.
  bool stream_exists = false;
  if (LoadBlockGraphFromPdb(
          pdb_path_, image_file_, image_layout, &stream_exists)) {
    return true;
  } else if (stream_exists) {
    // If the stream exists but hasn't been loaded we return an error. At this
    // point an error message has already been logged if there was one.
    return false;
  }

  // At this point a full decomposition needs to be performed.
  image_layout_ = image_layout;
  image_ = &(image_layout->blocks);
  bool success = DecomposeImpl();
  image_layout_ = NULL;
  image_ = NULL;

  return success;
}

bool NewDecomposer::FindAndValidatePdbPath() {
  // Manually find the PDB path if it is not specified.
  if (pdb_path_.empty()) {
    if (!FindPdbForModule(image_file_.path(), &pdb_path_) ||
        pdb_path_.empty()) {
      LOG(ERROR) << "Unable to find PDB file for module: "
                 << image_file_.path().value();
      return false;
    }
  }
  DCHECK(!pdb_path_.empty());

  if (!file_util::PathExists(pdb_path_)) {
    LOG(ERROR) << "Path not found: " << pdb_path_.value();
    return false;
  }

  if (!pe::PeAndPdbAreMatched(image_file_.path(), pdb_path_)) {
    LOG(ERROR) << "PDB file \"" << pdb_path_.value() << "\" does not match "
               << "module \"" << image_file_.path().value() << "\".";
    return false;
  }

  return true;
}

bool NewDecomposer::LoadBlockGraphFromPdbStream(
    const PEFile& image_file,
    pdb::PdbStream* block_graph_stream,
    ImageLayout* image_layout) {
  DCHECK(block_graph_stream != NULL);
  DCHECK(image_layout != NULL);
  LOG(INFO) << "Reading block-graph and image layout from the PDB.";

  // Initialize an input archive pointing to the stream.
  scoped_refptr<pdb::PdbByteStream> byte_stream = new pdb::PdbByteStream();
  if (!byte_stream->Init(block_graph_stream))
    return false;
  DCHECK(byte_stream.get() != NULL);

  core::ScopedInStreamPtr pdb_in_stream;
  pdb_in_stream.reset(core::CreateByteInStream(
      byte_stream->data(), byte_stream->data() + byte_stream->length()));

  // Read the header.
  uint32 stream_version = 0;
  unsigned char compressed = 0;
  if (!pdb_in_stream->Read(sizeof(stream_version),
                           reinterpret_cast<core::Byte*>(&stream_version)) ||
      !pdb_in_stream->Read(sizeof(compressed),
                           reinterpret_cast<core::Byte*>(&compressed))) {
    LOG(ERROR) << "Failed to read existing Syzygy block-graph stream header.";
    return false;
  }

  // Check the stream version.
  if (stream_version != pdb::kSyzygyBlockGraphStreamVersion) {
    LOG(ERROR) << "PDB contains an unsupported Syzygy block-graph stream"
               << " version (got " << stream_version << ", expected "
               << pdb::kSyzygyBlockGraphStreamVersion << ").";
    return false;
  }

  // If the stream is compressed insert the decompression filter.
  core::InStream* in_stream = pdb_in_stream.get();
  scoped_ptr<core::ZInStream> zip_in_stream;
  if (compressed != 0) {
    zip_in_stream.reset(new core::ZInStream(in_stream));
    if (!zip_in_stream->Init()) {
      LOG(ERROR) << "Unable to initialize ZInStream.";
      return false;
    }
    in_stream = zip_in_stream.get();
  }

  // Deserialize the image-layout.
  core::NativeBinaryInArchive in_archive(in_stream);
  block_graph::BlockGraphSerializer::Attributes attributes = 0;
  if (!LoadBlockGraphAndImageLayout(
      image_file, &attributes, image_layout, &in_archive)) {
    LOG(ERROR) << "Failed to deserialize block-graph and image layout.";
    return false;
  }

  return true;
}

bool NewDecomposer::LoadBlockGraphFromPdb(const FilePath& pdb_path,
                                          const PEFile& image_file,
                                          ImageLayout* image_layout,
                                          bool* stream_exists) {
  DCHECK(image_layout != NULL);
  DCHECK(stream_exists != NULL);

  pdb::PdbFile pdb_file;
  pdb::PdbReader pdb_reader;
  if (!pdb_reader.Read(pdb_path, &pdb_file)) {
    LOG(ERROR) << "Unable to read the PDB named \"" << pdb_path.value()
               << "\".";
    return NULL;
  }

  // Try to get the block-graph stream from the PDB.
  scoped_refptr<pdb::PdbStream> block_graph_stream;
  if (!pdb::LoadNamedStreamFromPdbFile(pdb::kSyzygyBlockGraphStreamName,
                                       &pdb_file,
                                       &block_graph_stream) ||
      block_graph_stream.get() == NULL) {
    *stream_exists = false;
    return false;
  }
  if (block_graph_stream->length() == 0) {
    *stream_exists = false;
    LOG(WARNING) << "The block-graph stream is empty, ignoring it.";
    return false;
  }

  // The PDB contains a block-graph stream, the block-graph and the image layout
  // will be read from this stream.
  *stream_exists = true;
  if (!LoadBlockGraphFromPdbStream(image_file, block_graph_stream.get(),
                                   image_layout)) {
    return false;
  }

  return true;
}

bool NewDecomposer::DecomposeImpl() {
  // Instantiate and initialize our Debug Interface Access session. This logs
  // verbosely for us.
  ScopedComPtr<IDiaDataSource> dia_source;
  ScopedComPtr<IDiaSession> dia_session;
  ScopedComPtr<IDiaSymbol> global;
  if (!InitializeDia(image_file_, pdb_path_, dia_source.Receive(),
                     dia_session.Receive(), global.Receive())) {
    return false;
  }

  // Copy the image headers to the layout.
  CopySectionHeadersToImageLayout(
      image_file_.nt_headers()->FileHeader.NumberOfSections,
      image_file_.section_headers(),
      &(image_layout_->sections));

  // Create the sections in the underlying block-graph.
  if (!CreateBlockGraphSections())
    return false;

  // We scope the first few operations so that we don't keep the intermediate
  // references around any longer than we have to.
  {
    IntermediateReferences references;

    // First we parse out the PE blocks.
    if (!CreatePEImageBlocksAndReferences(&references))
      return false;

    // Next we parse out section contributions. Some of these may coincide with
    // existing PE parsed blocks, but when they do we expect them to be exact
    // collisions.
    if (!CreateBlocksFromSectionContribs(dia_session.get()))
      return false;

    // Flesh out the rest of the image with gap blocks.
    if (!CreateGapBlocks())
      return false;

    // Finalize the PE-parsed intermediate references.
    if (!FinalizeIntermediateReferences(references))
      return false;
  }

  // Parse the fixups and use them to create references.
  if (!CreateReferencesFromFixups(dia_session.get()))
    return false;

  return true;
}

bool NewDecomposer::CreateBlockGraphSections() {
  // Iterate through the image sections, and create sections in the BlockGraph.
  size_t num_sections = image_file_.nt_headers()->FileHeader.NumberOfSections;
  for (size_t i = 0; i < num_sections; ++i) {
    const IMAGE_SECTION_HEADER* header = image_file_.section_header(i);
    std::string name = pe::PEFile::GetSectionName(*header);
    BlockGraph::Section* section = image_->graph()->AddSection(
        name, header->Characteristics);
    DCHECK(section != NULL);

    // For now, we expect them to have been created with the same IDs as those
    // in the original image.
    if (section->id() != i) {
      LOG(ERROR) << "Unexpected section ID.";
      return false;
    }
  }

  return true;
}

bool NewDecomposer::CreatePEImageBlocksAndReferences(
    IntermediateReferences* references) {
  DCHECK(references != NULL);

  PEFileParser::AddReferenceCallback add_reference(
      base::Bind(&AddIntermediateReference, base::Unretained(references)));
  PEFileParser parser(image_file_, image_, add_reference);
  PEFileParser::PEHeader header;
  if (!parser.ParseImage(&header)) {
    LOG(ERROR) << "Unable to parse PE image.";
    return false;
  }

  return true;
}

bool NewDecomposer::CreateBlocksFromSectionContribs(IDiaSession* session) {
  ScopedComPtr<IDiaEnumSectionContribs> section_contribs;
  SearchResult search_result = FindDiaTable(session,
                                            section_contribs.Receive());
  if (search_result != kSearchSucceeded) {
    if (search_result == kSearchFailed)
      LOG(ERROR) << "No section contribution table found.";
    return false;
  }

  size_t rsrc_id = image_file_.GetSectionIndex(kResourceSectionName);

  LONG count = 0;
  if (section_contribs->get_Count(&count) != S_OK) {
    LOG(ERROR) << "Failed to get section contributions enumeration length.";
    return false;
  }

  for (LONG visited = 0; visited < count; ++visited) {
    ScopedComPtr<IDiaSectionContrib> section_contrib;
    ULONG fetched = 0;
    HRESULT hr = section_contribs->Next(1, section_contrib.Receive(), &fetched);
    // The standard way to end an enumeration (according to the docs) is by
    // returning S_FALSE and setting fetched to 0. We don't actually see this,
    // but it wouldn't be an error if we did.
    if (hr == S_FALSE && fetched == 0)
      break;
    if (hr != S_OK) {
      LOG(ERROR) << "Failed to get DIA section contribution: "
                 << com::LogHr(hr) << ".";
      return false;
    }
    // We actually end up seeing S_OK and fetched == 0 when the enumeration
    // terminates, which goes against the publishes documentations.
    if (fetched == 0)
      break;

    DWORD rva = 0;
    DWORD length = 0;
    DWORD section_id = 0;
    BOOL code = FALSE;
    ScopedComPtr<IDiaSymbol> compiland;
    ScopedBstr bstr_name;
    if ((hr = section_contrib->get_relativeVirtualAddress(&rva)) != S_OK ||
        (hr = section_contrib->get_length(&length)) != S_OK ||
        (hr = section_contrib->get_addressSection(&section_id)) != S_OK ||
        (hr = section_contrib->get_code(&code)) != S_OK ||
        (hr = section_contrib->get_compiland(compiland.Receive())) != S_OK ||
        (hr = compiland->get_name(bstr_name.Receive())) != S_OK) {
      LOG(ERROR) << "Failed to get section contribution properties: "
                 << com::LogHr(hr) << ".";
      return false;
    }

    // Determine if this function was built by a supported compiler.
    bool is_built_by_supported_compiler =
        IsBuiltBySupportedCompiler(compiland.get());

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
    BlockType block_type =
        code ? BlockGraph::CODE_BLOCK : BlockGraph::DATA_BLOCK;
    Block* block = CreateBlockOrFindCoveringPeBlock(
        block_type, RelativeAddress(rva), length, name);
    if (block == NULL) {
      LOG(ERROR) << "Unable to create block for compiland \"" << name << "\".";
      return false;
    }

    // Set the block attributes.
    block->set_attribute(BlockGraph::SECTION_CONTRIB);
    if (!is_built_by_supported_compiler)
      block->set_attribute(BlockGraph::BUILT_BY_UNSUPPORTED_COMPILER);
  }

  return true;
}

bool NewDecomposer::CreateGapBlocks() {
  size_t num_sections = image_file_.nt_headers()->FileHeader.NumberOfSections;

  // Iterate through all the image sections.
  for (size_t i = 0; i < num_sections; ++i) {
    const IMAGE_SECTION_HEADER* header = image_file_.section_header(i);
    DCHECK(header != NULL);

    BlockType type = BlockGraph::CODE_BLOCK;
    const char* section_type = NULL;
    switch (GetSectionType(header)) {
      case kSectionCode:
        type = BlockGraph::CODE_BLOCK;
        section_type = "code";
        break;

      case kSectionData:
        type = BlockGraph::DATA_BLOCK;
        section_type = "data";
        break;

      default:
        continue;
    }

    if (!CreateSectionGapBlocks(header, type)) {
      LOG(ERROR) << "Unable to create gap blocks for " << section_type
                 << " section \"" << header->Name << "\".";
      return false;
    }
  }

  return true;
}

bool NewDecomposer::FinalizeIntermediateReferences(
    const IntermediateReferences& references) {
  for (size_t i = 0; i < references.size(); ++i) {
    // This logs verbosely for us.
    if (!CreateReference(references[i].src_addr,
                         references[i].size,
                         references[i].type,
                         references[i].dst_addr,
                         references[i].dst_addr,
                         image_)) {
      return false;
    }
  }
  return true;
}

bool NewDecomposer::CreateReferencesFromFixups(IDiaSession* session) {
  DCHECK(session != NULL);

  PEFile::RelocSet reloc_set;
  if (!image_file_.DecodeRelocs(&reloc_set))
    return false;

  OMAPs omap_from;
  PdbFixups fixups;
  if (!LoadDebugStreams(session, &fixups, &omap_from))
    return false;

  // While creating references from the fixups this removes the
  // corresponding reference data from the relocs. We use this as a kind of
  // double-entry bookkeeping to ensure all is well and right in the world.
  if (!CreateReferencesFromFixupsImpl(image_file_, fixups, omap_from,
                                      &reloc_set, image_)) {
    return false;
  }

  if (!reloc_set.empty()) {
    LOG(ERROR) << "Found reloc entries without matching FIXUP entries.";
    return false;
  }

  return true;
}

Block* NewDecomposer::CreateBlock(BlockType type,
                                  RelativeAddress address,
                                  BlockGraph::Size size,
                                  const base::StringPiece& name) {
  Block* block = image_->AddBlock(type, address, size, name);
  if (block == NULL) {
    LOG(ERROR) << "Unable to add block at " << address << " with size "
               << size << ".";
    return NULL;
  }

  // Mark the source range from whence this block originates. This is assuming
  // an untransformed image. To handle transformed images we'd have to use the
  // OMAP information to do this properly.
  bool pushed = block->source_ranges().Push(
      Block::DataRange(0, size),
      Block::SourceRange(address, size));
  DCHECK(pushed);

  BlockGraph::SectionId section = image_file_.GetSectionIndex(address, size);
  if (section == BlockGraph::kInvalidSectionId) {
    LOG(ERROR) << "Block at " << address << " with size " << size
               << " lies outside of all sections.";
    return NULL;
  }
  block->set_section(section);

  const uint8* data = image_file_.GetImageData(address, size);
  if (data != NULL)
    block->SetData(data, size);

  return block;
}

Block* NewDecomposer::CreateBlockOrFindCoveringPeBlock(
    BlockType type,
    RelativeAddress addr,
    BlockGraph::Size size,
    const base::StringPiece& name) {
  Block* block = image_->GetBlockByAddress(addr);
  if (block != NULL) {
    RelativeAddress block_addr;
    CHECK(image_->GetAddressOf(block, &block_addr));

    RelativeRange existing_block(block_addr, block->size());

    // If this is not a PE parsed block that covers us entirely, then this is
    // an error.
    if ((block->attributes() & BlockGraph::PE_PARSED) == 0 ||
        !existing_block.Contains(addr, size)) {
      LOG(ERROR) << "Trying to create block \"" << name.as_string() << "\" at "
                 << addr.value() << " with size " << size << " that conflicts "
                 << "with existing block \"" << block->name() << " at "
                 << block_addr << " with size " << block->size() << ".";
      return NULL;
    }

    return block;
  }
  DCHECK(block == NULL);

  return CreateBlock(type, addr, size, name);
}

bool NewDecomposer::CreateGapBlock(BlockType block_type,
                                   RelativeAddress address,
                                   BlockGraph::Size size) {
  Block* block = CreateBlock(block_type, address, size,
      StringPrintf("Gap Block 0x%08X", address.value()).c_str());
  if (block == NULL) {
    LOG(ERROR) << "Unable to create gap block.";
    return false;
  }
  block->set_attribute(BlockGraph::GAP_BLOCK);

  return true;
}

bool NewDecomposer::CreateSectionGapBlocks(const IMAGE_SECTION_HEADER* header,
                                           BlockType block_type) {
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
  if (section_begin < it->first.start()) {
    if (!CreateGapBlock(
        block_type, section_begin, it->first.start() - section_begin)) {
      return false;
    }
  }

  // Now iterate the blocks and fill in gaps.
  for (; it != end; ++it) {
    const Block* block = it->second;
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
          block_type, block_end, next->first.start() - block_end)) {
        return false;
      }
  }

  return true;
}

}  // namespace pe
