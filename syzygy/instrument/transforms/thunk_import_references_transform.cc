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

#include "syzygy/instrument/transforms/thunk_import_references_transform.h"

// The Win8 SDK defines this in winerror.h, and it is subsequently redefined by
// delayimp.h
#undef FACILITY_VISUALCPP
#include <delayimp.h>
#include <limits>

#include "base/logging.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "syzygy/block_graph/basic_block_assembler.h"
#include "syzygy/block_graph/block_builder.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/common/defs.h"
#include "syzygy/pe/pe_utils.h"

namespace instrument {
namespace transforms {

namespace {

using block_graph::BlockGraph;
using block_graph::TypedBlock;
using block_graph::ConstTypedBlock;

// A simple struct that can be used to let us access strings using TypedBlock.
struct StringStruct {
  const char string[1];
};

typedef BlockGraph::Offset Offset;
typedef TypedBlock<IMAGE_DOS_HEADER> DosHeader;
typedef TypedBlock<IMAGE_IMPORT_BY_NAME> ImageImportByName;
typedef TypedBlock<IMAGE_IMPORT_DESCRIPTOR> ImageImportDescriptor;
typedef TypedBlock<IMAGE_NT_HEADERS> NtHeaders;
typedef TypedBlock<StringStruct> StringBlock;
typedef TypedBlock<ImgDelayDescr> ImageDelayImportDescriptor;

// We add this suffix to the destination
const char kThunkSuffix[] = "_ImportThunk";
const char kDelayThunkSuffix[] = "_DelayImportThunk";

}  // namespace

using pe::transforms::PEAddImportsTransform;
using pe::transforms::ImportedModule;

const char ThunkImportReferencesTransform::kTransformName[] =
    "ThunkImportReferencesTransform";

const char ThunkImportReferencesTransform::kEntryHookName[] =
    "_indirect_penter";
const char ThunkImportReferencesTransform::kDefaultInstrumentDll[] =
    "call_trace.dll";

ThunkImportReferencesTransform::ThunkImportReferencesTransform()
    : thunk_section_(NULL),
      instrument_dll_name_(kDefaultInstrumentDll) {
}

bool ThunkImportReferencesTransform::TransformBlockGraph(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {
  DCHECK_NE(reinterpret_cast<TransformPolicyInterface*>(NULL), policy);
  DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), header_block);
  DCHECK_EQ(BlockGraph::PE_IMAGE, block_graph->image_format());
  DCHECK_EQ(reinterpret_cast<BlockGraph::Section*>(NULL), thunk_section_);

  // We always exclude our own agent DLL from instrumentation.
  modules_to_exclude_.insert(instrument_dll_name_);

  // Start by finding or adding import entries for our instrumentation hook.
  ImportedModule import_module(instrument_dll_name_);
  size_t hook_index = import_module.AddSymbol(
      kEntryHookName, ImportedModule::kAlwaysImport);

  add_imports_transform_.AddModule(&import_module);

  if (!add_imports_transform_.TransformBlockGraph(
          policy, block_graph, header_block)) {
    LOG(ERROR) << "Unable to add imports for instrumentation DLL.";
    return false;
  }

  if (!import_module.GetSymbolReference(hook_index, &hook_ref_)) {
    LOG(ERROR) << "Unable to get import reference for hook.";
    return false;
  }

  ImportAddressLocationNameMap import_locations;
  if (!LookupImportLocations(modules_to_exclude_,
                             header_block,
                             &import_locations)) {
    LOG(ERROR) << "Unable to resolve import names and locations.";
    return false;
  }
  if (!LookupDelayImportLocations(modules_to_exclude_,
                                  header_block,
                                  &import_locations)) {
    LOG(ERROR) << "Unable to resolve delay import names and locations.";
    return false;
  }

  // Now instrument all the import locations we located.
  if (!InstrumentImportReferences(block_graph, import_locations)) {
    LOG(ERROR) << "Unable to instrument import references.";
    return false;
  }

  return true;
}

void ThunkImportReferencesTransform::ExcludeModule(
  const base::StringPiece& module_name) {
  modules_to_exclude_.insert(module_name.as_string());
}

bool ThunkImportReferencesTransform::ModuleNameLess::operator()(
    const std::string& lhs, const std::string& rhs) const {
  size_t len = std::min(lhs.size(), rhs.size());
  for (size_t i = 0; i < len; ++i) {
    char lhc = base::ToLowerASCII(lhs[i]);
    char rhc = base::ToLowerASCII(rhs[i]);
    if (lhc < rhc)
      return true;
    else if (lhc > rhc)
      return false;
  }

  // The strings are equal the end of the shorter string,
  // if the lhs is shorter it's smaller.
  return lhs.size() < rhs.size();
}

// This method builds up a set of thunk blocks as well as a thunk table
// containing pointers to these blocks. Existing import references are then
// replaced by references to the thunk table. Since imports are invoked via
// an indirect call or jump instruction, changing the address of the call
// statement from an address into the IAT to an address into the thunk table
// gets the thunk called properly.
bool ThunkImportReferencesTransform::InstrumentImportReferences(
    BlockGraph* block_graph,
    const ImportAddressLocationNameMap& import_locations) {
  // Find or create the section we put our thunks in.
  thunk_section_ = block_graph->FindOrAddSection(common::kThunkSectionName,
                                                 pe::kCodeCharacteristics);
  if (thunk_section_ == NULL) {
    LOG(ERROR) << "Unable to find or create .thunks section.";
    return false;
  }

  // Find the set of blocks referred by import_locations.
  BlockSet import_blocks;
  if (!GetImportBlocks(import_locations, &import_blocks)) {
    LOG(ERROR) << "Unable to get import blocks.";
    return false;
  }

  // Typedef for the thunk block map. The key is the <iat block, offset> the
  // (since all callers can use the same thunk) and the value is the offset into
  // the thunk table that points to the thunk block for that IAT entry.
  typedef std::pair<const BlockGraph::Block*, BlockGraph::Offset>
      ThunkBlockKey;
  typedef std::map<ThunkBlockKey, BlockGraph::Offset> ThunkBlockMap;
  ThunkBlockMap thunk_block_map;

  // Create the thunk table - we'll grow it as we go.
  BlockGraph::Block* thunk_table_block =
      block_graph->AddBlock(BlockGraph::DATA_BLOCK, 0, "ImportsThunkTable");
  thunk_table_block->set_section(thunk_section_->id());
  BlockGraph::Offset thunk_table_offset = 0;

  // Now iterate through the import blocks and instrument the references.
  BlockSet::const_iterator it = import_blocks.begin();
  for (; it != import_blocks.end(); ++it) {
    BlockGraph::Block* iat_block = *it;

    // Next, list all referrers to get all references into the IAT. For each
    // eligible reference, create a thunk (in its own block) and add a pointer
    // to it to the thunk table.
    BlockGraph::Block::ReferrerSet iat_referrers(iat_block->referrers());
    BlockGraph::Block::ReferrerSet::const_iterator iat_referrer_iter(
        iat_referrers.begin());
    for (; iat_referrer_iter != iat_referrers.end(); ++iat_referrer_iter) {
      BlockGraph::Block* referrer = iat_referrer_iter->first;

      if (referrer == iat_block) {
        LOG(WARNING) << "Unexpected self-reference in IAT.";
        continue;
      }

      if (referrer->type() != BlockGraph::CODE_BLOCK) {
        // We shouldn't see data referring to import table entries, outside
        // the PE structures.
        DCHECK(referrer->attributes() & BlockGraph::PE_PARSED);

        LOG(INFO) << "Skipping non-code block reference from block: '"
                  << referrer->name() << "'";
        continue;
      }

      if (referrer->attributes() & BlockGraph::THUNK) {
        LOG(INFO) << "Skipping thunk block reference from block: '"
                  << referrer->name() << "'";
        continue;
      }

      // Now that we know the referring block, we need to find out where in the
      // IAT it refers to.
      BlockGraph::Reference ref;
      if (!referrer->GetReference(iat_referrer_iter->second, &ref)) {
        LOG(ERROR) << "Unable to get reference from referrer.";
        return false;
      }

      // See whether this is an eligible import.
      ImportAddressLocationNameMap::const_iterator it(
          import_locations.find(
              std::make_pair(ref.referenced(), ref.offset())));
      if (it == import_locations.end()) {
        // It's not an eligible location, skip it.
        continue;
      }

      // For now, let's not try and thunk thunks. This means that we can't
      // e.g. double-instrument, which is a potentially legitimate use case,
      // but it should only be supported if there's adequate testing for it.
      if (referrer->section() == thunk_section_->id()) {
        LOG(ERROR) << "Thunking a reference from the thunk section, "
                   << "in block: '" << referrer->name() << "'";
        return false;
      }

      // Look for the reference in the thunk block map, and only create a
      // new one if it does not already exist.
      BlockGraph::Block* thunk_block = NULL;
      BlockGraph::Offset new_ref_offset = 0;

      ThunkBlockKey key(std::make_pair(iat_block, ref.offset()));
      ThunkBlockMap::const_iterator thunk_it = thunk_block_map.find(key);
      if (thunk_it == thunk_block_map.end()) {
        // Create the thunk block for this offset into the IAT.
        thunk_block = CreateOneThunk(block_graph, ref, it->second);
        if (thunk_block == NULL) {
          LOG(DFATAL) << "Unable to create thunk block.";
          return false;
        }

        // Now add a reference to the thunk in the thunk table.
        BlockGraph::Reference thunk_ref(BlockGraph::ABSOLUTE_REF,
                                        sizeof(core::AbsoluteAddress),
                                        thunk_block, 0, 0);
        thunk_table_block->set_size(
            thunk_table_offset + sizeof(core::AbsoluteAddress));
        thunk_table_block->SetReference(thunk_table_offset, thunk_ref);

        // Remember this thunk in case we need to use it again.
        thunk_block_map[key] = thunk_table_offset;
        new_ref_offset = thunk_table_offset;

        // Move to the next empty entry in the thunk table.
        thunk_table_offset += sizeof(core::AbsoluteAddress);
        DCHECK_EQ(static_cast<BlockGraph::Size>(thunk_table_offset),
                  thunk_table_block->size());
      } else {
        new_ref_offset = thunk_it->second;
      }

      // Update the referrer to point to the new location in the thunk table.
      BlockGraph::Reference new_ref(ref.type(),
                                    ref.size(),
                                    thunk_table_block,
                                    new_ref_offset,
                                    0);
      referrer->SetReference(iat_referrer_iter->second, new_ref);
    }
  }

  return true;
}

BlockGraph::Block* ThunkImportReferencesTransform::CreateOneThunk(
    BlockGraph* block_graph,
    const BlockGraph::Reference& destination,
    const base::StringPiece& name) {
  using block_graph::BasicBlockSubGraph;
  using block_graph::BasicBlockAssembler;
  using block_graph::BasicCodeBlock;
  using block_graph::BlockBuilder;
  using block_graph::Operand;
  using block_graph::Displacement;

  // Construct the name for the new thunk.
  std::string thunk_name(name.as_string());
  thunk_name.append(kThunkSuffix);

  // Set up a basic block subgraph containing a single block description, with
  // that block description containing a single empty basic block, and get an
  // assembler writing into that basic block.
  BasicBlockSubGraph bbsg;
  BasicBlockSubGraph::BlockDescription* block_desc = bbsg.AddBlockDescription(
      thunk_name,
      NULL,
      BlockGraph::CODE_BLOCK,
      thunk_section_->id(),
      1,
      0);
  BasicCodeBlock* bb = bbsg.AddBasicCodeBlock(name);
  block_desc->basic_block_order.push_back(bb);
  BasicBlockAssembler assm(bb->instructions().begin(), &bb->instructions());

  // The thunk contains this.
  // push  dword ptr [<import>]
  // jmp   dword ptr [<entry_hook>]
  assm.push(
      Operand(Displacement(destination.referenced(), destination.offset())));
  assm.jmp(Operand(Displacement(hook_ref_.referenced(), hook_ref_.offset())));

  // Condense into a block.
  BlockBuilder block_builder(block_graph);
  if (!block_builder.Merge(&bbsg)) {
    LOG(ERROR) << "Failed to build thunk block.";
    return NULL;
  }

  // Exactly one new block should have been created.
  DCHECK_EQ(1u, block_builder.new_blocks().size());
  BlockGraph::Block* thunk = block_builder.new_blocks().front();

  return thunk;
}

bool ThunkImportReferencesTransform::GetImportBlocks(
    const ImportAddressLocationNameMap& import_locations,
    BlockSet* import_blocks) {
  DCHECK(import_blocks != NULL);

  ImportAddressLocationNameMap::const_iterator it;
  BlockGraph::Block* last_block = NULL;
  while (true) {
    it = import_locations.upper_bound(
        std::make_pair(last_block, std::numeric_limits<Offset>::max()));

    if (it == import_locations.end())
      break;

    last_block = it->first.first;
    import_blocks->insert(last_block);
  }

  return true;
}

bool ThunkImportReferencesTransform::LookupImportLocations(
    const ModuleNameSet& exclusions,
    BlockGraph::Block* header_block,
    ImportAddressLocationNameMap* import_locations) {
  DCHECK(header_block != NULL);
  DCHECK(import_locations != NULL);

  // Start by retrieving the NT headers.
  DosHeader dos_header;
  NtHeaders nt_headers;
  if (!dos_header.Init(0, header_block) ||
      !dos_header.Dereference(dos_header->e_lfanew, &nt_headers)) {
    LOG(ERROR) << "Unable to cast image headers.";
    return false;
  }

  // Get to the import directory.
  const IMAGE_DATA_DIRECTORY* import_directory =
      &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

  ImageImportDescriptor iida;
  if (!nt_headers.Dereference(import_directory->VirtualAddress, &iida)) {
    LOG(ERROR) << "Failed to dereference Image Import Descriptor Array.";
    return false;
  }

  // The array is NULL terminated with a potentially incomplete descriptor so
  // we can't use ElementCount - 1.
  size_t descriptor_count =
      (common::AlignUp(iida.block()->size(), sizeof(IMAGE_IMPORT_DESCRIPTOR)) /
       sizeof(IMAGE_IMPORT_DESCRIPTOR)) - 1;

  for (size_t iida_index = 0; iida_index < descriptor_count; ++iida_index) {
    StringBlock dll_name_block;
    if (!iida.Dereference(iida[iida_index].Name, &dll_name_block)) {
      LOG(ERROR) << "Unable to dereference DLL name.";
      return false;
    }

    size_t len = strnlen(dll_name_block->string, dll_name_block.ElementCount());
    std::string dll_name(dll_name_block->string, dll_name_block->string + len);

    // Move to the next one if this is an excluded module.
    if (exclusions.find(dll_name) != exclusions.end())
      continue;

    // Walk the IAT and the INT(also know as hna) for this module concurrently
    // until we come to a zero terminator for one or the other and mark their
    // offsets and names in the location names map.
    TypedBlock<IMAGE_IMPORT_BY_NAME*> hna, iat;
    if (!iida.Dereference(iida[iida_index].OriginalFirstThunk, &hna) ||
        !iida.Dereference(iida[iida_index].FirstThunk, &iat)) {
      LOG(ERROR) << "Unable to dereference OriginalFirstThunk/FirstThunk.";
      return false;
    }

    // Loop through the imports, tag and bag them.
    size_t i = 0;
    for (; i < hna.ElementCount() && i < iat.ElementCount(); ++i) {
      ConstTypedBlock<IMAGE_THUNK_DATA32> thunk;
      if (!thunk.Init(hna.OffsetOf(hna[i]), hna.block())) {
        LOG(ERROR) << "Unable to dereference IMAGE_THUNK_DATA32.";
        return false;
      }

      // Construct the location for this entry.
      ImportAddressLocation key(
          std::make_pair(iat.block(), iat.OffsetOf(iat[i])));
      std::string import_name = dll_name;

      // Is this an ordinal import?
      if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) {
        // Ordinal imports are named <dll>:#<ordinal>.
        base::StringAppendF(&import_name,
                            ":#%d",
                            IMAGE_ORDINAL(thunk->u1.Ordinal));
      } else if (!thunk.HasReference(thunk->u1.AddressOfData)) {
        // Have no reference? Then terminate the iteration.
        // We sanity check that the actual data is null.
        DCHECK_EQ(0u, thunk->u1.AddressOfData);
        break;
      } else {
        // Otherwise this should point to an IMAGE_IMPORT_BY_NAME structure.
        ImageImportByName iibn;
        if (!hna.Dereference(hna[i], &iibn)) {
          LOG(ERROR) << "Unable to dereference IMAGE_IMPORT_BY_NAME.";
          return false;
        }
        size_t len =
            strnlen(iibn->Name,
                    iibn.block()->size() - iibn.OffsetOf(iibn->Name));
        std::string function_name(iibn->Name, iibn->Name + len);

        base::StringAppendF(&import_name, ":%s", function_name.c_str());
      }

      // Tag and name it.
      bool inserted =
          import_locations->insert(std::make_pair(key, import_name)).second;

      DCHECK(inserted);
    }
  }

  return true;
}

bool ThunkImportReferencesTransform::LookupDelayImportLocations(
    const ModuleNameSet& exclusions,
    BlockGraph::Block* header_block,
    ImportAddressLocationNameMap* import_locations) {
  DCHECK(header_block != NULL);
  DCHECK(import_locations != NULL);

  // Start by retrieving the NT headers.
  DosHeader dos_header;
  NtHeaders nt_headers;
  if (!dos_header.Init(0, header_block) ||
      !dos_header.Dereference(dos_header->e_lfanew, &nt_headers)) {
    LOG(ERROR) << "Unable to cast image headers.";
    return false;
  }

  // Get to the delay import directory.
  const IMAGE_DATA_DIRECTORY* delay_import_directory =
      &nt_headers->OptionalHeader
          .DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];

  ImageDelayImportDescriptor idida;
  if (!nt_headers.Dereference(delay_import_directory->VirtualAddress, &idida)) {
    // Unable to dereference, this is only an error if there are delay imports.
    if (!nt_headers.HasReference(delay_import_directory->VirtualAddress)) {
      DCHECK_EQ(0U, delay_import_directory->VirtualAddress);
      return true;
    }

    LOG(ERROR) << "Failed to dereference delay Image Import Descriptor Array.";
    return false;
  }

  for (size_t idida_idx = 0; idida_idx < idida.ElementCount(); ++idida_idx) {
    // The last descriptor is a sentinel.
    if (idida[idida_idx].grAttrs == 0)
      break;

    StringBlock dll_name_block;
    if (!idida.Dereference(idida[idida_idx].rvaDLLName, &dll_name_block)) {
      LOG(ERROR) << "Unable to dereference DLL name.";
      return false;
    }

    size_t len = strnlen(dll_name_block->string, dll_name_block.ElementCount());
    std::string dll_name(dll_name_block->string, dll_name_block->string + len);

    // Move to the next one if this is an excluded module.
    if (exclusions.find(dll_name) != exclusions.end())
      continue;

    // Walk the IAT and the INT(also know as hna) for this module concurrently
    // until we come to a zero terminator for one or the other and mark their
    // offsets and names in the location names map.
    TypedBlock<IMAGE_IMPORT_BY_NAME*> hna, iat;
    if (!idida.Dereference(idida[idida_idx].rvaINT, &hna) ||
        !idida.Dereference(idida[idida_idx].rvaIAT, &iat)) {
      LOG(ERROR) << "Unable to dereference OriginalFirstThunk/FirstThunk.";
      return false;
    }

    // Loop through the imports, tag and bag them.
    size_t i = 0;
    for (; i < hna.ElementCount() && i < iat.ElementCount(); ++i) {
      ConstTypedBlock<IMAGE_THUNK_DATA32> thunk;
      if (!thunk.Init(hna.OffsetOf(hna[i]), hna.block())) {
        LOG(ERROR) << "Unable to dereference IMAGE_THUNK_DATA32.";
        return false;
      }

      // Construct the location for this entry.
      ImportAddressLocation key(
          std::make_pair(iat.block(), iat.OffsetOf(iat[i])));
      std::string import_name = dll_name;

      // Is this an ordinal import?
      if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) {
        // Ordinal imports are named <dll>:#<ordinal>.
        base::StringAppendF(&import_name,
                            ":#%d",
                            IMAGE_ORDINAL(thunk->u1.Ordinal));
      } else if (!thunk.HasReference(thunk->u1.AddressOfData)) {
        // Have no reference? Then terminate the iteration.
        // We sanity check that the actual data is null.
        DCHECK_EQ(0u, thunk->u1.AddressOfData);
        break;
      } else {
        // Otherwise this should point to an IMAGE_IMPORT_BY_NAME structure.
        ImageImportByName iibn;
        if (!hna.Dereference(hna[i], &iibn)) {
          LOG(ERROR) << "Unable to dereference IMAGE_IMPORT_BY_NAME.";
          return false;
        }
        size_t len =
            strnlen(iibn->Name,
                    iibn.block()->size() - iibn.OffsetOf(iibn->Name));
        std::string function_name(iibn->Name, iibn->Name + len);

        base::StringAppendF(&import_name, ":%s", function_name.c_str());
      }

      // Tag and name it.
      bool inserted =
          import_locations->insert(std::make_pair(key, import_name)).second;

      DCHECK(inserted);
    }
  }

  return true;
}

}  // namespace transforms
}  // namespace instrument
