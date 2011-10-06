// Copyright 2010 Google Inc.
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

#include "syzygy/instrument/instrumenter.h"
#include "base/string_util.h"
#include "base/utf_string_conversions.h"
#include "syzygy/common/defs.h"
#include "syzygy/common/syzygy_version.h"
#include "syzygy/core/serialization.h"
#include "syzygy/pe/pe_file_writer.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/metadata.h"

using core::AbsoluteAddress;
using core::RelativeAddress;
using pe::Decomposer;
using pe::PEFileWriter;

namespace {

const char* const kEntryHookTable[] = {
    "_indirect_penter",
    "_indirect_penter_dllmain",
};

enum EntryHookIndex {
  kIndirectPenter,
  kIndirectPenterDllMain,
  kEntryHookIndexMax
};

void CompileAsserts() {
  COMPILE_ASSERT(kEntryHookIndexMax == ARRAYSIZE(kEntryHookTable),
                 entry_hook_table_and_entry_hook_indices_not_same_size);
}

// TODO(rogerm): this functionality is duplicated! Consolidate!
size_t Align(size_t value, size_t alignment) {
  size_t expanded = value + alignment - 1;
  return expanded - (expanded % alignment);
}

// TODO(rogerm): this functionality is duplicated! Consolidate!
size_t WordAlign(size_t value) {
  return Align(value, sizeof(WORD));
}

}  // namespace

const char* const Instrumenter::kCallTraceClientDllEtw = "call_trace.dll";
const char* const Instrumenter::kCallTraceClientDllRpc =
    "call_trace_client.dll";

Instrumenter::Instrumenter()
    : client_dll_(kCallTraceClientDllEtw),
      image_import_by_name_block_(NULL),
      hint_name_array_block_(NULL),
      import_address_table_block_(NULL),
      dll_name_block_(NULL),
      image_import_descriptor_array_block_(NULL),
      resource_section_id_(pe::kInvalidSection) {
}

void Instrumenter::set_client_dll(const char* const client_dll) {
  DCHECK(client_dll != NULL);
  DCHECK(client_dll[0] != '\0');
  client_dll_ = client_dll;
}

bool Instrumenter::Instrument(const FilePath& input_dll_path,
                              const FilePath& output_dll_path) {
  DCHECK(!input_dll_path.empty());
  DCHECK(!output_dll_path.empty());

  // Read and decompose the input image for starters.
  LOG(INFO) << "Parsing input image PE headers.";
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

  // Construct and initialize our instrumenter.
  if (!Initialize(&decomposed)) {
    LOG(ERROR) << "Unable to initialize instrumenter.";
    return false;
  }

  // Copy the sections, except for .rsrc and .relocs.
  LOG(INFO) << "Copying sections.";
  if (!CopySections()) {
    LOG(ERROR) << "Unable to copy sections.";
    return false;
  }

  // Instrument the binary. This creates .import and .thunks sections.
  LOG(INFO) << "Adding call trace import descriptor.";
  if (!AddCallTraceImportDescriptor(
      decomposed.header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT])) {
    LOG(ERROR) << "Unable to add call trace import.";
    return false;
  }

  // Is this image directly executable or is it a DLL?
  WORD characteristics = input_dll.nt_headers()->FileHeader.Characteristics;
  bool is_dll = (characteristics & IMAGE_FILE_DLL) != 0;

  // If the image is a DLL, use the DllMain version of the instrumentation
  // hook for the entrypoint; otherwise, use the geneneral one.
  EntryHookIndex entry_point_hook =
      is_dll ? kIndirectPenterDllMain : kIndirectPenter;

  LOG(INFO) << "Instrumenting code blocks.";
  if (!InstrumentCodeBlocks(&decomposed.image, entry_point_hook)) {
    LOG(ERROR) << "Unable to instrument code blocks.";
    return false;
  }

  // Write metadata section.
  if (!WriteMetadataSection(input_dll))
    return false;

  // Copies the resource section, if there is one.
  if (!CopyResourceSection())
    return false;

  LOG(INFO) << "Copying data directory.";
  if (!CopyDataDirectory(decomposed.header)) {
    LOG(ERROR) << "Unable to copy the input image's data directory.";
    return false;
  }

  // Update the data directory import entry to refer to our newly created
  // section.
  if (!builder().SetDataDirectoryEntry(IMAGE_DIRECTORY_ENTRY_IMPORT,
                                       image_import_descriptor_array_block_)) {
    LOG(ERROR) << "Unable to set data directory entry.";
    return false;
  }

  // Finalize the headers and write the image.
  LOG(INFO) << "Finalizing headers.";
  if (!FinalizeImageHeaders(decomposed.header)) {
    LOG(ERROR) << "Unable to finalize image headers.";
    return false;
  }

  LOG(INFO) << "Writing the image.";
  if (!WriteImage(output_dll_path)) {
    LOG(ERROR) << "Unable to write " << output_dll_path.value();
    return false;
  }

  return true;
}

bool Instrumenter::CopySections() {
  // Copy the sections from the decomposed image to the new one, save for the
  // .relocs section. If there is a .rsrc section, does not copy it but stores
  // its index in resource_section_id_.
  for (size_t i = 0; i < original_num_sections() - 1; ++i) {
    const IMAGE_SECTION_HEADER& section = original_sections()[i];

    // Skip the resource section if we encounter it.
    std::string name = pe::PEFile::GetSectionName(section);
    if (name == common::kResourceSectionName) {
      // We should only ever come across one of these, and it should be
      // second to last.
      DCHECK_EQ(original_num_sections() - 2, i);
      DCHECK_EQ(pe::kInvalidSection, resource_section_id_);
      resource_section_id_ = i;
      continue;
    }

    LOG(INFO) << "Copying section " << i << " (" << name << ").";
    if (!CopySection(section)) {
      LOG(ERROR) << "Unable to copy section.";
      return false;
    }
  }

  return true;
}

bool Instrumenter::AddCallTraceImportDescriptor(
    const BlockGraph::Block* original_image_import_descriptor_array) {
  DCHECK(original_image_import_descriptor_array != NULL);

  RelativeAddress start = builder().next_section_address();
  RelativeAddress insert_at = start;

  // Create the image import by name block.
  if (!CreateImageImportByNameBlock(&insert_at)) {
    LOG(ERROR) << "Unable to create image import by name block";
    return false;
  }

  // Create the hint name array and import address table blocks.
  if (!CreateImportAddressTableBlocks(&insert_at)) {
    LOG(ERROR) << "Unable to create import address table block";
    return false;
  }

  // Create the DLL name block with room for a null character.
  if (!CreateDllNameBlock(&insert_at)) {
    LOG(ERROR) << "Unable to create dll name block";
    return false;
  }

  // Align the import descriptor array block to a DWORD boundary.
  insert_at.set_value(Align(insert_at.value(), sizeof(DWORD)));

  // Create the image import descript array block.
  if (!CreateImageImportDescriptorArrayBlock(
      original_image_import_descriptor_array, &insert_at)) {
    LOG(ERROR) << "Unable to create image import descriptor array block";
    return false;
  }

  // Wrap the above blocks in a new section.
  uint32 import_dir_size = insert_at - start;
  uint32 flags = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE |
                 IMAGE_SCN_CNT_INITIALIZED_DATA;
  RelativeAddress real_start = builder().AddSegment(
      ".import", import_dir_size, import_dir_size, flags);

  DCHECK_EQ(start, real_start);

  return true;
}

bool Instrumenter::InstrumentCodeBlocks(BlockGraph* block_graph,
                                        size_t entry_point_hook) {
  DCHECK(block_graph != NULL);
  DCHECK_LT(entry_point_hook, static_cast<size_t>(kEntryHookIndexMax));

  RelativeAddress start = builder().next_section_address();
  RelativeAddress insert_at = start;

  // The block map needs to be copied because it will change while we create
  // new thunks. However, pointers to the original blocks are needed, so copy
  // the block pointers into a vector. Also, we only need to instrument code
  // blocks, so filter non code blocks out here.
  std::vector<BlockGraph::Block*> block_list;
  BlockGraph::BlockMap::iterator block_it(
      block_graph->blocks_mutable().begin());
  for (; block_it != block_graph->blocks_mutable().end(); ++block_it) {
    if (block_it->second.type() == BlockGraph::CODE_BLOCK) {
      block_list.push_back(&block_it->second);
    }
  }

  // Iterate through all the code blocks in the decomposed image's block graph.
  for (uint32 i = 0; i < block_list.size(); ++i) {
    BlockGraph::Block* block = block_list[i];
    if (!CreateThunks(block, &insert_at)) {
      LOG(ERROR) << "Unable to create thunks for block";
      return false;
    }
  }

  // Instrument the image's entry point.
  if (!InstrumentEntryPoint(entry_point_hook, &insert_at)) {
    LOG(ERROR) << "Unable to update etnry point";
    return false;
  }

  // Wrap the thunks in a new section.
  uint32 thunks_size = insert_at - start;
  builder().AddSegment(".thunks",
                       thunks_size,
                       thunks_size,
                       IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ |
                       IMAGE_SCN_MEM_EXECUTE);

  return true;
}

bool Instrumenter::CreateImageImportByNameBlock(
    RelativeAddress* insert_at) {
  DCHECK(image_import_by_name_block_ == NULL);

  // Figure out how large the block needs to be to hold all the names of the
  // hooks we export.  The IMAGE_IMPORT_BY_NAME struct has a WORD ordinal and
  // a variable sized field for the null-terminated function name. Each entry
  // should be WORD aligned, and will be referenced from the import table.
  size_t total_size = 0;
  for (int i = 0; i < kEntryHookIndexMax; ++i) {
    total_size += sizeof(WORD) + WordAlign(strlen(kEntryHookTable[i]) + 1);
  }

  // Allocate the block.
  BlockGraph::Block* block =
      builder().address_space().AddBlock(BlockGraph::DATA_BLOCK,
                                         *insert_at,
                                         total_size,
                                         "image_import_by_name");
  if (block == NULL) {
    LOG(ERROR) << "Unable to allocate image import by name block";
    return false;
  }

  uint8* raw_data = block->AllocateData(total_size);
  if (raw_data == NULL) {
    LOG(ERROR) << "Unable to allocate image import by name block data";
    return false;
  }

  *insert_at += block->size();

  // Populate the block with IMAGE_IMPORT_BY_NAME records.
  size_t offset = 0;
  for (int i = 0; i < kEntryHookIndexMax; ++i) {
    size_t size = strlen(kEntryHookTable[i]) + 1;
    IMAGE_IMPORT_BY_NAME* image_import_by_name =
        reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(raw_data + offset);
    image_import_by_name->Hint = 0;
    base::strlcpy(reinterpret_cast<char*>(&image_import_by_name->Name[0]),
                  kEntryHookTable[i],
                  size);

    offset += sizeof(WORD) + WordAlign(size);
  }

  image_import_by_name_block_ = block;
  return true;
}

bool Instrumenter::CreateImportAddressTableBlocks(RelativeAddress* insert_at) {
  DCHECK(insert_at != NULL);
  DCHECK(image_import_by_name_block_ != NULL);
  DCHECK(hint_name_array_block_ == NULL);
  DCHECK(import_address_table_block_ == NULL);

  if (!CreateImportAddressTableBlock("hint_name_array", insert_at,
                                     &hint_name_array_block_)) {
     return false;
  }

  if (!CreateImportAddressTableBlock("import_address_table", insert_at,
                                     &import_address_table_block_)) {
     return false;
  }

  return true;
}

bool Instrumenter::CreateImportAddressTableBlock(const char* name,
                                                 RelativeAddress* insert_at,
                                                 BlockGraph::Block** block) {
  DCHECK(insert_at != NULL);
  DCHECK(block != NULL);
  DCHECK(*block == NULL);
  DCHECK(name != NULL);
  DCHECK(image_import_by_name_block_ != NULL);

  // The hint name array and import address table are identical null-terminated
  // arrays of IMAGE_THUNK_DATA. Each IMAGE_THUNK_DATA entry points to an
  // IMAGE_IMPORT_BY_NAME entry in the image import by name array.

  const size_t kImageThunkDataSize =
      sizeof(IMAGE_THUNK_DATA) * (kEntryHookIndexMax + 1);

  // Allocate the new block.
  BlockGraph::Block* new_block =
      builder().address_space().AddBlock(BlockGraph::DATA_BLOCK,
                                         *insert_at,
                                         kImageThunkDataSize,
                                         name);
  if (new_block == NULL) {
    LOG(ERROR) << "Unable to allocate " << name << " block.";
    return false;
  }

  // Allocate the the memory for the new block. It will already be zero-
  // initialized, which takes care of null-terminating the table.
  uint8* raw_data = new_block->AllocateData(new_block->size());
  if (raw_data == NULL) {
    LOG(ERROR) << "Unable to allocate " << name << " block data.";
    return false;
  }

  // Create references to each of the defined hooks.
  size_t offset = 0;
  for (int hook_index = 0; hook_index < kEntryHookIndexMax; ++hook_index) {
    // Create a reference to the hook's offset.
    BlockGraph::Reference hook_ref(BlockGraph::RELATIVE_REF,
                                   sizeof(RelativeAddress),
                                   image_import_by_name_block_,
                                   offset);
    new_block->SetReference(hook_index * sizeof(IMAGE_THUNK_DATA), hook_ref);
    offset += (sizeof(WORD) +
               WordAlign(strlen(kEntryHookTable[hook_index]) + 1));
  }

  // Advance the block insertion address.
  *insert_at += new_block->size();

  // Update the instrumenter's reference to this block.
  *block = new_block;

  return true;
}

bool Instrumenter::CreateDllNameBlock(RelativeAddress* insert_at) {
  DCHECK(dll_name_block_ == NULL);

  // Create the DLL name block with room for a null character.
  BlockGraph::Block* block =
      builder().address_space().AddBlock(BlockGraph::DATA_BLOCK,
                                         *insert_at,
                                         client_dll_.length() + 1,
                                         "client_dll_name");
  if (block == NULL) {
    LOG(ERROR) << "Unable to allocate client dll name block.";
    return false;
  }
  *insert_at += block->size();

  uint8* raw_data = block->AllocateData(block->size());
  if (raw_data == NULL) {
    LOG(ERROR) << "Unable to allocate client dll name data.";
    return false;
  }

  base::strlcpy(
      reinterpret_cast<char*>(raw_data), client_dll_.c_str(), block->size());

  dll_name_block_ = block;
  return true;
}

bool Instrumenter::CreateImageImportDescriptorArrayBlock(
    const BlockGraph::Block* original_image_import_descriptor_array,
    RelativeAddress* insert_at) {
  DCHECK(original_image_import_descriptor_array != NULL);
  DCHECK(hint_name_array_block_ != NULL);
  DCHECK(import_address_table_block_ != NULL);
  DCHECK(dll_name_block_ != NULL);
  DCHECK(image_import_descriptor_array_block_ == NULL);

  // The image import descriptor array is an array of IMAGE_IMPORT_DESCRIPTOR
  // structs where the last struct is zeroed-out (i.e. the array length is one
  // more than the actual number of imports). The OriginalFirstThunk member
  // points to a hint name array, the Name member points to the DLL name, and
  // the FirstThunk member points to an import address table.
  // Note: The PE Parser truncates the original_image_import_descriptor_array
  //       size to the first DWORD of the sentinel (i.e., loses about 16 bytes)
  //       So we need to make sure we re-expand/align the array.
  size_t original_block_size = Align(
     original_image_import_descriptor_array->size(),
     sizeof(IMAGE_IMPORT_DESCRIPTOR));
  size_t block_size = original_block_size + sizeof(IMAGE_IMPORT_DESCRIPTOR);
  BlockGraph::Block* block =
      builder().address_space().AddBlock(BlockGraph::DATA_BLOCK,
                                         *insert_at,
                                         block_size,
                                         "image_import_descriptor");
  if (block == NULL) {
    LOG(ERROR) << "Unable to allocate image import descriptor array block";
    return false;
  }
  *insert_at += block->size();

  uint8* data = block->AllocateData(block_size);
  if (data == NULL) {
    LOG(ERROR) << "Unable to allocate image import descriptor array block "
                  "data";
    return false;
  }

  // Copy IMAGE_IMPORT_DESCRIPTOR data from the old one to the new one.
  // TODO(ericdingle): This doesn't copy the references from the old block to
  // the new block (i.e. it is dependent on the fact that the original import
  // table is written into the exact same address space in the new image).
  size_t original_data_size =
      original_block_size - sizeof(IMAGE_IMPORT_DESCRIPTOR);
  memcpy(data, original_image_import_descriptor_array->data(),
         original_data_size);
  // And zero out the rest.
  memset(data + original_data_size, 0, block_size - original_data_size);

  // For the new IMAGE_IMPORT_DESCRIPTOR, add references to the hint name
  // array, the import address table and the dll name.
  size_t offset = original_data_size;
  block->SetReference(
      offset + offsetof(IMAGE_IMPORT_DESCRIPTOR, OriginalFirstThunk),
      BlockGraph::Reference(BlockGraph::RELATIVE_REF,
                            sizeof(RelativeAddress),
                            hint_name_array_block_,
                            0));
  block->SetReference(
      offset + offsetof(IMAGE_IMPORT_DESCRIPTOR, FirstThunk),
      BlockGraph::Reference(BlockGraph::RELATIVE_REF,
                            sizeof(RelativeAddress),
                            import_address_table_block_,
                            0));
  block->SetReference(
      offset + offsetof(IMAGE_IMPORT_DESCRIPTOR, Name),
      BlockGraph::Reference(BlockGraph::RELATIVE_REF,
                            sizeof(RelativeAddress),
                            dll_name_block_,
                            0));

  image_import_descriptor_array_block_ = block;
  return true;
}

bool Instrumenter::InstrumentEntryPoint(size_t entry_hook,
                                        RelativeAddress* insert_at) {
  DCHECK(insert_at != NULL);
  DCHECK_LT(entry_hook, static_cast<size_t>(kEntryHookIndexMax));

  const BlockGraph::Reference& entry_point = builder().entry_point();
  BlockGraph::Block* entry_block = entry_point.referenced();

  // Create a new thunk for the entry point block.
  BlockGraph::Block* thunk_block;
  if (!CreateOneThunk(entry_block,
                      entry_point,
                      entry_hook,
                      insert_at,
                      &thunk_block)) {
    LOG(ERROR) << "Unable to create entry point thunk";
    return false;
  }

  // Create a new entry point reference.
  BlockGraph::Reference new_entry_point(entry_point.type(),
                                        entry_point.size(),
                                        thunk_block,
                                        0);
  builder().set_entry_point(new_entry_point);

  return true;
}

bool Instrumenter::CreateThunks(BlockGraph::Block* block,
                                RelativeAddress* insert_at) {
  // Typedef for the thunk block map. The key is the offset within the callee
  // block and the value is the thunk block that forwards to the callee at that
  // offset.
  typedef std::map<BlockGraph::Offset, BlockGraph::Block*> ThunkBlockMap;
  ThunkBlockMap thunk_block_map;

  // Iterate through all the block's referrers, creating thunks as we go.
  BlockGraph::Block::ReferrerSet referrers = block->referrers();
  BlockGraph::Block::ReferrerSet::const_iterator referrer_it(referrers.begin());
  for (; referrer_it != referrers.end(); ++referrer_it) {
    const BlockGraph::Block::Referrer& referrer = *referrer_it;

    // Skip self-references.
    if (referrer.first == block)
      continue;

    // Get the reference.
    BlockGraph::Reference ref;
    if (!referrer.first->GetReference(referrer.second, &ref)) {
      LOG(ERROR) << "Unable to get reference from referrer";
      return false;
    }

    // Look for the reference in the thunk block map, and only create a new one
    // if it does not already exist.
    BlockGraph::Block* thunk_block = NULL;
    ThunkBlockMap::const_iterator thunk_it = thunk_block_map.find(ref.offset());
    if (thunk_it == thunk_block_map.end()) {
      if (!CreateOneThunk(block, ref, kIndirectPenter, insert_at,
                          &thunk_block)) {
        LOG(ERROR) << "Unable to create thunk block";
        return false;
      }
      thunk_block_map[ref.offset()] = thunk_block;
    } else {
      thunk_block = thunk_it->second;
    }
    DCHECK(thunk_block != NULL);

    // Update the referrer to point to the thunk.
    BlockGraph::Reference new_ref(ref.type(),
                                  ref.size(),
                                  thunk_block,
                                  0);
    referrer.first->SetReference(referrer.second, new_ref);
  }

  return true;
}

bool Instrumenter::CreateOneThunk(BlockGraph::Block* block,
                                  const BlockGraph::Reference& ref,
                                  size_t hook_index,
                                  RelativeAddress* insert_at,
                                  BlockGraph::Block** thunk_block) {
  DCHECK(import_address_table_block_ != NULL);
  DCHECK(block != NULL);
  DCHECK_LT(hook_index, static_cast<size_t>(kEntryHookIndexMax));
  DCHECK(insert_at != NULL);
  DCHECK(thunk_block != NULL);

  // We push the absolute address of the function to be called on the
  // stack, and then we invoke the _indirect_penter function.
  // 6844332211    push  offset (11223344)
  // FF2588776655  jmp   dword ptr [(55667788)]
  static const Thunk kThunk = {
    0x68,
    NULL,
    0x25FF,
    NULL
  };

  // Create the new thunk block, and set its data.
  std::string name = std::string(block->name()) + "_thunk";
  BlockGraph::Block* new_block =
      builder().address_space().AddBlock(BlockGraph::CODE_BLOCK,
                                         *insert_at,
                                         sizeof(Thunk),
                                         name.c_str());
  if (new_block == NULL) {
    LOG(ERROR) << "Unable to allocate thunk block.";
    return false;
  }
  *insert_at += new_block->size();
  new_block->set_data_size(new_block->size());
  new_block->set_data(reinterpret_cast<const uint8*>(&kThunk));

  // Set an absolute reference to the original block at the given offset.
  new_block->SetReference(
      offsetof(Thunk, func_addr),
      BlockGraph::Reference(BlockGraph::ABSOLUTE_REF,
                            sizeof(AbsoluteAddress),
                            block,
                            ref.offset()));

  // Set an absolute reference to the correct instrumentation hook in the call
  // trace client dll import table. This corresponds to the hook_index'th
  // IMAGE_THUNK_DATA entry in the import_address_table_block_.
  new_block->SetReference(
      offsetof(Thunk, hook_addr),
      BlockGraph::Reference(BlockGraph::ABSOLUTE_REF,
                            sizeof(RelativeAddress),
                            import_address_table_block_,
                            hook_index * sizeof(IMAGE_THUNK_DATA)));

  *thunk_block = new_block;
  return true;
}

bool Instrumenter::WriteMetadataSection(const pe::PEFile& input_dll) {
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

bool Instrumenter::CopyResourceSection() {
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
