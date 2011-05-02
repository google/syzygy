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
#include "syzygy/pe/pe_file_writer.h"
#include "syzygy/pe/decomposer.h"

using core::AbsoluteAddress;
using core::RelativeAddress;
using pe::PEFileWriter;
using pe::Decomposer;

namespace {

const char* kCallTraceDllName = "call_trace.dll";
const char* kIndirectPenterName = "_indirect_penter";

// TODO(rogerm): this functionality is duplicated!  Consolidate!
size_t Align(size_t value, size_t alignment) {
  size_t expanded = value + alignment - 1;
  return expanded - (expanded % alignment);
}

// TODO(rogerm): this functionality is duplicated!  Consolidate!
size_t WordAlign(size_t value) {
  return Align(value, sizeof(WORD));
}

}  // namespace

Instrumenter::Instrumenter(const BlockGraph::AddressSpace& original_addr_space,
                           BlockGraph* block_graph)
    : RelinkerBase(original_addr_space, block_graph),
      image_import_by_name_block_(NULL),
      hint_name_array_block_(NULL),
      import_address_table_block_(NULL),
      dll_name_block_(NULL),
      image_import_descriptor_array_block_(NULL) {
}

Instrumenter::~Instrumenter() {
}

bool Instrumenter::CopySections() {
  // Copy the sections from the decomposed image to the new one, save for the
  // .relocs section.
  for (size_t i = 0; i < original_num_sections() - 1; ++i) {
    const IMAGE_SECTION_HEADER& section = original_sections()[i];
    if (!CopySection(section)) {
      LOG(ERROR) << "Unable to copy section";
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
  if (!CreateImportAddressTableBlock(&insert_at)) {
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

  // Update the data directory import entry.
  if (!builder().SetDataDirectoryEntry(IMAGE_DIRECTORY_ENTRY_IMPORT,
                                       image_import_descriptor_array_block_)) {
    LOG(ERROR) << "Unable to set data directory entry";
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

bool Instrumenter::InstrumentCodeBlocks(BlockGraph* block_graph) {
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
  if (!InstrumentEntryPoint(&insert_at)) {
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

  // The image import by name array contains an IMAGE_IMPORT_BY_NAME for each
  // function invoked in the call trace DLL (just _indirect_penter in our case).
  // The IMAGE_IMPORT_BY_NAME struct has a WORD ordinal and a variable sized
  // field for the null-terminated function name.
  uint32 size = sizeof(WORD) + WordAlign(strlen(kIndirectPenterName) + 1);
  BlockGraph::Block* block =
      builder().address_space().AddBlock(BlockGraph::DATA_BLOCK,
                                         *insert_at,
                                         size,
                                         "image_import_by_name");
  if (block == NULL) {
    LOG(ERROR) << "Unable to allocate image import by name block";
    return false;
  }
  *insert_at += block->size();

  IMAGE_IMPORT_BY_NAME* image_import_by_name =
      reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(block->AllocateData(size));
  if (image_import_by_name == NULL) {
    LOG(ERROR) << "Unable to allocate image import by name block data";
    return false;
  }
  image_import_by_name->Hint = 0;
  strncpy(reinterpret_cast<char*>(&image_import_by_name->Name[0]),
         kIndirectPenterName,
         size - sizeof(WORD));

  image_import_by_name_block_ = block;
  return true;
}

bool Instrumenter::CreateImportAddressTableBlock(RelativeAddress* insert_at) {
  DCHECK(image_import_by_name_block_ != NULL);
  DCHECK(hint_name_array_block_ == NULL);
  DCHECK(import_address_table_block_ == NULL);

  // The hint name array and import address table are null-terminated arrays of
  // IMAGE_THUNK_DATA. Each IMAGE_THUNK_DATA entry points to an
  // IMAGE_IMPORT_BY_NAME entry in the image import by name array.
  static const IMAGE_THUNK_DATA kImageThunkDataArray[] = {
    NULL,  // This will be overwritten by the reference.
    NULL
  };

  // Create the hint name array block.
  BlockGraph::Block* block =
      builder().address_space().AddBlock(BlockGraph::DATA_BLOCK,
                                         *insert_at,
                                         sizeof(kImageThunkDataArray),
                                         "hint_name_array");
  if (block == NULL) {
    LOG(ERROR) << "Unable to allocate hint name array block";
    return false;
  }
  *insert_at += block->size();

  block->set_data_size(block->size());
  block->set_data(reinterpret_cast<const uint8*>(kImageThunkDataArray));

  // Create a reference to offset 0 of the image import by name block.
  BlockGraph::Reference image_import_by_name_ref(BlockGraph::RELATIVE_REF,
                                                 sizeof(RelativeAddress),
                                                 image_import_by_name_block_,
                                                 0);
  block->SetReference(0, image_import_by_name_ref);

  hint_name_array_block_ = block;

  // Create the import addres table block.
  block = builder().address_space().AddBlock(BlockGraph::DATA_BLOCK,
                                             *insert_at,
                                             sizeof(kImageThunkDataArray),
                                             "import_address_table");
  if (block == NULL) {
    LOG(ERROR) << "Unable to allocate import address table block";
    return false;
  }
  *insert_at += block->size();

  block->set_data_size(block->size());
  block->set_data(reinterpret_cast<const uint8*>(kImageThunkDataArray));
  block->SetReference(0, image_import_by_name_ref);

  import_address_table_block_ = block;
  return true;
}

bool Instrumenter::CreateDllNameBlock(RelativeAddress* insert_at) {
  DCHECK(dll_name_block_ == NULL);

  // Create the DLL name block with room for a null character.
  BlockGraph::Block* block =
      builder().address_space().AddBlock(BlockGraph::DATA_BLOCK,
                                         *insert_at,
                                         strlen(kCallTraceDllName) + 1,
                                         "dll_name");
  if (block == NULL) {
    LOG(ERROR) << "Unable to allocate dll name block";
    return false;
  }
  *insert_at += block->size();

  block->set_data_size(block->size());
  block->set_data(reinterpret_cast<const uint8*>(kCallTraceDllName));

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

bool Instrumenter::InstrumentEntryPoint(RelativeAddress* insert_at) {
  const BlockGraph::Reference& entry_point = builder().entry_point();
  BlockGraph::Block* entry_block = entry_point.referenced();

  // Create a new thunk for the entry point block.
  BlockGraph::Block* thunk_block;
  if (!CreateOneThunk(entry_block,
                      entry_point,
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
      if (!CreateOneThunk(block, ref, insert_at, &thunk_block)) {
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
                                  RelativeAddress* insert_at,
                                  BlockGraph::Block** thunk_block) {
  DCHECK(import_address_table_block_ != NULL);
  DCHECK(block != NULL);
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
    LOG(ERROR) << "Unable to allocate thunk block";
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

  // Set an absolute reference to the indirect penter function in the call
  // trace dll import which is in offset 0 of the import address table block.
  new_block->SetReference(
      offsetof(Thunk, indirect_penter),
      BlockGraph::Reference(BlockGraph::ABSOLUTE_REF,
                            sizeof(RelativeAddress),
                            import_address_table_block_,
                            0));

  *thunk_block = new_block;
  return true;
}

bool Instrumenter::Instrument(const FilePath& input_dll_path,
                              const FilePath& output_dll_path) {
  DCHECK(!input_dll_path.empty());
  DCHECK(!output_dll_path.empty());

  // Read and decompose the input image for starters.
  pe::PEFile input_dll;
  if (!input_dll.Init(input_dll_path)) {
    LOG(ERROR) << "Unable to read " << input_dll_path.value() << ".";
    return false;
  }

  Decomposer decomposer(input_dll, input_dll_path);
  Decomposer::DecomposedImage decomposed;
  if (!decomposer.Decompose(&decomposed, NULL)) {
    LOG(ERROR) << "Unable to decompose " << input_dll_path.value() << ".";
    return false;
  }

  // Construct and initialize our instrumenter.
  Instrumenter instrumenter(decomposed.address_space, &decomposed.image);
  if (!instrumenter.Initialize(decomposed.header.nt_headers)) {
    LOG(ERROR) << "Unable to initialize instrumenter.";
    return false;
  }

  // Copy the sections and the data directory.
  if (!instrumenter.CopySections()) {
    LOG(ERROR) << "Unable to copy sections.";
    return false;
  }

  if (!instrumenter.CopyDataDirectory(decomposed.header)) {
    LOG(ERROR) << "Unable to copy the input image's data directory.";
    return false;
  }

  // Instrument the binary.
  if (!instrumenter.AddCallTraceImportDescriptor(
      decomposed.header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT])) {
    LOG(ERROR) << "Unable to add call trace import.";
    return false;
  }
  if (!instrumenter.InstrumentCodeBlocks(&decomposed.image)) {
    LOG(ERROR) << "Unable to instrument code blocks.";
    return false;
  }

  // Finalize the headers and write the image.
  if (!instrumenter.FinalizeImageHeaders(decomposed.header)) {
    LOG(ERROR) << "Unable to finalize image headers.";
  }
  if (!instrumenter.WriteImage(output_dll_path)) {
    LOG(ERROR) << "Unable to write " << output_dll_path.value();
    return false;
  }

  return true;
}
