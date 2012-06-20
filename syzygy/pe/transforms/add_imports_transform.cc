// Copyright 2012 Google Inc.
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
//
// The AddImportsTransform can be summed up as follows:
//
// (1) Make sure that the imports and IAT data directories exist.
// (2) For each module to be imported, either find it in the import data
//     directory, or add a new entry. The entry is always added to the end
//     of the list so that module indices are strictly increasing, allowing
//     the transform to be stacked. Adding a new entry also causes the creation
//     of two new blocks (for the INT and the module filename), as well as
//     extends the existing IAT block.
// (3) For each symbol to be imported, either find it in the module's INT/IAT,
//     or add a new entry. Adding a new entry causes the existing INT and IAT
//     blocks to be extended. The new entry is always added to the end of the
//     module's table so that symbol indices are strictly increasing, again
//     allowing the transform to be stacked. Rather than allocating a new
//     block for the name of the symbol we reuse the module filename block and
//     insert the name of the symbol immediately prior to the module filename.
//     This ensures that all of the strings for a module are laid out together,
//     mimicking the observed behaviour of the MS linker.
//
// We give a quick rundown of the PE structures involved, their layout in
// typical PE images and how we parse them into blocks. This helps visualize
// the work performed by the transform.
//
// headers:
//
//   ...
//   nt_headers
//     DataDirectory
//       ...
//       IMAGE_DIRECTORY_ENTRY_IMPORT -> IMAGE_IMPORT_DESCRIPTOR array
//       ...
//       IMAGE_DIRECTORY_ENTRY_IAT -> Import Address Table
//       ...
//
// .rdata:
//
//   Import Address Table
//   NOTE: All entries in this table must remain consecutive as it is also
//       exposed directly via a data directory. At runtime these get patched to
//       point to the actual functions rather than the thunks. This is stored
//       at the very beginning of .rdata and parsed as a single Block.
//     IAT[0,0] -> thunk[0, 0]  \
//     ...                      |
//     IAT[0,j] -> thunk[0, j]  |
//     NULL terminator          |
//     ...                      |- Block
//     IAT[i,0] -> thunk[i, 0]  |
//     ...                      |
//     IAT[i,k] -> thunk[i, k]  |
//     NULL terminator          /
//
//   ... whole bunch of other .rdata here ...
//   NOTE: The following are stored at the end of .rdata, in the order
//       shown (they are not quite last, being immediately prior to export
//       information).
//
//   IMAGE_IMPORT_DESCRIPTOR array  \
//     IMAGE_IMPORT_DESCRIPTOR[0]   |
//       -> module_name[0]          |
//       -> INT[0,0]                |
//       -> IAT[0,0]                |
//     ...                          |- Block
//     IMAGE_IMPORT_DESCRIPTOR[i]   |
//       -> module_name[i]          |
//       -> INT[i,0]                |
//       -> IAT[i,0]                |
//     NULL terminator              /
//
//   Import Name Table (also known as Hint Name Array)
//   NOTE: The entries for each module need be consecutive. While the entries
//       across all modules are consecutive, they need not be.
//     INT[0,0] -> thunk[0, 0]  \
//     ...                      |_ Block
//     INT[0,j] -> thunk[0, j]  |
//     NULL terminator          /
//     ...
//     INT[i,0] -> thunk[i, 0]  \
//     ...                      |_ Block
//     INT[i,k] -> thunk[i, k]  |
//     NULL terminator          /
//
//   Array of names
//   NOTE: These are consecutive in typical PE images (with the layout shown
//       below), but they need not be.
//     thunk[0, 0]     } Block
//     ...
//     thunk[0, j]     } Block
//     module_name[0]  } Block
//     ...
//     thunk[i, 0]     } Block
//     ...
//     thunk[i, k]     } Block
//     module_name[i]  } Block

#include "syzygy/pe/transforms/add_imports_transform.h"

#include "base/string_util.h"
#include "base/stringprintf.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/common/align.h"
#include "syzygy/pe/pe_utils.h"

namespace pe {
namespace transforms {

using block_graph::BlockGraph;
using block_graph::ConstTypedBlock;
using block_graph::TypedBlock;
using core::RelativeAddress;

// A simple struct that can be used to let us access strings using TypedBlock.
struct StringStruct {
  const char string[1];
};

typedef BlockGraph::Offset Offset;
typedef TypedBlock<IMAGE_DOS_HEADER> DosHeader;
typedef TypedBlock<IMAGE_IMPORT_BY_NAME> ImageImportByName;
typedef TypedBlock<IMAGE_IMPORT_DESCRIPTOR> ImageImportDescriptor;
typedef TypedBlock<IMAGE_NT_HEADERS> NtHeaders;
typedef TypedBlock<IMAGE_THUNK_DATA32> ImageThunkData32;
typedef TypedBlock<StringStruct> String;

namespace {

const size_t kPtrSize = sizeof(core::RelativeAddress);

// Looks up the given data directory and checks that it points to valid data.
// If it doesn't, it will allocate a block with the given name and size.
bool EnsureDataDirectoryExists(size_t directory_index,
                               const char* block_name,
                               size_t block_size,
                               BlockGraph* block_graph,
                               BlockGraph::Block* nt_headers_block) {
  DCHECK(block_name != NULL);
  DCHECK_LT(directory_index,
            static_cast<size_t>(IMAGE_NUMBEROF_DIRECTORY_ENTRIES));
  DCHECK_GT(block_size, 0u);
  DCHECK(block_graph != NULL);
  DCHECK(nt_headers_block != NULL);

  NtHeaders nt_headers;
  if (!nt_headers.Init(0, nt_headers_block)) {
    LOG(ERROR) << "Unable to cast NT headers.";
    return false;
  }

  IMAGE_DATA_DIRECTORY* data_directory =
      nt_headers->OptionalHeader.DataDirectory + directory_index;

  // No entry? Then make a zero initialized block that is stored in .rdata,
  // where all of these structures live.
  if (!nt_headers.HasReference(data_directory->VirtualAddress)) {
    BlockGraph::Section* section = block_graph->FindOrAddSection(
        kReadOnlyDataSectionName, kReadOnlyDataCharacteristics);
    DCHECK(section != NULL);

    BlockGraph::Block* block = block_graph->AddBlock(
        BlockGraph::DATA_BLOCK, block_size, block_name);
    DCHECK(block != NULL);
    block->set_section(section->id());
    block->set_attribute(BlockGraph::PE_PARSED);

    // We need to actually allocate the data so that future TypedBlock
    // dereferences will work.
    if (block->AllocateData(block_size) == NULL) {
      LOG(ERROR) << "Failed to allocate block data.";
      return false;
    }

    // Hook it up to the NT header.
    nt_headers.SetReference(BlockGraph::RELATIVE_REF,
                            data_directory->VirtualAddress,
                            block,
                            0, 0);
    data_directory->Size = block_size;
  }

  return true;
}

// Finds or creates an Image Import Descriptor block for the given library.
// Returns true on success, false otherwise.
bool FindOrAddImageImportDescriptor(const char* module_name,
                                    BlockGraph* block_graph,
                                    BlockGraph::Block* iida_block,
                                    BlockGraph::Block* iat_block,
                                    ImageImportDescriptor* iid,
                                    bool* added) {
  DCHECK(module_name != NULL);
  DCHECK(block_graph != NULL);
  DCHECK(iida_block != NULL);
  DCHECK(iat_block != NULL);
  DCHECK(iid != NULL);
  DCHECK(added != NULL);

  *added = false;

  ImageImportDescriptor iida;
  if (!iida.Init(0, iida_block)) {
    LOG(ERROR) << "Unable to cast Image Import Descriptor.";
    return false;
  }

  // The array is NULL terminated with a potentially incomplete descriptor so
  // we can't use ElementCount - 1.
  size_t descriptor_count =
      (common::AlignUp(iida_block->size(), sizeof(IMAGE_IMPORT_DESCRIPTOR)) /
       sizeof(IMAGE_IMPORT_DESCRIPTOR)) - 1;

  for (size_t iida_index = 0; iida_index < descriptor_count; ++iida_index) {
    String dll_name;
    if (!iida.Dereference(iida[iida_index].Name, &dll_name)) {
      LOG(ERROR) << "Unable to dereference DLL name.";
      return false;
    }

    size_t max_len = dll_name.block()->size() - dll_name.offset();
    if (base::strncasecmp(dll_name->string, module_name, max_len) == 0) {
      // This should never fail, but we sanity check it nonetheless.
      bool result = iid->Init(iida.OffsetOf(iida[iida_index]), iida.block());
      DCHECK(result);
      return true;
    }
  }

  // Create room for the new descriptor, which we'll tack on to the end of the
  // array, but before the NULL terminator. We use 'InsertData' so that all
  // labels are patched up.
  Offset new_iid_offset = descriptor_count * sizeof(IMAGE_IMPORT_DESCRIPTOR);
  iida_block->InsertData(
      new_iid_offset, sizeof(IMAGE_IMPORT_DESCRIPTOR), true);
  iida_block->SetLabel(
      new_iid_offset,
      base::StringPrintf("Image Import Descriptor: %s", module_name),
      BlockGraph::DATA_LABEL);

  // We expect the new entry to be dereferencable using iida[descriptor_count].
  DCHECK_GT(iida.ElementCount(), descriptor_count);

  // Create the various child structures that will be pointed to by the
  // import descriptor. The INT block and the IAT block are NULL terminated
  // lists of pointers, and the terminating NULL is allocated. We don't yet
  // allocate a block to hold the import names, deferring that for later.
  BlockGraph::SectionId iida_section_id = iida_block->section();
  size_t name_len = strlen(module_name);
  BlockGraph::Block* int_block = block_graph->AddBlock(
      BlockGraph::DATA_BLOCK, kPtrSize,
      base::StringPrintf("Import Name Table: %s", module_name));
  BlockGraph::Block* dll_name_block = block_graph->AddBlock(
      BlockGraph::DATA_BLOCK, name_len + 1,
      base::StringPrintf("Import Name: %s", module_name));
  if (int_block == NULL || dll_name_block == NULL) {
    LOG(ERROR) << "Unable to create blocks for Image Import Descriptor.";
    return false;
  }

  // NOTE: If PEParser was modified to parse a single INT block, we could be
  //     extending/reusing it rather than creating a new INT per module.
  int_block->set_section(iida_section_id);
  int_block->set_attribute(BlockGraph::PE_PARSED);
  int_block->SetLabel(
      0,
      StringPrintf("%s INT: NULL entry", module_name),
      BlockGraph::DATA_LABEL);
  if (int_block->AllocateData(kPtrSize) == NULL) {
    LOG(ERROR) << "Failed to allocate block data.";
    return false;
  }

  // We use the DLL name block and extend it. This keeps things well ordered
  // when writing back the image using a canonical ordering.
  dll_name_block->set_section(iida_section_id);
  dll_name_block->set_attribute(BlockGraph::PE_PARSED);
  if (dll_name_block->CopyData(name_len + 1, module_name) == NULL) {
    LOG(ERROR) << "Failed to copy block data.";
    return false;
  }

  // Add another NULL entry to the IAT block, but only if it does not already
  // consist of a single NULL entry (meaning it was just created). We are purely
  // extending this block, so no need to use the data insertion functions.
  Offset iat_offset = 0;
  if (iat_block->size() != kPtrSize) {
    iat_offset = iat_block->size();
    size_t iat_size = iat_offset + kPtrSize;
    iat_block->set_size(iat_size);
    iat_block->ResizeData(iat_size);
    DCHECK_EQ(iat_size, iat_block->size());
    DCHECK_EQ(iat_size, iat_block->data_size());
  }

  // Add a label for debugging purposes.
  iat_block->SetLabel(iat_offset,
                      StringPrintf("%s: NULL thunk", module_name),
                      BlockGraph::DATA_LABEL);

  // Hook up these blocks.
  iida.SetReference(BlockGraph::RELATIVE_REF,
                    iida[descriptor_count].OriginalFirstThunk, int_block, 0, 0);
  iida.SetReference(BlockGraph::RELATIVE_REF,
                    iida[descriptor_count].FirstThunk, iat_block, iat_offset,
                    iat_offset);
  iida.SetReference(BlockGraph::RELATIVE_REF,
                    iida[descriptor_count].Name, dll_name_block, 0, 0);

  // Finally, return the descriptor.
  if (!iid->Init(new_iid_offset, iida_block)) {
    LOG(ERROR) << "Unable to cast Image Import Descriptor.";
    return false;
  }

  *added = true;

  return true;
}

// Finds or adds an imported symbol to the given module (represented by its
// import descriptor). Returns true on success, false otherwise. On success
// returns a reference to the module's IAT entry. New entries are always added
// to the end of the table so as not to invalidate any other unlinked references
// (not part of the BlockGraph, so unable to be patched up) into the table.
bool FindOrAddImportedSymbol(const char* symbol_name,
                             const ImageImportDescriptor& iid,
                             BlockGraph* block_graph,
                             BlockGraph::Block* iat_block,
                             size_t* iat_index,
                             bool* added) {
  DCHECK(symbol_name != NULL);
  DCHECK(block_graph != NULL);
  DCHECK(iat_block != NULL);
  DCHECK(iat_index != NULL);
  DCHECK(added != NULL);

  *added = false;

  TypedBlock<IMAGE_IMPORT_BY_NAME*> hna, iat;
  if (!iid.Dereference(iid->OriginalFirstThunk, &hna) ||
      !iid.Dereference(iid->FirstThunk, &iat)) {
    LOG(ERROR) << "Unable to dereference OriginalFirstThunk/FirstThunk.";
    return false;
  }

  // Loop through the existing imports and see if we can't find a match. If so,
  // we don't need to import the symbol as it is already imported. The array is
  // NULL terminated so we loop through all elements except for the last one.
  size_t i = 0;
  for (; i < hna.ElementCount() && i < iat.ElementCount(); ++i) {
    ConstTypedBlock<IMAGE_THUNK_DATA32> thunk;
    if (!thunk.Init(hna.OffsetOf(hna[i]), hna.block())) {
      LOG(ERROR) << "Unable to dereference IMAGE_THUNK_DATA32.";
      return false;
    }

    // Is this an ordinal import? Skip it, as we have no way of
    // knowing the actual name of the symbol.
    if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
      continue;

    // Have no reference? Then terminate the iteration.
    if (!thunk.HasReference(thunk->u1.AddressOfData)) {
      // We sanity check that the actual data is null.
      DCHECK_EQ(0u, thunk->u1.AddressOfData);
      break;
    }

    // Otherwise this should point to an IMAGE_IMPORT_BY_NAME structure.
    ImageImportByName iibn;
    if (!hna.Dereference(hna[i], &iibn)) {
      LOG(ERROR) << "Unable to dereference IMAGE_IMPORT_BY_NAME.";
      return false;
    }

    // Check to see if this symbol matches that of the current image import
    // by name.
    size_t max_len = iibn.block()->data_size() - iibn.offset() -
        offsetof(IMAGE_IMPORT_BY_NAME, Name);
    const char* import_name = reinterpret_cast<const char*>(iibn->Name);
    if (::strncmp(import_name, symbol_name, max_len) == 0) {
      *iat_index = i;
      return true;
    }
  }

  // Figure out how large the data needs to be to hold the name of this exported
  // symbol.  The IMAGE_IMPORT_BY_NAME struct has a WORD ordinal and a variable
  // sized field for the null-terminated function name. Each entry should be
  // WORD aligned, and will be referenced from the import address table and the
  // import name table.
  size_t symbol_name_len = strlen(symbol_name);
  size_t iibn_size = sizeof(WORD) + common::AlignUp(symbol_name_len + 1,
                                                    sizeof(WORD));

  // Get the DLL name. We will be inserting the IIBN entry to the block
  // containing it immediately prior to the DLL name.
  String dll_name;
  if (!iid.Dereference(iid->Name, &dll_name)) {
    LOG(ERROR) << "Unable to dereference DLL name.";
    return false;
  }
  Offset iibn_offset = dll_name.offset();
  dll_name.block()->InsertData(iibn_offset, iibn_size, true);

  // Populate the import struct.
  TypedBlock<IMAGE_IMPORT_BY_NAME> iibn;
  if (!iibn.InitWithSize(iibn_offset, iibn_size, dll_name.block())) {
    LOG(ERROR) << "Unable to dereference new IMAGE_IMPORT_BY_NAME.";
    return false;
  }
  iibn->Hint = 0;
  base::strlcpy(reinterpret_cast<char*>(iibn->Name), symbol_name,
                symbol_name_len + 1);

  // Make room in the INT and the IAT for the new symbol. We place it
  // after the last entry for this module.
  Offset int_offset = hna.OffsetOf(hna[i]);
  Offset iat_offset = iat.OffsetOf(iat[i]);
  // We're pointed at the terminating zero. The position we're pointing at can
  // be the destination for references (in the normal case where someone is
  // using the import). However, in the special case where the IAT and the INT
  // are empty, our slot may also be pointed at by the import descriptor.
  // If we were to insert data at this position, we'd push the import
  // descriptor's pointer forward, past our new entry. To avoid this, we insert
  // the new data after the terminating zero we're pointing at, then usurp the
  // previously terminating zero for our entry.
  hna.block()->InsertData(int_offset + kPtrSize, kPtrSize, true);
  iat.block()->InsertData(iat_offset + kPtrSize, kPtrSize, true);

  // Because of the usurping mentioned above, we manually move any existing
  // labels.
  BlockGraph::Label label;
  if (hna.block()->GetLabel(int_offset, &label)) {
    hna.block()->RemoveLabel(int_offset);
    hna.block()->SetLabel(int_offset + kPtrSize, label);
  }
  if (iat.block()->GetLabel(iat_offset, &label)) {
    iat.block()->RemoveLabel(iat_offset);
    iat.block()->SetLabel(iat_offset + kPtrSize, label);
  }

  // Add the new labels. We have to get the module_name at this point
  // because it may have been moved with our insertions above.
  String module_name;
  if (!iid.Dereference(iid->Name, &module_name)) {
    LOG(ERROR) << "Unable to dereference import name.";
    return false;
  }
  hna.block()->SetLabel(
      int_offset,
      StringPrintf("%s INT: %s", module_name->string, symbol_name),
      BlockGraph::DATA_LABEL);
  iat.block()->SetLabel(
      iat_offset,
      StringPrintf("%s IAT: %s", module_name->string, symbol_name),
      BlockGraph::DATA_LABEL);

  // Hook up the newly created IMAGE_IMPORT_BY_NAME to both tables.
  BlockGraph::Reference iibn_ref(BlockGraph::RELATIVE_REF,
                                 kPtrSize,
                                 iibn.block(),
                                 iibn.offset(),
                                 iibn.offset());
  hna.block()->SetReference(int_offset, iibn_ref);
  iat.block()->SetReference(iat_offset, iibn_ref);

  // Return the reference to the IAT entry for the newly imported symbol.
  *iat_index = i;
  *added = true;

  return true;
}

}  // namespace


const char AddImportsTransform::kTransformName[] = "AddImportsTransform";

AddImportsTransform::AddImportsTransform()
    : modules_added_(0), symbols_added_(0) {
}

bool AddImportsTransform::TransformBlockGraph(
    BlockGraph* block_graph, BlockGraph::Block* dos_header_block) {
  DCHECK(block_graph != NULL);
  DCHECK(dos_header_block != NULL);

  modules_added_ = 0;
  symbols_added_ = 0;

  DosHeader dos_header;
  NtHeaders nt_headers;
  if (!dos_header.Init(0, dos_header_block) ||
      !dos_header.Dereference(dos_header->e_lfanew, &nt_headers)) {
    LOG(ERROR) << "Unable to cast image headers.";
    return false;
  }

  // Get the block containing the image import directory. In general it's not
  // safe to keep around a pointer into a TypedBlock, but we won't be resizing
  // or reallocating the data within nt_headers so this is safe.
  if (!EnsureDataDirectoryExists(IMAGE_DIRECTORY_ENTRY_IMPORT,
                                 "Image Import Descriptor Array",
                                 sizeof(IMAGE_IMPORT_DESCRIPTOR),
                                 block_graph,
                                 nt_headers.block())) {
    LOG(ERROR) << "Failed to create Image Import Descriptor Array.";
    return false;
  }
  IMAGE_DATA_DIRECTORY* import_directory =
      nt_headers->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_IMPORT;
  DCHECK(nt_headers.HasReference(import_directory->VirtualAddress));

  ImageImportDescriptor image_import_descriptor;
  if (!nt_headers.Dereference(import_directory->VirtualAddress,
                              &image_import_descriptor)) {
    // This could happen if the image import descriptor array is empty, and
    // terminated by a *partial* null entry. However, we've not yet seen that.
    LOG(ERROR) << "Failed to dereference Image Import Descriptor Array.";
    return false;
  }

  // We expect the image import descriptor to have been parsed as its own block,
  // so the reference needs to be to offset 0.
  if (image_import_descriptor.offset() != 0) {
    LOG(ERROR) << "Unexpected offset on Image Import Descriptor.";
    return false;
  }

  image_import_descriptor_block_ = image_import_descriptor.block();

  // Similarly, get the block containing the IAT.
  if (!EnsureDataDirectoryExists(IMAGE_DIRECTORY_ENTRY_IAT,
                                 "Import Address Table",
                                 kPtrSize,
                                 block_graph,
                                 nt_headers.block())) {
    LOG(ERROR) << "Failed to create Import Address Table.";
    return false;
  }
  IMAGE_DATA_DIRECTORY* iat_directory =
      nt_headers->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_IAT;
  DCHECK(nt_headers.HasReference(iat_directory->VirtualAddress));
  TypedBlock<RelativeAddress> iat;
  if (!nt_headers.Dereference(iat_directory->VirtualAddress, &iat)) {
    LOG(ERROR) << "Failed to dereference Import Address Table.";
    return false;
  }

  // We expect the import address table to have been parsed as its own block,
  // so the reference needs to be to offset 0.
  if (iat.offset() != 0) {
    LOG(ERROR) << "Unexpected offset on Image Address Table";
    return false;
  }
  import_address_table_block_ = iat.block();

  // Handle each library individually.
  for (size_t i = 0; i < imported_modules_.size(); ++i) {
    ImportedModule* module = imported_modules_[i];
    if (module->size() == 0)
      continue;

    // First find or create an entry for this module in the Image Import
    // Descriptor Array.
    ImageImportDescriptor iid;
    bool module_added = false;
    if (!FindOrAddImageImportDescriptor(module->name().c_str(),
                                        block_graph,
                                        image_import_descriptor_block_,
                                        import_address_table_block_,
                                        &iid,
                                        &module_added)) {
      LOG(ERROR) << "Failed to find or import module.";
      return false;
    }
    modules_added_ += module_added;

    // This should always succeed as iid was initialized earlier.
    bool inited = module->import_descriptor_.Init(iid.offset(), iid.block());
    DCHECK(inited);

    for (size_t j = 0; j < module->size(); ++j) {
      ImportedModule::Symbol& symbol = module->symbols_[j];

      // Now, for each symbol get the offset of the IAT entry. This will create
      // the entry (and all accompanying structures) if necessary.
      size_t symbol_index = ImportedModule::kInvalidIndex;
      bool symbol_added = false;
      if (!FindOrAddImportedSymbol(symbol.name.c_str(),
                                   iid,
                                   block_graph,
                                   import_address_table_block_,
                                   &symbol_index,
                                   &symbol_added)) {
        LOG(ERROR) << "Failed to find or import symbol.";
        return false;
      }
      symbols_added_ += symbol_added;
      symbol.index = symbol_index;
    }
  }

  // Update the data directory sizes.
  import_directory->Size = image_import_descriptor_block_->size();
  iat_directory->Size = import_address_table_block_->size();

  return true;
}

const size_t AddImportsTransform::ImportedModule::kInvalidIndex = -1;

size_t AddImportsTransform::ImportedModule::AddSymbol(const char* symbol_name) {
  Symbol symbol = {symbol_name, kInvalidIndex};
  symbols_.push_back(symbol);
  return symbols_.size() - 1;
}

bool AddImportsTransform::ImportedModule::GetSymbolReference(
    size_t index, BlockGraph::Reference* abs_reference) const {
  DCHECK_LT(index, symbols_.size());
  DCHECK(abs_reference != NULL);

  size_t symbol_index = symbols_[index].index;
  if (import_descriptor_.block() == NULL || symbol_index == kInvalidIndex) {
    LOG(ERROR) << "Called GetAbsReference on an unitialized ImportedSymbol.";
    return false;
  }

  ImageThunkData32 thunks;
  if (!import_descriptor_.Dereference(import_descriptor_->FirstThunk,
                                      &thunks)) {
    LOG(ERROR) << "Unable to dereference IMAGE_THUNK_DATA32.";
    return false;
  }

  if (symbol_index >= thunks.ElementCount()) {
    LOG(ERROR) << "Invalid symbol_index for IAT.";
    return false;
  }

  Offset offset = thunks.OffsetOf(thunks[symbol_index].u1.AddressOfData);
  *abs_reference = BlockGraph::Reference(
      BlockGraph::ABSOLUTE_REF, kPtrSize, thunks.block(), offset, offset);

  return true;
}

}  // namespace transforms
}  // namespace pe
