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

#ifndef SYZYGY_INSTRUMENT_INSTRUMENTER_H_
#define SYZYGY_INSTRUMENT_INSTRUMENTER_H_

#include "syzygy/core/block_graph.h"
#include "syzygy/relink/relinker.h"

class Instrumenter : public RelinkerBase {
 public:
  Instrumenter(const BlockGraph::AddressSpace& original_addr_space,
               BlockGraph* block_graph);
  ~Instrumenter();

  // Copy all sections (except the .relocs section) from the decomposed
  // image to the new image.
  bool CopySections();

  // Copy and append to the import directory such that an import entry for
  // the call trace DLL is added. This requires adding a number of new blocks.
  // The new blocks are added to a new section called ".imports".
  bool AddCallTraceImportDescriptor(
      const BlockGraph::Block* original_image_import_descriptor_array);

  // Instrument code blocks by creating thunks to intercept all references.
  bool InstrumentCodeBlocks(BlockGraph* block_graph);

 private:
  #pragma pack(push)
  #pragma pack(1)
  struct Thunk {
    BYTE push;
    DWORD func_addr;
    WORD jmp;
    DWORD indirect_penter;
  };
  #pragma pack(pop)

  // Create the image import by name block.
  bool CreateImageImportByNameBlock(RelativeAddress* insert_at);

  // Create the hint name array and import address table blocks.
  bool CreateImportAddressTableBlock(RelativeAddress* insert_at);

  // Create the DLL name block.
  bool CreateDllNameBlock(RelativeAddress* insert_at);

  // Create the image import descriptor array block.
  bool CreateImageImportDescriptorArrayBlock(
      const BlockGraph::Block* original_image_import_descriptor_array,
      RelativeAddress* insert_at);

  // Instrument the image's entry point so that the entry point of the image
  // points to at thunk.
  bool InstrumentEntryPoint(RelativeAddress* insert_at);

  // Create thunks for all referrers to @p block.
  bool CreateThunks(BlockGraph::Block* block,
                    RelativeAddress* insert_at);

  // Create a thunk for @p block using reference @p ref. This method is
  // responsible for updating @p insert_at.
  bool CreateOneThunk(BlockGraph::Block* block,
                      const BlockGraph::Reference& ref,
                      RelativeAddress* insert_at,
                      BlockGraph::Block** thunk_block);

  // Blocks created while updating the import directory.
  BlockGraph::Block* image_import_by_name_block_;
  BlockGraph::Block* hint_name_array_block_;
  BlockGraph::Block* import_address_table_block_;
  BlockGraph::Block* dll_name_block_;
  BlockGraph::Block* image_import_descriptor_array_block_;
};

#endif  // SYZYGY_INSTRUMENT_INSTRUMENTER_H_
