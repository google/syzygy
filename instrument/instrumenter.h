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

#ifndef SYZYGY_INSTRUMENT_INSTRUMENTER_H_
#define SYZYGY_INSTRUMENT_INSTRUMENTER_H_

#include "syzygy/core/block_graph.h"
#include "syzygy/relink/relinker.h"

class Instrumenter : public relink::RelinkerBase {
 public:
  Instrumenter();

  // Change the client DLL to which instrumented binaries will be bound.
  void set_client_dll(const char* client_dll);

  // Wrapper function to instrument an input dll to an output dll.
  bool Instrument(const FilePath& input_dll_path,
                  const FilePath& output_dll_path);

  // The pre-defined call trace client DLLs. By default the ETW version will
  // be used.
  static const char* const kCallTraceClientDllEtw;
  static const char* const kCallTraceClientDllRpc;

 private:
  // Copy all sections (except the .relocs and .rsrc sections) from the
  // decomposed image to the new image.
  bool CopySections();

  // Copy and append to the import directory such that an import entry for
  // the call trace DLL is added. This requires adding a number of new blocks.
  // The new blocks are added to a new section called ".imports".
  bool AddCallTraceImportDescriptor(
      const BlockGraph::Block* original_image_import_descriptor_array);

  // Instrument code blocks by creating thunks to intercept all references.
  bool InstrumentCodeBlocks(BlockGraph* block_graph, size_t entry_hook_index);

  #pragma pack(push)
  #pragma pack(1)
  struct Thunk {
    BYTE push;
    DWORD func_addr;  // The real function to invoke.
    WORD jmp;
    DWORD hook_addr;  // The instrumentation hook that gets called beforehand.
  };
  #pragma pack(pop)

  // Create the image import by name block.
  bool CreateImageImportByNameBlock(RelativeAddress* insert_at);

  // Create both the hint name array and import address table blocks.
  bool CreateImportAddressTableBlocks(RelativeAddress* insert_at);

  // Create a single address table block.
  bool CreateImportAddressTableBlock(const char* name,
                                     RelativeAddress* insert_at,
                                     BlockGraph::Block** block);

  // Create the DLL name block.
  bool CreateDllNameBlock(RelativeAddress* insert_at);

  // Create the image import descriptor array block.
  bool CreateImageImportDescriptorArrayBlock(
      const BlockGraph::Block* original_image_import_descriptor_array,
      RelativeAddress* insert_at);

  // Instrument the image's entry point so that the entry point of the image
  // points to at thunk.
  bool InstrumentEntryPoint(size_t entry_hook, RelativeAddress* insert_at);

  // Create thunks for all referrers to @p block.
  bool CreateThunks(BlockGraph::Block* block,
                    RelativeAddress* insert_at);

  // Create a thunk for @p block using reference @p ref. This method is
  // responsible for updating @p insert_at.
  bool CreateOneThunk(BlockGraph::Block* block,
                      const BlockGraph::Reference& ref,
                      size_t hook_index,
                      RelativeAddress* insert_at,
                      BlockGraph::Block** thunk_block);

  // Creates a read-only data section containing metadata about the toolchain
  // and the input module.
  bool WriteMetadataSection(const pe::PEFile& input_dll);

  // Copies the resource section from the original module to the instrumented
  // module.
  bool CopyResourceSection();

  // The call trace client dll to which to bind the instrumented image.
  std::string client_dll_;

  // Blocks created while updating the import directory.
  BlockGraph::Block* image_import_by_name_block_;
  BlockGraph::Block* hint_name_array_block_;
  BlockGraph::Block* import_address_table_block_;
  BlockGraph::Block* dll_name_block_;
  BlockGraph::Block* image_import_descriptor_array_block_;
  // Holds the index of the resource section, if this module has one.
  // If not, stores kInvalidIndex.
  size_t resource_section_id_;
};

#endif  // SYZYGY_INSTRUMENT_INSTRUMENTER_H_
