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

#ifndef SYZYGY_INSTRUMENT_INSTRUMENTER_H_
#define SYZYGY_INSTRUMENT_INSTRUMENTER_H_

#include "syzygy/block_graph/block_graph.h"
#include "syzygy/relink/relinker.h"

namespace instrument {

class Instrumenter : public relink::RelinkerBase {
 public:
  Instrumenter();

  // Change the client DLL to which instrumented binaries will be bound.
  void set_client_dll(const char* client_dll);
  const char* client_dll() const;

  // If set to false, references with a non-zero offset into the destination
  // will not be instrumented.  The default is to instrument them.
  void set_instrument_interior_references(bool instrument);
  bool instrument_interior_references() const;

  // Wrapper function to instrument an input dll to an output dll.
  //
  // @param input_dll_path the DLL to instrument.
  // @param input_pdb_path the PDB for the DLL to instrument.
  // @param output_dll_path the path where the instrumented DLL should be
  //     written.
  // @param output_pdb_path the path where the instrumented DLL's PDB file
  //     should be written.
  // @returns true on success, false otherwise.
  bool Instrument(const FilePath& input_dll_path,
                  const FilePath& input_pdb_path,
                  const FilePath& output_dll_path,
                  const FilePath& output_pdb_path);

  // The pre-defined call trace client DLLs. By default the ETW version will
  // be used.
  static const char* const kCallTraceClientDllEtw;
  static const char* const kCallTraceClientDllProfiler;
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
  bool InstrumentCodeBlocks(BlockGraph* block_graph);

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

  // Create thunks for all referrers to @p block.
  bool CreateThunks(BlockGraph::Block* block,
                    RelativeAddress* insert_at);

  // Create a thunk for @p block using reference @p ref. This method is
  // responsible for updating @p insert_at.
  bool CreateOneThunk(BlockGraph::Block* block,
                      const BlockGraph::Reference& ref,
                      RelativeAddress* insert_at,
                      BlockGraph::Block** thunk_block);

  // Update the thunk for the main entry point to call the dllmain version of
  // _indirect_penter instead of the standard one.
  //
  // @pre The module being instrumented is a DLL.
  // @pre The main thunking process has already been completed (i.e., the
  //     thunks already exist).
  bool FixEntryPointThunk();

  // Update the thunks for the __declspec(thread) static initializers to call
  // the dllmain version of _indirect_penter instead of the standard one.
  //
  // @pre The module being instrumented is a DLL.
  // @pre The main thunking process has already been completed (i.e., the
  //     thunks already exist).
  bool FixTlsInitializerThunks();

  // Update @p thunk block to point to _indirect_penter_dllmain instead of
  // _indirect_penter.
  bool RedirectThunk(BlockGraph::Block* thunk_block);

  // The call trace client dll to which to bind the instrumented image.
  std::string client_dll_;

  // Whether to instrument references with a non-zero offset into the
  // destination block.
  bool instrument_interior_references_;

  // Blocks created while updating the import directory.
  BlockGraph::Block* image_import_by_name_block_;
  BlockGraph::Block* hint_name_array_block_;
  BlockGraph::Block* import_address_table_block_;
  BlockGraph::Block* dll_name_block_;
  BlockGraph::Block* image_import_descriptor_array_block_;

  const std::string thunk_suffix_;
};

#endif  // SYZYGY_INSTRUMENT_INSTRUMENTER_H_

}  // namespace instrument
