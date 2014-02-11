// Copyright 2013 Google Inc. All Rights Reserved.
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
// CoffAddImportsTransform is the COFF-equivalent of PEAddImportsTransform;
// it adds external symbols to a COFF block graph, that can then be
// referenced in calls, address computations and accesses.
//
// Use is similar to PEAddImportsTransform:
//
//   // For COFF, the library name is ignored and always considered imported
//   // and never added. Which library (or simple object file) a symbol is
//   // resolved from is left to the linker. Hence, all symbols share a
//   // common table, which tells the linker what to look up, but not where
//   // to look for it.
//   ImportedModule foo_dll("foo.dll");
//   size_t foo_foo_index = foo_dll.AddSymbol("foo");
//   size_t foo_bar_index = foo_dll.AddSymbol("bar");
//
//   CoffAddImportsTransform add_imports_transform;
//   add_imports_transform.AddModule(&foo_dll);
//   add_imports_transform.TransformBlockGraph(block_graph, headers_block);
//
//   // Create a reference to function 'bar' in 'foo.dll'. If is_ptr
//   // is true on return of GetSymbolReference, then the reference is
//   // to a pointer to the actual thing (i.e., we need to handle one more
//   // level of indirection).
//   BlockGraph::Reference foo_bar_ref;
//   bool is_ptr = false;
//   CHECK(foo_dll.GetSymbolReference(foo_bar_index, &foo_bar_ref, &is_ptr));
//   some_block->SetReference(some_offset, foo_bar_ref);

#ifndef SYZYGY_PE_TRANSFORMS_COFF_ADD_IMPORTS_TRANSFORM_H_
#define SYZYGY_PE_TRANSFORMS_COFF_ADD_IMPORTS_TRANSFORM_H_

#include "syzygy/block_graph/typed_block.h"
#include "syzygy/block_graph/transforms/named_transform.h"
#include "syzygy/pe/coff_utils.h"
#include "syzygy/pe/transforms/pe_coff_add_imports_transform.h"

namespace pe {
namespace transforms {

using block_graph::BlockGraph;
using block_graph::TransformPolicyInterface;
using block_graph::transforms::NamedBlockGraphTransformImpl;

// A transform for adding COFF symbols to a given block graph.
class CoffAddImportsTransform
    : public NamedBlockGraphTransformImpl<CoffAddImportsTransform>,
      public PECoffAddImportsTransform {
 public:
  // Construct an empty CoffAddImportsTransform, that imports nothing
  // initially.
  CoffAddImportsTransform() {}

  // Perform the transform. Add entries for any missing symbols to the COFF
  // symbol table, and fill the attached imported module objects.
  //
  // @param policy The policy object restricting how the transform is applied.
  // @param block_graph the BlockGraph to populate.
  // @param headers_block the block containing the headers.
  // @returns true on success, false otherwise.
  virtual bool TransformBlockGraph(
      const TransformPolicyInterface* policy,
      BlockGraph* block_graph,
      BlockGraph::Block* headers_block) OVERRIDE;

  // The name of this transform.
  static const char kTransformName[];

 private:
  // Process all symbols in @p module as requested, adding to
  // @p names_to_add any symbol that needs to be imported and is not
  // already present.
  //
  // @param file_header the COFF file header.
  // @param known_names the collection of existing symbols in the current
  //     symbol table.
  // @param module the module to process.
  // @param names_to_add the collection of new symbols that will need to be
  //     added to the symbol table.
  // @param string_len_to_add incremented by the extra space (in bytes)
  //     required to hold the added names.
  // @returns true on success, false on failure
  bool FindAndCollectSymbolsFromModule(
      const block_graph::TypedBlock<IMAGE_FILE_HEADER>& file_header,
      const CoffSymbolNameOffsetMap& known_names,
      ImportedModule* module,
      CoffSymbolNameOffsetMap* names_to_add,
      size_t* string_len_to_add);

  // Update all references in @p module.
  //
  // @param symbols_block the block containing the symbol table.
  // @param module the module to update.
  void UpdateModuleReferences(BlockGraph::Block* symbols_block,
                              ImportedModule* module);

  typedef std::pair<ImportedModule*, size_t> ModuleSymbol;
  typedef std::map<ModuleSymbol, BlockGraph::Offset> ModuleSymbolOffsetMap;
  ModuleSymbolOffsetMap module_symbol_offset_map_;

  DISALLOW_COPY_AND_ASSIGN(CoffAddImportsTransform);
};

}  // namespace transforms
}  // namespace pe

#endif  // SYZYGY_PE_TRANSFORMS_COFF_ADD_IMPORTS_TRANSFORM_H_
