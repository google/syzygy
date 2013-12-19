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
//
// Defines a PE-specific block-graph transform that finds or adds imports to a
// given module. Multiple libraries may be specified, and multiple functions per
// library. If an import is not found and the mode is kFindOnly, then the
// import will be added. This may also cause an entire imported module to
// be added.
//
// Use is as follows:
//
//   ImportedModule foo_dll("foo.dll");
//   size_t foo_foo_index = foo_dll.AddSymbol("foo");
//   size_t foo_bar_index = foo_dll.AddSymbol("bar");
//
//   PEAddImportsTransform add_imports_transform;
//   add_imports_transform.AddModule(&foo_dll);
//   add_imports_transform.TransformBlockGraph(block_graph, dos_header_block);
//
//   // Create a reference to function 'bar' in 'foo.dll'.
//   BlockGraph::Reference foo_bar_ref;
//   CHECK(foo_dll.GetSymbolReference(foo_bar_index, &foo_bar_ref));
//   some_block->SetReference(some_offset, foo_bar_ref);
//
// NOTE: The references provided by GetSymbolReference are only valid
//     immediately after they are constructed. If the import directory entries
//     are changed between creating the reference and adding it to a block,
//     than it may have been invalidated.

#ifndef SYZYGY_PE_TRANSFORMS_PE_ADD_IMPORTS_TRANSFORM_H_
#define SYZYGY_PE_TRANSFORMS_PE_ADD_IMPORTS_TRANSFORM_H_

#include <windows.h>

#include "syzygy/block_graph/typed_block.h"
#include "syzygy/block_graph/transforms/named_transform.h"
#include "syzygy/pe/transforms/pe_coff_add_imports_transform.h"

namespace pe {
namespace transforms {

using block_graph::transforms::NamedBlockGraphTransformImpl;

// A transform for adding imported modules/symbols to a given block-graph.
class PEAddImportsTransform
    : public NamedBlockGraphTransformImpl<PEAddImportsTransform>,
      public PECoffAddImportsTransform {
 public:
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::TransformPolicyInterface TransformPolicyInterface;

  PEAddImportsTransform();

  // Performs the transform. Adds entries for any missing modules and
  // symbols, returning references to their entries via the ImportedModule
  // objects.
  //
  // If a date/time stamp is specified in an imported module, it will be
  // used to update the import descriptor binding field (which indicates
  // which version of the library is currently bound in the import table);
  // this can be used to provide stubs at program launch time, that will be
  // replaced by the loader once the real library is loaded.
  //
  // @param policy The policy object restricting how the transform is applied.
  // @param block_graph the BlockGraph to populate.
  // @param dos_header_block the block containing the module's DOS header.
  // @returns true on success, false otherwise.
  virtual bool TransformBlockGraph(
      const TransformPolicyInterface* policy,
      BlockGraph* block_graph,
      BlockGraph::Block* dos_header_block) OVERRIDE;

  // @returns a pointer to the Block containing the Image Import Descriptor.
  BlockGraph::Block* image_import_descriptor_block() {
    return image_import_descriptor_block_;
  }

  // @returns a pointer to the Block containing the Import Address Table.
  BlockGraph::Block* import_address_table_block() {
    return import_address_table_block_;
  }

  // The name of this transform.
  static const char kTransformName[];

 protected:
  // Processes normal imports. If |find_only| is false then this will add the
  // appropriate PE structures and inject missing imports.
  bool FindOrAddImports(bool find_only,
                        BlockGraph* block_graph,
                        BlockGraph::Block* nt_headers_block);
  // Processes delay-load imports. This only searches for existing ones, and
  // currently does not add any new delay-load imports or related PE structures.
  bool FindDelayLoadImports(BlockGraph* block_graph,
                            BlockGraph::Block* nt_headers_block);

  // We cache various blocks for easier unittesting.
  BlockGraph::Block* image_import_descriptor_block_;
  BlockGraph::Block* import_address_table_block_;
  BlockGraph::Block* image_delayload_descriptor_block_;
};

}  // namespace transforms
}  // namespace pe

#endif  // SYZYGY_PE_TRANSFORMS_PE_ADD_IMPORTS_TRANSFORM_H_
