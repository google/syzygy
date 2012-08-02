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

#include "syzygy/instrument/transforms/asan_transform.h"

#include "base/logging.h"
#include "base/stringprintf.h"
#include "base/memory/ref_counted.h"
#include "syzygy/pe/block_util.h"
#include "syzygy/pe/transforms/add_imports_transform.h"

namespace pe {
namespace transforms {

using block_graph::BasicBlock;
using block_graph::TypedBlock;
using block_graph::BlockGraph;
using block_graph::BasicBlockSubGraph;
using block_graph::Instruction;
using core::DisplacementImpl;
using core::OperandImpl;
using core::Register;
using core::RegisterCode;

const char AsanBasicBlockTransform::kTransformName[] =
    "SyzyAsanBasicBlockTransform";

bool AsanBasicBlockTransform::InstrumentBasicBlock(BasicBlock* basic_block) {
  DCHECK(basic_block != NULL);
  // TODO(sebmarchand): Instrument the basic block !
  return true;
}

bool AsanBasicBlockTransform::TransformBasicBlockSubGraph(
    BlockGraph* block_graph, BasicBlockSubGraph* subgraph) {
  DCHECK(block_graph != NULL);
  DCHECK(subgraph != NULL);

  // Iterates through each basic block and instruments it.
  BasicBlockSubGraph::BBCollection::iterator it =
      subgraph->basic_blocks().begin();
  for (; it != subgraph->basic_blocks().end(); ++it) {
    if (!InstrumentBasicBlock(&it->second))
      return false;
  }
  return true;
}

const char AsanTransform::kTransformName[] =
    "SyzyAsanTransform";

const char AsanTransform::kAsanHookWriteTestName[] =
    "__asan_write_access";

const char AsanTransform::kAsanHookReadTestName[] =
    "__asan_read_access";

const char AsanTransform::kSyzyAsanDll[] = "asan_rtl.dll";

AsanTransform::AsanTransform() : asan_dll_name_(kSyzyAsanDll) {
}

bool AsanTransform::PreBlockGraphIteration(BlockGraph* block_graph,
                                           BlockGraph::Block* header_block) {
  AddImportsTransform::ImportedModule import_module(asan_dll_name_.c_str());
  size_t asan_hook_write_test_index =
      import_module.AddSymbol(kAsanHookWriteTestName);
  size_t asan_hook_read_test_index =
      import_module.AddSymbol(kAsanHookReadTestName);

  AddImportsTransform add_imports_transform;
  add_imports_transform.AddModule(&import_module);

  if (!add_imports_transform.TransformBlockGraph(block_graph, header_block)) {
    LOG(ERROR) << "Unable to add imports for Asan instrumentation DLL.";
    return false;
  }

  if (!import_module.GetSymbolReference(asan_hook_write_test_index,
                                        &hook_asan_write_test_) ||
      !import_module.GetSymbolReference(asan_hook_read_test_index,
                                        &hook_asan_read_test_)) {
    LOG(ERROR) << "Unable to get import references for Asan.";
    return false;
  }

  return true;
}

bool AsanTransform::OnBlock(BlockGraph* block_graph,
                            BlockGraph::Block* block) {
  DCHECK(block_graph != NULL);
  DCHECK(block != NULL);
  if (block->type() != BlockGraph::CODE_BLOCK)
    return true;

  if (!CodeBlockIsBasicBlockDecomposable(block))
    return true;

  AsanBasicBlockTransform transform(&hook_asan_write_test_,
                                    &hook_asan_read_test_);

  if (!ApplyBasicBlockSubGraphTransform(&transform, block_graph, block, NULL))
    return false;

  return true;
}

}  // namespace transforms
}  // namespace pe
