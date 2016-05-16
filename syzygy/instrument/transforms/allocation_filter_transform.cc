// Copyright 2014 Google Inc. All Rights Reserved.
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
// Implements the AllocationFilterTransform class.

#include "syzygy/instrument/transforms/allocation_filter_transform.h"

#include "base/logging.h"
#include "base/values.h"
#include "base/json/json_reader.h"
#include "syzygy/core/address_space.h"
#include "syzygy/pe/transforms/pe_add_imports_transform.h"

namespace instrument {
namespace transforms {

namespace {

using base::DictionaryValue;
using base::ListValue;
using base::Value;

using block_graph::BasicBlock;
using block_graph::BasicBlockAssembler;
using block_graph::BasicBlockReference;
using block_graph::BasicBlockSubGraph;
using block_graph::BasicCodeBlock;
using block_graph::BlockGraph;
using block_graph::Displacement;
using block_graph::Operand;
using block_graph::TransformPolicyInterface;
using pe::transforms::PEAddImportsTransform;

typedef BasicBlockSubGraph::BlockDescriptionList
    BlockDescriptionList;
typedef pe::transforms::ImportedModule ImportedModule;

const char kPreCallFunctioName[] = "asan_SetAllocationFilterFlag";
const char kPostCallFunctioName[] = "asan_ClearAllocationFilterFlag";

// Sets up the pre-call and post-call hooks import.
bool SetupEntryHooks(const TransformPolicyInterface* policy,
                     BlockGraph* block_graph,
                     BlockGraph::Block* header_block,
                     const std::string& module_name,
                     BlockGraph::Reference* pre_call,
                     BlockGraph::Reference* post_call) {
  DCHECK(policy != NULL);
  DCHECK(block_graph != NULL);
  DCHECK(header_block != NULL);
  DCHECK(pre_call != NULL);
  DCHECK(post_call != NULL);

  // Setup the import module.
  ImportedModule module(module_name);
  size_t pre_call_index = module.AddSymbol(kPreCallFunctioName,
                                           ImportedModule::kAlwaysImport);

  size_t post_call_index = module.AddSymbol(kPostCallFunctioName,
                                            ImportedModule::kAlwaysImport);

  // Setup the add-imports transform.
  PEAddImportsTransform add_imports;
  add_imports.AddModule(&module);

  // Add the imports to the block-graph.
  if (!ApplyBlockGraphTransform(
          &add_imports, policy, block_graph, header_block)) {
    LOG(ERROR) << "Unable to add import hook functions.";
    return false;
  }

  // Get a reference to the pre-call hook function.
  if (!module.GetSymbolReference(pre_call_index, pre_call)) {
    LOG(ERROR) << "Unable to get a reference to " << kPreCallFunctioName << ".";
    return false;
  }
  DCHECK(pre_call->IsValid());

  // Get a reference to the post-call hook function.
  if (!module.GetSymbolReference(post_call_index, post_call)) {
    LOG(ERROR) << "Unable to get a reference to " << kPostCallFunctioName
               << ".";
    return false;
  }
  DCHECK(post_call->IsValid());

  return true;
}

}  // namespace

const char AllocationFilterTransform::kTransformName[] =
    "AllocationFilterTransform";

AllocationFilterTransform::AllocationFilterTransform(
    FunctionNameOffsetMap targets)
    : instrument_dll_name_(transforms::AsanTransform::kSyzyAsanDll),
      targets_(targets) {
  // Non debug friendly by default.
  set_debug_friendly(false);
  // Reporting enabled by default.
  set_enable_reporting(true);
}

bool AllocationFilterTransform::PreBlockGraphIteration(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {
  DCHECK_NE(reinterpret_cast<TransformPolicyInterface*>(NULL), policy);
  DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), header_block);
  DCHECK_EQ(BlockGraph::PE_IMAGE, block_graph->image_format());

  // Setup instrumentation functions hooks.
  if (!SetupEntryHooks(policy,
                       block_graph,
                       header_block,
                       instrument_dll_name_,
                       &pre_call_hook_ref_,
                       &post_call_hook_ref_)) {
    return false;
  }

  return true;
}

bool AllocationFilterTransform::OnBlock(const TransformPolicyInterface* policy,
                                  BlockGraph* block_graph,
                                  BlockGraph::Block* block) {
  DCHECK(block_graph != NULL);
  DCHECK(block != NULL);

  // Ignore non-decomposable blocks.
  if (!policy->BlockIsSafeToBasicBlockDecompose(block))
    return true;

  if (!ApplyBasicBlockSubGraphTransform(this, policy, block_graph, block, NULL))
    return false;

  return true;
}

bool AllocationFilterTransform::TransformBasicBlockSubGraph(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BasicBlockSubGraph* subgraph) {
  DCHECK(policy != NULL);
  DCHECK(block_graph != NULL);
  DCHECK(subgraph != NULL);
  DCHECK(pre_call_hook_ref_.IsValid());
  DCHECK(post_call_hook_ref_.IsValid());

  // Reset tracked instrumented calls.
  instrumented_.clear();

  BlockDescriptionList& descriptions = subgraph->block_descriptions();
  DCHECK_EQ(1u, descriptions.size());
  const auto description = descriptions.begin();
  const std::string function_name = description->name;
    FunctionNameOffsetMap::const_iterator target_iter =
        targets_.find(function_name);

  // Skip the block if the function name is not included in |targets_|.
  if (target_iter == targets_.end())
    return true;

  // Iterate over the basic blocks in this block.
  const OffsetSet& offset_set = target_iter->second;
  BasicBlockSubGraph::BasicBlockOrdering& original_order =
      (*description).basic_block_order;
  DCHECK(!original_order.empty());
  for (auto basic_block : original_order) {
    BasicCodeBlock* bb = BasicCodeBlock::Cast(basic_block);
    if (bb == NULL || bb->is_padding() || !bb->IsValid())
      continue;

    // The instructions offset is calculated progressively.
    Offset next_offset = bb->offset();

    BasicBlock::Instructions::iterator inst_iter = bb->instructions().begin();
    BasicBlock::Instructions::iterator next_iter;
    for (; inst_iter != bb->instructions().end(); inst_iter = next_iter) {
      // Since the BasicBlockAssembler can inject new instructions, and modify
      // the instruction sequence, the iterators used in the loop are safely
      // handled before any modification.
      next_offset += inst_iter->size();
      next_iter = inst_iter;
      ++next_iter;

      if (inst_iter->IsCall() && !inst_iter->CallsNonReturningFunction()) {
        // Instrument only the calls in the specified offsets.
        if (offset_set.find(next_offset) == offset_set.end())
          continue;

        // Keep track of the instrumented calls.
        instrumented_[function_name].insert(next_offset);

        block_graph::Instruction::SourceRange source_range =
            inst_iter->source_range();

        // Using local scope to control exactly when the instructions are
        // injected. The BasicBlockAssembler flush the new instructions when
        // leaving scope.
        // Prepend a call to pre-call hook (asan_SetAllocationFilterFlag).
        {
          DCHECK(pre_call_hook_ref_.IsValid());
          BlockGraph::Reference* pre_call_hook_ref = &pre_call_hook_ref_;
          auto pre_call_hook(
              Operand(Displacement(pre_call_hook_ref->referenced(),
                                    pre_call_hook_ref->offset())));
          BasicBlockAssembler bb_asm_enter(inst_iter, &bb->instructions());

          // Configure the assembler to copy the SourceRange information of
          // the current instrumented instruction into newly created
          // instructions. This is a hack to allow valid stack walking and
          // better error reporting, but breaks the 1:1 OMAP mapping and may
          // confuse some debuggers.
          if (debug_friendly_)
            bb_asm_enter.set_source_range(inst_iter->source_range());
          bb_asm_enter.call(pre_call_hook);
        }

        // Append a call to post-call hook (asan_ClearAllocationFilterFlag).
        {
          DCHECK(post_call_hook_ref_.IsValid());
          BlockGraph::Reference* post_call_hook_ref = &post_call_hook_ref_;
          auto post_call_hook(
              Operand(Displacement(post_call_hook_ref->referenced(),
                                    post_call_hook_ref_.offset())));
          BasicBlockAssembler bb_asm_exit(next_iter, &bb->instructions());
          if (debug_friendly_)
            bb_asm_exit.set_source_range(inst_iter->source_range());
          bb_asm_exit.call(post_call_hook);
        }
      }
    }
  }

  // Report targeted but non-instrumented calls.
  if (enable_reporting_) {
    FunctionNameOffsetMap::const_iterator targets_iter =
        targets_.find(function_name);
    if (targets_iter != targets_.end()) {
      const OffsetSet& target_offsets = targets_iter->second;
      std::vector<Offset> non_instrumented;

      std::set_difference(target_offsets.begin(),
                          target_offsets.end(),
                          instrumented_[function_name].begin(),
                          instrumented_[function_name].end(),
                          std::back_inserter(non_instrumented));

      // Warn about non-instrumented calls.
      for (size_t i = 0; i < non_instrumented.size(); ++i) {
        LOG(WARNING) << "Target call " << function_name << " + "
                     << non_instrumented[i]
                     << " not instrumented.";
      }
    } else {
      DCHECK(instrumented_.empty());
    }
  }

  return true;
}

bool AllocationFilterTransform::ReadFromJSON(const base::FilePath& path,
    FunctionNameOffsetMap* targets) {
  DCHECK_NE(static_cast<FunctionNameOffsetMap*>(NULL), targets);
  std::string file_string;
  if (!base::ReadFileToString(path, &file_string)) {
    LOG(ERROR) << "Unable to read file to string.";
    return false;
  }

  if (!ReadFromJSON(file_string, targets)) {
    LOG(ERROR) << "Unable to parse JSON string.";
    return false;
  }
  return true;
}

bool AllocationFilterTransform::ReadFromJSON(const std::string& json,
    FunctionNameOffsetMap* targets) {
  DCHECK_NE(static_cast<FunctionNameOffsetMap*>(NULL), targets);
  std::unique_ptr<Value> value(base::JSONReader::Read(json).release());
  if (value.get() == NULL) {
    LOG(INFO) << "Ignoring invalid or empty allocation filter file.";
    return true;
  }

  if (value->GetType() != Value::TYPE_DICTIONARY) {
    LOG(ERROR) << "Invalid allocation filter transform file.";
    return false;
  }

  const DictionaryValue* outer_dict =
    reinterpret_cast<const DictionaryValue*>(value.get());

  std::string hooks_key("hooks");
  const DictionaryValue* hooks_dict = NULL;

  if (!outer_dict->GetDictionary(hooks_key, &hooks_dict)) {
    LOG(ERROR) << "Outer dictionary must contain key 'hooks'.";
    return false;
  }

  DictionaryValue::Iterator it(*hooks_dict);
  for (; !it.IsAtEnd(); it.Advance()) {
    std::string function_name = it.key();
    const ListValue* offset_list = NULL;

    if (!it.value().GetAsList(&offset_list))  {
      LOG(ERROR) << "Offset list expected.";
      return false;
    }

    // Load the offset list.
    ListValue::const_iterator list_iter = offset_list->begin();
    for (; list_iter != offset_list->end(); ++list_iter) {
      int int_offset = 0;
      if (!(*list_iter)->GetAsInteger(&int_offset)) {
        LOG(ERROR) << "Invalid offset.";
        return false;
      }
      if (int_offset < 0) {
        LOG(ERROR) << "Invalid (negative) offset.";
        return false;
      }
      Offset offset = static_cast<Offset>(int_offset);
      (*targets)[function_name].insert(offset);
    }
  }

  return true;
}

bool AllocationFilterTransform::PostBlockGraphIteration(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {
  DCHECK(policy != NULL);
  DCHECK(block_graph != NULL);
  DCHECK(header_block != NULL);
  return true;
}

}  // namespace transforms
}  // namespace instrument
