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

#include "syzygy/instrument/transforms/asan_transform.h"

#include <vector>

#include "base/logging.h"
#include "base/stringprintf.h"
#include "base/memory/ref_counted.h"
#include "syzygy/block_graph/basic_block_assembler.h"
#include "syzygy/block_graph/block_builder.h"
#include "syzygy/pe/block_util.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/transforms/add_imports_transform.h"
#include "third_party/distorm/files/include/mnemonics.h"
#include "third_party/distorm/files/src/x86defs.h"

namespace instrument {
namespace transforms {
namespace {

using block_graph::BasicBlock;
using block_graph::BasicCodeBlock;
using block_graph::BasicBlockAssembler;
using block_graph::BasicBlockSubGraph;
using block_graph::BasicBlockReference;
using block_graph::BlockBuilder;
using block_graph::BlockGraph;
using block_graph::Displacement;
using block_graph::Immediate;
using block_graph::Instruction;
using block_graph::Operand;
using block_graph::TypedBlock;
using block_graph::Value;
using core::Register;
using core::RegisterCode;
using pe::transforms::AddImportsTransform;
typedef AsanBasicBlockTransform::MemoryAccessMode AsanMemoryAccessMode;
typedef AsanBasicBlockTransform::AsanHookMap HookMap;

// Returns true iff opcode should be instrumented.
bool ShouldInstrumentOpcode(uint16 opcode) {
  switch (opcode) {
    case I_LEA:
    case I_CALL:
    case I_JMP:
      return false;
    default:
      return true;
  }
}

// Computes the correct displacement, if any, for operand
// number @p operand of @p instr.
Displacement ComputeDisplacementForOperand(const Instruction& instr,
                                           size_t operand) {
  const _DInst& repr = instr.representation();

  DCHECK(repr.ops[operand].type == O_SMEM ||
         repr.ops[operand].type == O_MEM);

  size_t access_size_bytes = repr.ops[operand].size / 8;
  if (repr.dispSize == 0)
    return Displacement(access_size_bytes - 1);

  BasicBlockReference reference;
  if (instr.FindOperandReference(operand, &reference)) {
    if (reference.referred_type() == BasicBlockReference::REFERRED_TYPE_BLOCK) {
      return Displacement(reference.block(),
                          reference.offset() + access_size_bytes - 1);
    } else {
      return Displacement(reference.basic_block());
    }
  } else {
    return Displacement(repr.disp + access_size_bytes - 1);
  }
}

// Returns true if operand @p op is instrumentable, e.g.
// if it implies a memory access.
bool IsInstrumentable(const _Operand& op) {
  switch (op.type) {
    case O_SMEM:
    case O_MEM:
      return true;

    default:
      return false;
  }
}

// Decodes the first O_MEM or O_SMEM operand of @p instr, if any to the
// corresponding Operand.
AsanMemoryAccessMode DecodeMemoryAccess(const Instruction& instr,
                                        Operand* access,
                                        size_t* access_size) {
  DCHECK(access != NULL);
  const _DInst& repr = instr.representation();

  // Figure out which operand we're instrumenting.
  size_t mem_op_id = -1;
  if (IsInstrumentable(repr.ops[0])) {
    // The first operand is instrumentable.
    mem_op_id = 0;
  } else if (IsInstrumentable(repr.ops[1])) {
    // The second operand is instrumentable.
    mem_op_id = 1;
  } else {
    // Neither of the first two operands is instrumentable.
    return AsanBasicBlockTransform::kNoAccess;
  }

  *access_size = repr.ops[mem_op_id].size / 8;
  if (repr.ops[mem_op_id].type == O_SMEM) {
    // Simple memory dereference with optional displacement.
    Register base_reg(RegisterCode(repr.ops[mem_op_id].index - R_EAX));
    // Get the displacement for the operand.
    Displacement displ = ComputeDisplacementForOperand(instr, mem_op_id);

    *access = Operand(base_reg, displ);
  } else if (repr.ops[0].type == O_MEM || repr.ops[1].type == O_MEM) {
    // Complex memory dereference.
    Register index_reg(RegisterCode(repr.ops[mem_op_id].index - R_EAX));
    core::ScaleFactor scale = core::kTimes1;
    switch (repr.scale) {
      case 2:
        scale = core::kTimes2;
        break;
      case 4:
        scale = core::kTimes4;
        break;
      case 8:
        scale = core::kTimes8;
        break;
      default:
        break;
    }

    // Get the displacement for the operand (if any).
    Displacement displ = ComputeDisplacementForOperand(instr, mem_op_id);

    // Compute the full operand.
    if (repr.base != R_NONE) {
      Register base_reg(RegisterCode(repr.base - R_EAX));
      if (displ.size() == core::kSizeNone) {
        // No displacement, it's a [base + index * scale] access.
        *access = Operand(base_reg, index_reg, scale);
      } else {
        // This is a [base + index * scale + displ] access.
        *access = Operand(base_reg, index_reg, scale, displ);
      }
    } else {
      // No base, this is an [index * scale + displ] access.
      // TODO(siggi): AFAIK, there's no encoding for [index * scale] without
      //    a displacement. If this assert fires, I'm proven wrong.
      DCHECK_NE(core::kSizeNone, displ.size());

      *access = Operand(index_reg, scale, displ);
    }
  } else {
    NOTREACHED();

    return AsanBasicBlockTransform::kNoAccess;
  }

  if ((repr.flags & FLAG_DST_WR) && mem_op_id == 0) {
    // The first operand is written to.
    return AsanBasicBlockTransform::kWriteAccess;
  } else {
    return AsanBasicBlockTransform::kReadAccess;
  }
}

// Use @p bb_asm to inject a hook to @p hook to instrument the access to the
// address stored in the operand @p op.
void InjectAsanHook(BasicBlockAssembler* bb_asm,
                    const Operand& op,
                    BlockGraph::Reference* hook) {
  DCHECK(hook != NULL);
  bb_asm->push(core::eax);
  bb_asm->lea(core::eax, op);
  bb_asm->call(Operand(Displacement(hook->referenced(), hook->offset())));
}

typedef std::pair<BlockGraph::Block*, BlockGraph::Offset> ReferenceDest;
typedef std::map<ReferenceDest, ReferenceDest> ReferenceMap;
typedef std::set<BlockGraph::Block*> BlockSet;

// For every block referencing @p dst_blocks, redirects any reference "ref" in
// @p redirects to @p redirects[ref].
void RedirectReferences(const BlockSet& dst_blocks,
                        const ReferenceMap& redirects) {
  // For each block referenced by any source reference.
  BlockSet::const_iterator dst_block_it = dst_blocks.begin();
  for (; dst_block_it != dst_blocks.end(); ++dst_block_it) {
    // Iterate over all their referrers.
    BlockGraph::Block* referred_block = *dst_block_it;
    BlockGraph::Block::ReferrerSet referrers = referred_block->referrers();
    BlockGraph::Block::ReferrerSet::iterator referrer_it = referrers.begin();
    for (; referrer_it != referrers.end(); ++referrer_it) {
      BlockGraph::Block* referrer = referrer_it->first;

      // Don't redirect references from PE parsed blocks. This actually ends up
      // redirecting the IAT entries as well in the worst case.
      if (referrer->attributes() & BlockGraph::PE_PARSED)
        continue;

      // And redirect any references that happen to match a source reference.
      BlockGraph::Block::ReferenceMap::const_iterator reference_it =
          referrer->references().begin();

      for (; reference_it != referrer->references().end(); ++reference_it) {
        const BlockGraph::Reference& ref(reference_it->second);
        ReferenceDest dest(std::make_pair(ref.referenced(), ref.offset()));

        ReferenceMap::const_iterator it(redirects.find(dest));
        if (it != redirects.end()) {
          BlockGraph::Reference new_reference(ref.type(),
                                              ref.size(),
                                              it->second.first,
                                              it->second.second,
                                              0);

          referrer->SetReference(reference_it->first, new_reference);
        }
      }
    }
  }
}

// Get the name of an asan check access function for an @p access_mode access of
// @p access_size bytes.
std::string GetAsanCheckAccessFunctionName(uint8 access_size,
                                           AsanMemoryAccessMode access_mode) {
  DCHECK_NE(access_size, 0);
  DCHECK(access_mode != AsanBasicBlockTransform::kNoAccess);

  const char* access_mode_str = NULL;
  if (access_mode == AsanBasicBlockTransform::kReadAccess)
    access_mode_str = "read";
  else
    access_mode_str = "write";

  return base::StringPrintf("asan_check_%d_byte_%s_access", access_size,
                            access_mode_str);
}

// Add an import for an asan check access hook to the block-graph.
// @param access_size The size of the access. This is needed to get the correct
//     import function name.
// @param access_mode The kind of the access. This is needed to get the correct
//     import function name.
// @param import_module The module for which the import should be added.
// @param check_access_hook_map The map where the reference to the import should
//     be stored.
// @param block_graph The block-graph to populate.
// @param header_block The block containing the module's DOS header of this
//     block-graph.
bool AddAsanCheckAccessHook(uint8 access_size,
                            AsanMemoryAccessMode access_mode,
                            AddImportsTransform::ImportedModule* import_module,
                            HookMap* check_access_hook_map,
                            BlockGraph* block_graph,
                            BlockGraph::Block* header_block) {
  DCHECK(import_module != NULL);
  DCHECK(check_access_hook_map != NULL);
  DCHECK(block_graph != NULL);
  DCHECK(header_block != NULL);

  size_t asan_hook_check_access_index = import_module->AddSymbol(
      GetAsanCheckAccessFunctionName(access_size, access_mode));

  AddImportsTransform add_imports_transform;
  add_imports_transform.AddModule(import_module);

  if (!add_imports_transform.TransformBlockGraph(block_graph, header_block)) {
    LOG(ERROR) << "Unable to add imports for Asan instrumentation DLL.";
    return false;
  }

  BlockGraph::Reference import_reference;
  if (!import_module->GetSymbolReference(asan_hook_check_access_index,
                                         &import_reference)) {
    LOG(ERROR) << "Unable to get import reference for Asan.";
    return false;
  }
  HookMap& hook_map = *check_access_hook_map;
  hook_map[std::make_pair(access_mode, access_size)] = import_reference;

  return true;
}

}  // namespace

const char AsanBasicBlockTransform::kTransformName[] =
    "SyzyAsanBasicBlockTransform";

bool AsanBasicBlockTransform::InstrumentBasicBlock(
    BasicCodeBlock* basic_block) {
  DCHECK(basic_block != NULL);
  BasicBlock::Instructions::iterator iter_inst =
      basic_block->instructions().begin();

  // Process each instruction and inject a call to Asan when we find an
  // instrumentable memory access.
  for (; iter_inst != basic_block->instructions().end(); ++iter_inst) {
    Operand operand(core::eax);
    size_t access_size = 0;
    const Instruction& instr = *iter_inst;
    const _DInst& repr = instr.representation();

    MemoryAccessMode access_mode = DecodeMemoryAccess(instr,
                                                      &operand,
                                                      &access_size);

    // Bail if this is not a memory access.
    if (access_mode == kNoAccess)
      continue;

    // A basic block reference means that can be either a computed jump,
    // or a load from a case table. In either case it doesn't make sense
    // to instrument the access.
    if (operand.displacement().reference().referred_type() ==
        BasicBlockReference::REFERRED_TYPE_BASIC_BLOCK) {
      continue;
    }

    // A block reference means this instruction is reading or writing to
    // a global variable or some such. It's viable to pad and align global
    // variables and to red-zone the padding, but without that, there's nothing
    // to gain by instrumenting these accesses.
    if (operand.displacement().reference().referred_type() ==
        BasicBlockReference::REFERRED_TYPE_BLOCK) {
      continue;
    }

    // Is this an instruction we should be instrumenting.
    if (!ShouldInstrumentOpcode(repr.opcode))
      continue;

    // No point in instrumenting ESP-relative accesses.
    if (operand.base() == core::kRegisterEsp)
      continue;

    // We can't deal with repeated (string) instructions.
    if (FLAG_GET_PREFIX(repr.flags) & (FLAG_REPNZ | FLAG_REP))
      continue;

    BasicBlockAssembler bb_asm(iter_inst, &basic_block->instructions());
    Instruction::Representation inst = iter_inst->representation();
    AsanHookMap::iterator hook;
    hook = check_access_hooks_->find(std::make_pair(access_mode, access_size));
    if (hook == check_access_hooks_->end()) {
      LOG(ERROR) << "Invalid access size: " << access_size << " byte.";
      return false;
    }
    InjectAsanHook(&bb_asm, operand, &hook->second);
  }
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
    BasicCodeBlock* bb = BasicCodeBlock::Cast(*it);
    if (bb != NULL && !InstrumentBasicBlock(bb))
      return false;
  }
  return true;
}

const char AsanTransform::kTransformName[] =
    "SyzyAsanTransform";

const char AsanTransform::kCheckAccessName[] =
    "asan_check_access";

const char AsanTransform::kSyzyAsanDll[] = "asan_rtl.dll";

AsanTransform::AsanTransform() : asan_dll_name_(kSyzyAsanDll) {
}

bool AsanTransform::PreBlockGraphIteration(BlockGraph* block_graph,
                                           BlockGraph::Block* header_block) {
  bool already_instrumented = false;
  // Ensure that this image has not already been instrumented.
  if (!pe::HasImportEntry(header_block, kSyzyAsanDll, &already_instrumented)) {
    LOG(ERROR) << "Unable to check if the image is already instrumented.";
    return false;
  }

  if (already_instrumented) {
    LOG(ERROR) << "The image is already instrumented.";
    return false;
  }

  // Add an import entry for the ASAN runtime.
  AddImportsTransform::ImportedModule import_module(asan_dll_name_.c_str());

  // Import the hooks for the read accesses.
  for (int access_size = 1; access_size <= 32; access_size *= 2) {
    if (!AddAsanCheckAccessHook(access_size,
                                AsanBasicBlockTransform::kReadAccess,
                                &import_module,
                                &check_access_hooks_ref_,
                                block_graph, header_block)) {
      return false;
    }
  }

  if (!AddAsanCheckAccessHook(10,
                              AsanBasicBlockTransform::kReadAccess,
                              &import_module,
                              &check_access_hooks_ref_,
                              block_graph, header_block)) {
    return false;
  }

  // Import the hooks for the write accesses.
  for (int access_size = 1; access_size <= 32; access_size *= 2) {
    if (!AddAsanCheckAccessHook(access_size,
                                AsanBasicBlockTransform::kWriteAccess,
                                &import_module,
                                &check_access_hooks_ref_,
                                block_graph, header_block)) {
      return false;
    }
  }

  if (!AddAsanCheckAccessHook(10,
                              AsanBasicBlockTransform::kWriteAccess,
                              &import_module,
                              &check_access_hooks_ref_,
                              block_graph, header_block)) {
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

  if (!pe::CodeBlockIsBasicBlockDecomposable(block))
    return true;

  AsanBasicBlockTransform transform(&check_access_hooks_ref_);
  if (!ApplyBasicBlockSubGraphTransform(&transform, block_graph, block, NULL))
    return false;

  return true;
}

bool AsanTransform::PostBlockGraphIteration(BlockGraph* block_graph,
                                            BlockGraph::Block* header_block) {
  // This function redirects a the heap-related kernel32 imports to point to
  // a set of "override" imports in the ASAN runtime.

  // Import entries for the ASAN runtime and kernel32.
  AddImportsTransform::ImportedModule module_kernel32("kernel32.dll");
  AddImportsTransform::ImportedModule module_asan(asan_dll_name_.c_str());

  struct Kernel32ImportRedirect {
    const char* import_name;
    const char* redirect_name;
  };
  static const Kernel32ImportRedirect kKernel32Redirects[] = {
    { "HeapCreate", "asan_HeapCreate" },
    { "HeapDestroy", "asan_HeapDestroy" },
    { "HeapAlloc", "asan_HeapAlloc" },
    { "HeapReAlloc", "asan_HeapReAlloc" },
    { "HeapFree", "asan_HeapFree" },
    { "HeapSize", "asan_HeapSize" },
    { "HeapValidate", "asan_HeapValidate" },
    { "HeapCompact", "asan_HeapCompact" },
    { "HeapLock", "asan_HeapLock" },
    { "HeapUnlock", "asan_HeapUnlock" },
    { "HeapWalk", "asan_HeapWalk" },
    { "HeapSetInformation", "asan_HeapSetInformation" },
    { "HeapQueryInformation", "asan_HeapQueryInformation" },
  };

  // Add imports for the overrides to the respective modules.
  // HACK ALERT: This uses the AddImportsTransform to:
  // 1. Find existing imports we want to redirect. This has the unfortunate
  //    side effect of adding all of the imports we query for.
  // 2. Create imports for the redirects, which will create imports for
  //    all of the redirects, irrespective of whether we have anything to
  //    redirect them to.
  // TODO(siggi): Clean this up by factoring import discovery/probing out of the
  //     AddImports transform, and perhaps write yet another transform to remove
  //     unused imports.
  std::vector<std::pair<size_t, size_t>> override_indexes;
  for (size_t i = 0; i < arraysize(kKernel32Redirects); ++i) {
    size_t kernel32_index =
        module_kernel32.AddSymbol(kKernel32Redirects[i].import_name);
    size_t asan_index =
        module_asan.AddSymbol(kKernel32Redirects[i].redirect_name);

    override_indexes.push_back(std::make_pair(kernel32_index, asan_index));
  }

  AddImportsTransform add_imports_transform;
  add_imports_transform.AddModule(&module_asan);
  add_imports_transform.AddModule(&module_kernel32);
  if (!add_imports_transform.TransformBlockGraph(block_graph, header_block)) {
    LOG(ERROR) << "Unable to add imports for import redirection.";
    return false;
  }

  // Keeps track of all the blocks referenced by the original references.
  BlockSet dst_blocks;
  // Stores the reference mapping we want to rewrite.
  ReferenceMap reference_redirect_map;

  for (size_t i = 0; i < override_indexes.size(); ++i) {
    BlockGraph::Reference src;
    BlockGraph::Reference dst;
    if (!module_kernel32.GetSymbolReference(override_indexes[i].first, &src) ||
        !module_asan.GetSymbolReference(override_indexes[i].second, &dst)) {
       NOTREACHED() << "Unable to get references after a successful transform.";
      return false;
    }

    // Add the destination block to the set of referred blocks.
    dst_blocks.insert(src.referenced());
    reference_redirect_map.insert(
        std::make_pair(ReferenceDest(src.referenced(), src.offset()),
                       ReferenceDest(dst.referenced(), dst.offset())));
  }

  RedirectReferences(dst_blocks, reference_redirect_map);

  return true;
}

}  // namespace transforms
}  // namespace instrument
