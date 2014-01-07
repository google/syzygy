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
#include "base/string_util.h"
#include "base/stringprintf.h"
#include "base/memory/ref_counted.h"
#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/basic_block_assembler.h"
#include "syzygy/block_graph/block_builder.h"
#include "syzygy/block_graph/block_util.h"
#include "syzygy/common/defs.h"
#include "syzygy/pe/pe_utils.h"
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
using block_graph::TransformPolicyInterface;
using block_graph::TypedBlock;
using block_graph::Value;
using block_graph::analysis::LivenessAnalysis;
using block_graph::analysis::MemoryAccessAnalysis;
using core::Register32;
using pe::transforms::PEAddImportsTransform;

// A simple struct that can be used to let us access strings using TypedBlock.
struct StringStruct {
  const char string[1];
};

typedef pe::transforms::ImportedModule ImportedModule;
typedef AsanBasicBlockTransform::MemoryAccessMode AsanMemoryAccessMode;
typedef AsanBasicBlockTransform::AsanHookMap HookMap;
typedef std::vector<AsanBasicBlockTransform::AsanHookMapEntryKey>
    AccessHookParamVector;
typedef TypedBlock<IMAGE_IMPORT_DESCRIPTOR> ImageImportDescriptor;
typedef TypedBlock<StringStruct> String;

// Returns true iff opcode should be instrumented.
bool ShouldInstrumentOpcode(uint16 opcode) {
  switch (opcode) {
    // LEA does not actually access memory.
    case I_LEA:
      return false;

    // We can ignore the prefetch and clflush instructions. The instrumentation
    // will detect memory errors if and when the memory is actually accessed.
    case I_CLFLUSH:
    case I_PREFETCH:
    case I_PREFETCHNTA:
    case I_PREFETCHT0:
    case I_PREFETCHT1:
    case I_PREFETCHT2:
    case I_PREFETCHW:
      return false;
  }
  return true;
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

// Returns true if opcode @p opcode is a special instruction.
// Memory checks for special instructions (string instructions, instructions
// with prefix, etc) are handled by calling specialized functions rather than
// the standard memory checks.
bool IsSpecialInstruction(uint16_t opcode) {
  switch (opcode) {
    case I_CMPS:
    case I_STOS:
    case I_MOVS:
      return true;

    default:
      return false;
  }
}

// Decodes the first O_MEM or O_SMEM operand of @p instr, if any to the
// corresponding Operand.
bool DecodeMemoryAccess(const Instruction& instr,
    Operand* access,
    AsanBasicBlockTransform::MemoryAccessInfo* info) {
  DCHECK(access != NULL);
  DCHECK(info != NULL);
  const _DInst& repr = instr.representation();

  // Figure out which operand we're instrumenting.
  size_t mem_op_id = -1;
  if (IsInstrumentable(repr.ops[0]) && IsInstrumentable(repr.ops[1])) {
    // This happens with instructions like: MOVS [EDI], [ESI].
    DCHECK(repr.ops[0].size == repr.ops[1].size);
    mem_op_id = 0;
  } else if (IsInstrumentable(repr.ops[0])) {
    // The first operand is instrumentable.
    mem_op_id = 0;
  } else if (IsInstrumentable(repr.ops[1])) {
    // The second operand is instrumentable.
    mem_op_id = 1;
  } else {
    // Neither of the first two operands is instrumentable.
    return false;
  }

  // Determine the size of the access.
  info->size = repr.ops[mem_op_id].size / 8;

  // Determine the kind of access (read/write/instr/repz).
  if (FLAG_GET_PREFIX(repr.flags) & FLAG_REPNZ)
    info->mode = AsanBasicBlockTransform::kRepnzAccess;
  else if (FLAG_GET_PREFIX(repr.flags) & FLAG_REP)
    info->mode = AsanBasicBlockTransform::kRepzAccess;
  else if (IsSpecialInstruction(instr.opcode()))
    info->mode = AsanBasicBlockTransform::kInstrAccess;
  else if ((repr.flags & FLAG_DST_WR) && mem_op_id == 0) {
    // The first operand is written to.
    info->mode = AsanBasicBlockTransform::kWriteAccess;
  } else {
    info->mode = AsanBasicBlockTransform::kReadAccess;
  }

  // Determine the opcode of this instruction (when needed).
  if (info->mode == AsanBasicBlockTransform::kRepnzAccess ||
      info->mode == AsanBasicBlockTransform::kRepzAccess ||
      info->mode == AsanBasicBlockTransform::kInstrAccess) {
    info->opcode = instr.opcode();
  }

  // Determine operand of the access.
  if (repr.ops[mem_op_id].type == O_SMEM) {
    // Simple memory dereference with optional displacement.
    const Register32& base_reg = core::CastAsRegister32(
        core::GetRegister(repr.ops[mem_op_id].index));

    // Get the displacement for the operand.
    Displacement displ = ComputeDisplacementForOperand(instr, mem_op_id);
    *access = Operand(base_reg, displ);
  } else if (repr.ops[0].type == O_MEM || repr.ops[1].type == O_MEM) {
    // Complex memory dereference.
    const Register32& index_reg = core::CastAsRegister32(
        core::GetRegister(repr.ops[mem_op_id].index));

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
      const Register32& base_reg = core::CastAsRegister32(
          core::GetRegister(repr.base));

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
    return false;
  }

  return true;
}

// Use @p bb_asm to inject a hook to @p hook to instrument the access to the
// address stored in the operand @p op.
void InjectAsanHook(BasicBlockAssembler* bb_asm,
                    const AsanBasicBlockTransform::MemoryAccessInfo& info,
                    const Operand& op,
                    BlockGraph::Reference* hook,
                    const LivenessAnalysis::State& state) {
  DCHECK(hook != NULL);

  // Determine which kind of probe to inject.
  if (info.mode == AsanBasicBlockTransform::kReadAccess ||
      info.mode == AsanBasicBlockTransform::kWriteAccess) {
    // The standard load/store probe assume the address is in EDX.
    // It restore the original version of EDX and cleanup the stack.
    bb_asm->push(core::edx);
    bb_asm->lea(core::edx, op);
    bb_asm->call(Operand(Displacement(hook->referenced(), hook->offset())));
  } else {
    // The special instruction probe take addresses directly in registers.
    // The probe doesn't have any effects on stack, registers and flags.
    bb_asm->call(Operand(Displacement(hook->referenced(), hook->offset())));
  }
}

// Get the name of an asan check access function for an @p access_mode access.
// @param info The memory access information, e.g. the size on a load/store,
//     the instruction opcode and the kind of access.
std::string GetAsanCheckAccessFunctionName(
    AsanBasicBlockTransform::MemoryAccessInfo info) {
  DCHECK(info.mode != AsanBasicBlockTransform::kNoAccess);
  DCHECK_NE(0U, info.size);
  DCHECK(info.mode == AsanBasicBlockTransform::kReadAccess ||
         info.mode == AsanBasicBlockTransform::kWriteAccess ||
         info.opcode != 0);

  const char* rep_str = NULL;
  if (info.mode == AsanBasicBlockTransform::kRepzAccess)
    rep_str = "_repz";
  else if (info.mode == AsanBasicBlockTransform::kRepnzAccess)
    rep_str = "_repnz";
  else
    rep_str = "";

  const char* access_mode_str = NULL;
  if (info.mode == AsanBasicBlockTransform::kReadAccess)
    access_mode_str = "read";
  else if (info.mode == AsanBasicBlockTransform::kWriteAccess)
    access_mode_str = "write";
  else
    access_mode_str = reinterpret_cast<char*>(GET_MNEMONIC_NAME(info.opcode));

  std::string function_name =
      base::StringPrintf("asan_check%s_%d_byte_%s_access%s",
                          rep_str,
                          info.size,
                          access_mode_str,
                          info.save_flags ? "" : "_no_flags");
  StringToLowerASCII(&function_name);
  return function_name;
}

// Add the imports for the asan check access hooks to the block-graph.
// @param hooks_param_vector A vector of hook parameter values.
// @param default_stub_map Stubs for the asan check access functions.
// @param import_module The module for which the import should be added.
// @param check_access_hook_map The map where the reference to the imports
//     should be stored.
// @param policy The policy object restricting how the transform is applied.
// @param block_graph The block-graph to populate.
// @param header_block The block containing the module's DOS header of this
//     block-graph.
// @returns True on success, false otherwise.
bool AddAsanCheckAccessHooks(
    const AccessHookParamVector& hook_param_vector,
    const AsanBasicBlockTransform::AsanDefaultHookMap& default_stub_map,
    ImportedModule* import_module,
    HookMap* check_access_hook_map,
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {
  DCHECK(import_module != NULL);
  DCHECK(check_access_hook_map != NULL);
  DCHECK(policy != NULL);
  DCHECK(block_graph != NULL);
  DCHECK(header_block != NULL);

  // Add the hooks to the import module.

  typedef std::map<AsanBasicBlockTransform::AsanHookMapEntryKey, size_t>
      HooksParamsToIdxMap;
  HooksParamsToIdxMap hooks_params_to_idx;

  AccessHookParamVector::const_iterator iter_params = hook_param_vector.begin();
  for (; iter_params != hook_param_vector.end(); ++iter_params) {
    size_t symbol_idx = import_module->AddSymbol(
        GetAsanCheckAccessFunctionName(*iter_params),
        ImportedModule::kAlwaysImport);
    hooks_params_to_idx[*iter_params] = symbol_idx;
  }

  DCHECK_EQ(hooks_params_to_idx.size(), hook_param_vector.size());

  // Transforms the block-graph.

  PEAddImportsTransform add_imports_transform;
  add_imports_transform.AddModule(import_module);

  if (!add_imports_transform.TransformBlockGraph(
          policy, block_graph, header_block)) {
    LOG(ERROR) << "Unable to add imports for Asan instrumentation DLL.";
    return false;
  }

  // Get a reference to each hook and put it in the hooks map.
  HooksParamsToIdxMap::iterator iter_hooks = hooks_params_to_idx.begin();
  for (; iter_hooks != hooks_params_to_idx.end(); ++iter_hooks) {
    BlockGraph::Reference import_reference;
    if (!import_module->GetSymbolReference(iter_hooks->second,
                                           &import_reference)) {
      LOG(ERROR) << "Unable to get import reference for Asan.";
      return false;
    }
    HookMap& hook_map = *check_access_hook_map;
    hook_map[iter_hooks->first] = import_reference;

    // In a Chrome sandboxed process the NtMapViewOfSection function is
    // intercepted by the sandbox agent. This causes execution in the executable
    // before imports have been resolved, as the ntdll patch invokes into the
    // executable while resolving imports. As the Asan instrumentation directly
    // refers to the IAT entries we need to temporarily stub these function
    // until the Asan imports are resolved. To do this we need to make the IAT
    // entries for those functions point to a temporarily block and we need to
    // mark the image import descriptor for this DLL as bound.
    AsanBasicBlockTransform::AsanDefaultHookMap::const_iterator stub_reference =
        default_stub_map.find(iter_hooks->first.mode);
    if (stub_reference == default_stub_map.end()) {
       LOG(ERROR) << "Could not find the default hook for "
                  << GetAsanCheckAccessFunctionName(iter_hooks->first)
                  << ".";
      return false;
    }

    import_reference.referenced()->SetReference(import_reference.offset(),
                                                stub_reference->second);
  }

  return true;
}

// Create a stub for the asan_check_access functions. For load/store, the stub
// consists of a small block of code that restores the value of EDX and returns
// to the caller. Otherwise, the stub do return.
// @param block_graph The block-graph to populate with the stub.
// @param stub_name The stub's name.
// @param mode The kind of memory access.
// @param reference Will receive the reference to the created hook.
// @returns true on success, false otherwise.
bool CreateHooksStub(BlockGraph* block_graph,
                     const base::StringPiece& stub_name,
                     AsanBasicBlockTransform::MemoryAccessMode mode,
                     BlockGraph::Reference* reference) {
  DCHECK(reference != NULL);

  // Find or create the section we put our thunks in.
  BlockGraph::Section* thunk_section = block_graph->FindOrAddSection(
      common::kThunkSectionName, pe::kCodeCharacteristics);

  if (thunk_section == NULL) {
    LOG(ERROR) << "Unable to find or create .thunks section.";
    return false;
  }

  std::string stub_name_with_id = base::StringPrintf(
      "%.*s%d", stub_name.length(), stub_name.data(), mode);

  // Create the thunk for standard "load/store" (received address in EDX).
  BasicBlockSubGraph bbsg;
  BasicBlockSubGraph::BlockDescription* block_desc = bbsg.AddBlockDescription(
      stub_name_with_id,
      thunk_section->name(),
      BlockGraph::CODE_BLOCK,
      thunk_section->id(),
      1,
      0);

  BasicCodeBlock* bb = bbsg.AddBasicCodeBlock(stub_name_with_id);
  block_desc->basic_block_order.push_back(bb);
  BasicBlockAssembler assm(bb->instructions().begin(), &bb->instructions());

  if (mode == AsanBasicBlockTransform::kReadAccess ||
      mode == AsanBasicBlockTransform::kWriteAccess) {
    // The thunk body restores the original value of EDX and cleans the stack on
    // return.
    assm.mov(core::edx, Operand(core::esp, Displacement(4)));
    assm.ret(4);
  } else {
    assm.ret();
  }

  // Condense into a block.
  BlockBuilder block_builder(block_graph);
  if (!block_builder.Merge(&bbsg)) {
    LOG(ERROR) << "Failed to build thunk block.";
    return NULL;
  }

  // Exactly one new block should have been created.
  DCHECK_EQ(1u, block_builder.new_blocks().size());
  BlockGraph::Block* thunk = block_builder.new_blocks().front();

  *reference = BlockGraph::Reference(BlockGraph::ABSOLUTE_REF, 4, thunk, 0, 0);

  return true;
}

}  // namespace

const char AsanBasicBlockTransform::kTransformName[] =
    "SyzyAsanBasicBlockTransform";

bool AsanBasicBlockTransform::InstrumentBasicBlock(
    BasicCodeBlock* basic_block, StackAccessMode stack_mode) {
  DCHECK(basic_block != NULL);

  // Pre-compute liveness information for each instruction.
  std::list<LivenessAnalysis::State> states;
  LivenessAnalysis::State state;
  if (use_liveness_analysis_) {
    liveness_.GetStateAtExitOf(basic_block, &state);

    BasicBlock::Instructions::reverse_iterator rev_iter_inst =
        basic_block->instructions().rbegin();
    BasicBlock::Instructions::const_reverse_iterator rev_iter_inst_end =
        basic_block->instructions().rend();
    for (; rev_iter_inst != rev_iter_inst_end; ++rev_iter_inst) {
      const Instruction& instr = *rev_iter_inst;
      liveness_.PropagateBackward(instr, &state);
      states.push_front(state);
    }

    DCHECK_EQ(states.size(), basic_block->instructions().size());
  }

  // Get the memory accesses information for this basic block.
  MemoryAccessAnalysis::State memory_state;
  if (remove_redundant_checks_)
    memory_accesses_.GetStateAtEntryOf(basic_block, &memory_state);

  // Process each instruction and inject a call to Asan when we find an
  // instrumentable memory access.
  BasicBlock::Instructions::iterator iter_inst =
      basic_block->instructions().begin();
  std::list<LivenessAnalysis::State>::iterator iter_state = states.begin();
  for (; iter_inst != basic_block->instructions().end(); ++iter_inst) {
    Operand operand(core::eax);
    const Instruction& instr = *iter_inst;
    const _DInst& repr = instr.representation();

    MemoryAccessInfo info;
    info.mode = kNoAccess;
    info.size = 0;
    info.opcode = 0;
    info.save_flags = true;

    // Get current instruction liveness information.
    if (use_liveness_analysis_) {
      state = *iter_state;
      ++iter_state;
    }

    // When activated, skip redundant memory access check.
    if (remove_redundant_checks_) {
      bool need_memory_access_check = false;
      if (memory_state.HasNonRedundantAccess(instr))
        need_memory_access_check = true;

      // Update the memory accesses information for the current instruction.
      memory_accesses_.PropagateForward(instr, &memory_state);

      if (!need_memory_access_check)
        continue;
    }

    // Insert hook for a standard instruction.
    if (!DecodeMemoryAccess(instr, &operand, &info))
      continue;

    // Bail if this is not a memory access.
    if (info.mode == kNoAccess)
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

    // If there are no unconventional manipulations of the stack frame, we can
    // skip instrumenting stack-based memory access (based on ESP or EBP).
    // Conventionally, accesses through ESP/EBP are always on stack.
    if (stack_mode == kSafeStackAccess &&
        (operand.base() == core::kRegisterEsp ||
         operand.base() == core::kRegisterEbp)) {
      continue;
    }

    // We do not instrument memory accesses through special segments.
    // FS is used for thread local specifics and GS for CPU info.
    uint8_t segment = SEGMENT_GET(repr.segment);
    if (segment == R_FS || segment == R_GS)
      continue;

    // Finally, don't instrument any filtered instructions.
    if (IsFiltered(*iter_inst))
      continue;

    // Create a BasicBlockAssembler to insert new instruction.
    BasicBlockAssembler bb_asm(iter_inst, &basic_block->instructions());

    // Configure the assembler to copy the SourceRange information of the
    // current instrumented instruction into newly created instructions. This is
    // a hack to allow valid stack walking and better error reporting, but
    // breaks the 1:1 OMAP mapping and may confuse some debuggers.
    if (debug_friendly_)
      bb_asm.set_source_range(instr.source_range());

    if (use_liveness_analysis_ &&
        (info.mode == kReadAccess || info.mode == kWriteAccess)) {
      // Use the liveness information to skip saving the flags if possible.
      info.save_flags = state.AreArithmeticFlagsLive();
    }

    // Insert hook for standard instructions.
    AsanHookMap::iterator hook = check_access_hooks_->find(info);
    if (hook == check_access_hooks_->end()) {
      LOG(ERROR) << "Invalid access : " << GetAsanCheckAccessFunctionName(info);
      return false;
    }

    // Instrument this instruction.
    InjectAsanHook(&bb_asm, info, operand, &hook->second, state);
  }

  DCHECK(iter_state == states.end());

  return true;
}

bool AsanBasicBlockTransform::TransformBasicBlockSubGraph(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BasicBlockSubGraph* subgraph) {
  DCHECK(policy != NULL);
  DCHECK(block_graph != NULL);
  DCHECK(subgraph != NULL);

  // Perform a global liveness analysis.
  if (use_liveness_analysis_)
    liveness_.Analyze(subgraph);

  // Perform a redundant memory access analysis.
  if (remove_redundant_checks_)
    memory_accesses_.Analyze(subgraph);

  // Determines if this subgraph uses unconventional stack pointer
  // manipulations.
  StackAccessMode stack_mode = kUnsafeStackAccess;
  if (!block_graph::HasUnexpectedStackFrameManipulation(subgraph))
    stack_mode = kSafeStackAccess;

  // Iterates through each basic block and instruments it.
  BasicBlockSubGraph::BBCollection::iterator it =
      subgraph->basic_blocks().begin();
  for (; it != subgraph->basic_blocks().end(); ++it) {
    BasicCodeBlock* bb = BasicCodeBlock::Cast(*it);
    if (bb != NULL && !InstrumentBasicBlock(bb, stack_mode))
      return false;
  }
  return true;
}

const char AsanTransform::kTransformName[] = "SyzyAsanTransform";

const char AsanTransform::kAsanHookStubName[] = "asan_hook_stub";

const char AsanTransform::kSyzyAsanDll[] = "syzyasan_rtl.dll";

AsanTransform::AsanTransform()
    : asan_dll_name_(kSyzyAsanDll),
      debug_friendly_(false),
      use_liveness_analysis_(false),
      remove_redundant_checks_(false),
      use_interceptors_(false),
      check_access_hooks_ref_() {
}

bool AsanTransform::PreBlockGraphIteration(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {
  DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), header_block);

  // Ensure that this image has not already been instrumented.
  if (block_graph->FindSection(common::kThunkSectionName)) {
    LOG(ERROR) << "The image is already instrumented.";
    return false;
  }

  AccessHookParamVector access_hook_param_vec;
  AsanBasicBlockTransform::AsanDefaultHookMap default_stub_map;

  // Create the hook stub for read/write instructions.
  BlockGraph::Reference read_write_hook;
  if (!CreateHooksStub(block_graph, kAsanHookStubName,
                       AsanBasicBlockTransform::kReadAccess,
                       &read_write_hook)) {
    return false;
  }

  // Create the hook stub for strings instructions.
  BlockGraph::Reference instr_hook;
  if (!CreateHooksStub(block_graph, kAsanHookStubName,
                       AsanBasicBlockTransform::kInstrAccess,
                       &instr_hook)) {
    return false;
  }

  // Map each memory access kind to an appropriate stub.
  default_stub_map[AsanBasicBlockTransform::kReadAccess] = read_write_hook;
  default_stub_map[AsanBasicBlockTransform::kWriteAccess] = read_write_hook;
  default_stub_map[AsanBasicBlockTransform::kInstrAccess] = instr_hook;
  default_stub_map[AsanBasicBlockTransform::kRepzAccess] = instr_hook;
  default_stub_map[AsanBasicBlockTransform::kRepnzAccess] = instr_hook;

  // Add an import entry for the ASAN runtime.
  ImportedModule import_module(asan_dll_name_);

  // Import the hooks for the read/write accesses.
  for (int access_size = 1; access_size <= 32; access_size *= 2) {
    MemoryAccessInfo read_info =
        { AsanBasicBlockTransform::kReadAccess, access_size, 0, true };
    access_hook_param_vec.push_back(read_info);
    if (use_liveness_analysis()) {
      read_info.save_flags = false;
      access_hook_param_vec.push_back(read_info);
    }

    MemoryAccessInfo write_info =
        { AsanBasicBlockTransform::kWriteAccess, access_size, 0, true };
    access_hook_param_vec.push_back(write_info);
    if (use_liveness_analysis()) {
      write_info.save_flags = false;
      access_hook_param_vec.push_back(write_info);
    }
  }

  // Import the hooks for the read/write 10-bytes accesses.
  MemoryAccessInfo read_info_10 =
      { AsanBasicBlockTransform::kReadAccess, 10, 0, true };
  access_hook_param_vec.push_back(read_info_10);
  if (use_liveness_analysis()) {
    read_info_10.save_flags = false;
    access_hook_param_vec.push_back(read_info_10);
  }

  MemoryAccessInfo write_info_10 =
      { AsanBasicBlockTransform::kWriteAccess, 10, 0, true };
  access_hook_param_vec.push_back(write_info_10);
  if (use_liveness_analysis()) {
    write_info_10.save_flags = false;
    access_hook_param_vec.push_back(write_info_10);
  }

  // Import the hooks for strings/prefix memory accesses.
  const _InstructionType strings[] = { I_CMPS, I_MOVS, I_STOS };
  int strings_length = sizeof(strings)/sizeof(_InstructionType);

  for (int access_size = 1; access_size <= 4; access_size *= 2) {
    for (int inst = 0; inst < strings_length; ++inst) {
      MemoryAccessInfo repz_inst_info = {
         AsanBasicBlockTransform::kRepzAccess,
         access_size,
         strings[inst],
         true
      };
      access_hook_param_vec.push_back(repz_inst_info);

      MemoryAccessInfo inst_info = {
          AsanBasicBlockTransform::kInstrAccess,
          access_size,
          strings[inst],
          true
      };
      access_hook_param_vec.push_back(inst_info);
    }
  }

  if (!AddAsanCheckAccessHooks(access_hook_param_vec,
                               default_stub_map,
                               &import_module,
                               &check_access_hooks_ref_,
                               policy,
                               block_graph,
                               header_block)) {
    return false;
  }
  return true;
}

bool AsanTransform::OnBlock(const TransformPolicyInterface* policy,
                            BlockGraph* block_graph,
                            BlockGraph::Block* block) {
  DCHECK(policy != NULL);
  DCHECK(block_graph != NULL);
  DCHECK(block != NULL);

  if (!policy->BlockIsSafeToBasicBlockDecompose(block))
    return true;

  // Use the filter that was passed to us for our child transform.
  AsanBasicBlockTransform transform(&check_access_hooks_ref_);
  transform.set_debug_friendly(debug_friendly());
  transform.set_use_liveness_analysis(use_liveness_analysis());
  transform.set_remove_redundant_checks(remove_redundant_checks());
  transform.set_filter(filter());

  if (!ApplyBasicBlockSubGraphTransform(
          &transform, policy, block_graph, block, NULL)) {
    return false;
  }

  return true;
}

bool AsanTransform::PostBlockGraphIteration(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {
  DCHECK(policy != NULL);
  DCHECK(block_graph != NULL);
  DCHECK(header_block != NULL);

  // This function redirects the heap-related kernel32 imports to point to a set
  // of "override" imports in the ASAN runtime.

  static const size_t kInvalidIndex = -1;

  static const char* kKernel32RedirectionPrefix = "asan_";
  struct Kernel32ImportRedirect {
    const char* import_name;
    std::pair<size_t, size_t> override_indexes;
  };
  static const Kernel32ImportRedirect kKernel32HeapRedirects[] = {
    { "GetProcessHeap" },
    { "HeapCreate" },
    { "HeapDestroy" },
    { "HeapAlloc" },
    { "HeapReAlloc" },
    { "HeapFree" },
    { "HeapSize" },
    { "HeapValidate" },
    { "HeapCompact" },
    { "HeapLock" },
    { "HeapUnlock" },
    { "HeapWalk" },
    { "HeapSetInformation" },
    { "HeapQueryInformation" },
  };
  static const Kernel32ImportRedirect kKernel32FunctionRedirects[] = {
    { "ReadFile" },
    { "WriteFile" },
  };

  // TODO(sebmarchand): Use the RedirectImport transform when it's ready.
  std::vector<Kernel32ImportRedirect> kernel32_redirects;
  for (size_t i = 0; i < arraysize(kKernel32HeapRedirects); ++i)
    kernel32_redirects.push_back(kKernel32HeapRedirects[i]);

  if (use_interceptors_) {
    for (size_t i = 0; i < arraysize(kKernel32FunctionRedirects); ++i)
      kernel32_redirects.push_back(kKernel32FunctionRedirects[i]);
  }

  // Initialize the module info for querying kernel32 imports.
  ImportedModule module_kernel32("kernel32.dll");
  std::vector<Kernel32ImportRedirect>::iterator iter =
      kernel32_redirects.begin();
  for (; iter != kernel32_redirects.end(); ++iter) {
    size_t kernel32_index =
        module_kernel32.AddSymbol(iter->import_name,
                                  ImportedModule::kFindOnly);
    iter->override_indexes = std::make_pair(kernel32_index, kInvalidIndex);
  }

  // Query the kernel32 imports.
  PEAddImportsTransform find_kernel_imports;
  find_kernel_imports.AddModule(&module_kernel32);
  if (!find_kernel_imports.TransformBlockGraph(
          policy, block_graph, header_block)) {
    LOG(ERROR) << "Unable to find kernel32 imports for redirection.";
    return false;
  }

  // The timestamp 1 corresponds to Thursday, 01 Jan 1970 00:00:01 GMT. Setting
  // the timestamp of the image import descriptor to this value allows us to
  // temporarily bind the library until the loader finishes loading this module.
  // As the value is far in the past this means that the entries in the IAT for
  // this module will all be replaced by pointers into the actual library.
  // We need to bind the IAT for our module to make sure the stub is used until
  // the sandbox lets the loader finish patching the IAT entries.
  static const size_t kDateInThePast = 1;

  // Add ASAN imports for those kernel32 functions we found. These will later
  // be redirected.
  ImportedModule module_asan(asan_dll_name_, kDateInThePast);
  iter = kernel32_redirects.begin();
  for (; iter != kernel32_redirects.end(); ++iter) {
    size_t kernel32_index = iter->override_indexes.first;
    if (module_kernel32.SymbolIsImported(kernel32_index)) {
      size_t asan_index = module_asan.AddSymbol(
          base::StringPrintf("%s%s",
                             kKernel32RedirectionPrefix,
                             iter->import_name),
          ImportedModule::kAlwaysImport);
      DCHECK_EQ(kInvalidIndex, iter->override_indexes.second);
      iter->override_indexes.second = asan_index;
    }
  }

  // Another transform can safely be run without invalidating the results
  // stored in module_kernel32, as additions to the IAT will strictly be
  // performed at the end.
  PEAddImportsTransform add_imports_transform;
  add_imports_transform.AddModule(&module_asan);
  if (!add_imports_transform.TransformBlockGraph(
          policy, block_graph, header_block)) {
    LOG(ERROR) << "Unable to add imports for import redirection.";
    return false;
  }

  // Stores the reference mapping we want to rewrite.
  pe::ReferenceMap reference_redirect_map;

  iter = kernel32_redirects.begin();
  for (; iter != kernel32_redirects.end(); ++iter) {
    // Symbols that aren't imported don't need to be redirected.
    size_t kernel32_index = iter->override_indexes.first;
    size_t asan_index = iter->override_indexes.second;
    if (!module_kernel32.SymbolIsImported(kernel32_index)) {
      DCHECK_EQ(kInvalidIndex, asan_index);
      continue;
    }

    DCHECK_NE(kInvalidIndex, asan_index);
    BlockGraph::Reference src;
    BlockGraph::Reference dst;
    if (!module_kernel32.GetSymbolReference(kernel32_index, &src) ||
        !module_asan.GetSymbolReference(asan_index, &dst)) {
       NOTREACHED() << "Unable to get references after a successful transform.";
      return false;
    }

    // Record the reference mapping.
    reference_redirect_map.insert(
        std::make_pair(pe::ReferenceDest(src.referenced(), src.offset()),
                       pe::ReferenceDest(dst.referenced(), dst.offset())));
  }

  // Redirect the references.
  pe::RedirectReferences(reference_redirect_map);

  if (use_interceptors_) {
    FunctionInterceptionSet interception_set;
    interception_set.insert("memchr");
    interception_set.insert("memcpy");
    interception_set.insert("memmove");
    interception_set.insert("memset");
    interception_set.insert("strcspn");
    interception_set.insert("strlen");
    interception_set.insert("strrchr");
    interception_set.insert("strcmp");
    interception_set.insert("strpbrk");
    interception_set.insert("strstr");
    interception_set.insert("strspn");
    interception_set.insert("strncpy");
    interception_set.insert("strncat");
    interception_set.insert("wcsrchr");
    InterceptFunctions(&module_asan,
                       policy,
                       block_graph,
                       header_block,
                       interception_set);
  }

  return true;
}

bool AsanTransform::InterceptFunctions(
    ImportedModule* import_module,
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* header_block,
    const FunctionInterceptionSet& functions_set) {
  DCHECK(import_module != NULL);
  DCHECK(block_graph != NULL);
  DCHECK(header_block != NULL);

  // The map containing the information about the functions that we want to
  // intercept.
  FunctionInterceptionInfoMap function_redirection_info_map;

  // Find the blocks that we want to intercept. This is O(N log(M)), with N
  // being the number of blocks in the image and M the number of functions that
  // we want to intercept.
  block_graph::BlockGraph::BlockMap::iterator iter_blocks =
      block_graph->blocks_mutable().begin();
  for (; iter_blocks != block_graph->blocks_mutable().end(); ++iter_blocks) {
    if (functions_set.find(iter_blocks->second.name()) == functions_set.end())
      continue;

    // Generate the name of the hook for this function and add it to the image.
    std::string hook_name = base::StringPrintf("asan_%s",
        iter_blocks->second.name().c_str());
    size_t symbol_index =
        import_module->AddSymbol(hook_name, ImportedModule::kAlwaysImport);

    // Save the information about this block.
    function_redirection_info_map[
        iter_blocks->second.name()].asan_symbol_index = symbol_index;
    function_redirection_info_map[iter_blocks->second.name()].function_block =
        &iter_blocks->second;
  }

  // Transforms the block-graph.
  PEAddImportsTransform add_imports_transform;
  add_imports_transform.AddModule(import_module);
  if (!add_imports_transform.TransformBlockGraph(
          policy, block_graph, header_block)) {
    LOG(ERROR) << "Unable to add imports for Asan instrumentation DLL.";
    return false;
  }

  // Find or create the section we put our thunks in.
  BlockGraph::Section* thunk_section = block_graph->FindOrAddSection(
      common::kThunkSectionName, pe::kCodeCharacteristics);

  if (thunk_section == NULL) {
    LOG(ERROR) << "Unable to find or create " << common::kThunkSectionName
               << " section.";
    return false;
  }

  // For every function that we want to intercept we create a thunk that'll
  // verify the parameters and call the original function.
  FunctionInterceptionInfoMap::iterator iter_redirection_info =
      function_redirection_info_map.begin();
  for (; iter_redirection_info != function_redirection_info_map.end();
       ++iter_redirection_info) {
    DCHECK(iter_redirection_info->second.function_block != NULL);
    DCHECK_NE(~0U, iter_redirection_info->second.asan_symbol_index);
    BlockGraph::Reference import_reference;
    if (!import_module->GetSymbolReference(
            iter_redirection_info->second.asan_symbol_index,
            &import_reference)) {
      LOG(ERROR) << "Unable to get import reference for Asan.";
      return false;
    }

    // Generate the name of the thunk for this function.
    std::string thunk_name = base::StringPrintf("asan_%s_thunk",
        iter_redirection_info->first.data());

    // Generate a basic code block for this thunk.
    BasicBlockSubGraph bbsg;
    BasicBlockSubGraph::BlockDescription* block_desc = bbsg.AddBlockDescription(
        thunk_name,
        thunk_section->name(),
        BlockGraph::CODE_BLOCK,
        thunk_section->id(),
        1,
        0);
    BasicCodeBlock* bb = bbsg.AddBasicCodeBlock(thunk_name);
    block_desc->basic_block_order.push_back(bb);
    BasicBlockAssembler assm(bb->instructions().begin(), &bb->instructions());
    assm.jmp(Operand(Displacement(import_reference.referenced(),
                                  import_reference.offset())));

    // Condense into a block.
    BlockBuilder block_builder(block_graph);
    if (!block_builder.Merge(&bbsg)) {
      LOG(ERROR) << "Failed to build thunk block.";
      return false;
    }

    // Exactly one new block should have been created.
    DCHECK_EQ(1u, block_builder.new_blocks().size());
    BlockGraph::Block* thunk = block_builder.new_blocks().front();

    // Transfer the references to the original block to the thunk.
    if (!iter_redirection_info->second.function_block->TransferReferrers(0,
            thunk, BlockGraph::Block::kSkipInternalReferences)) {
      LOG(ERROR) << "Failed to redirect the reference during the interception "
                 << "of a function.";
      return false;
    }

    // Temporarily make the interceptor imports point to their original
    // function. These references will be ... has been loaded. This is necessary
    // so that Chrome sandbox code (which runs under the loader lock before all
    // imports have been resolved) doesn't crash.
    import_reference.referenced()->SetReference(import_reference.offset(),
        BlockGraph::Reference(BlockGraph::ABSOLUTE_REF, 4,
            iter_redirection_info->second.function_block, 0, 0));
  }

  return true;
}

bool operator<(const AsanBasicBlockTransform::MemoryAccessInfo& left,
               const AsanBasicBlockTransform::MemoryAccessInfo& right) {
  if (left.mode != right.mode)
    return left.mode < right.mode;
  if (left.size != right.size)
    return left.size < right.size;
  if (left.save_flags != right.save_flags)
    return left.save_flags < right.save_flags;
  return left.opcode < right.opcode;
}

}  // namespace transforms
}  // namespace instrument
