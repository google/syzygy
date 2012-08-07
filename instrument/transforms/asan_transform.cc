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
#include "syzygy/block_graph/basic_block_assembler.h"
#include "syzygy/pe/block_util.h"
#include "syzygy/pe/transforms/add_imports_transform.h"
#include "third_party/distorm/files/include/mnemonics.h"
#include "third_party/distorm/files/src/x86defs.h"

namespace pe {
namespace transforms {
namespace {

using block_graph::BasicBlock;
using block_graph::BasicBlockAssembler;
using block_graph::BasicBlockSubGraph;
using block_graph::BlockGraph;
using block_graph::Displacement;
using block_graph::Immediate;
using block_graph::Instruction;
using block_graph::Operand;
using block_graph::Value;
using core::Register;
using core::RegisterCode;

// Represent the different kind of access to the memory.
enum MemoryAccessMode {
  kNoAccess,
  kReadAccess,
  kWriteAccess,
};

// Returns true iff opcode is instrumentable.
bool IsInstrumentable(uint16 opcode) {
  switch (opcode) {
    case I_LEA:
    case I_CALL:
    case I_JMP:
      return false;
    default:
      return true;
  }
}

// Decodes the first O_MEM or O_SMEM operand of @p instr, if any to the
// corresponding Operand.
MemoryAccessMode DecodeMemoryAccess(const Instruction::Representation& instr,
                                    Operand* access) {
  DCHECK(access != NULL);

  MemoryAccessMode access_mode = kNoAccess;
  if (instr.ops[0].type == O_SMEM || instr.ops[1].type == O_SMEM) {
    // Simple memory dereference with optional displacement.
    uint8 mem_op_id = instr.ops[0].type == O_SMEM ? 0 : 1;
    access_mode = mem_op_id == 0 ? kWriteAccess : kReadAccess;
    Register base_reg(RegisterCode(instr.ops[mem_op_id].index - R_EAX));
    *access = Operand(base_reg, Displacement(instr.disp));
  } else if (instr.ops[0].type == O_MEM || instr.ops[1].type == O_MEM) {
    // Complex memory dereference.
    uint8 mem_op_id = instr.ops[0].type == O_MEM ? 0 : 1;
    access_mode = mem_op_id == 0 ? kWriteAccess : kReadAccess;
    Register index_reg(RegisterCode(instr.ops[mem_op_id].index - R_EAX));
    core::ScaleFactor scale = core::kTimes1;
    switch (instr.scale) {
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
    if (instr.base != R_NONE) {
      Register base_reg(RegisterCode(instr.base - R_EAX));
      *access = Operand(base_reg, index_reg, scale, Displacement(instr.disp));
    } else {
      *access = Operand(index_reg, scale, Displacement(instr.disp));
    }
  }
  return access_mode;
}

// Use @p bb_asm to inject a hook to @p hook to instrument the access to the
// address stored in the operand @p op.
void InjectAsanHook(BasicBlockAssembler* bb_asm, Operand op,
                    BlockGraph::Reference* hook) {
  DCHECK(hook != NULL);
  bb_asm->push(core::eax);
  bb_asm->lea(core::eax, op);
  bb_asm->call(Operand(Displacement(hook->referenced(), hook->offset())));
}

}  // namespace

const char AsanBasicBlockTransform::kTransformName[] =
    "SyzyAsanBasicBlockTransform";

bool AsanBasicBlockTransform::InstrumentBasicBlock(BasicBlock* basic_block) {
  DCHECK(basic_block != NULL);
  BasicBlock::Instructions::iterator iter_inst =
      basic_block->instructions().begin();
  // Process each instruction and inject a call to Asan when we find a memory
  // access.
  for (; iter_inst != basic_block->instructions().end(); ++iter_inst) {
    Operand operand(core::eax);
    MemoryAccessMode access_mode = DecodeMemoryAccess(
        iter_inst->representation(), &operand);
    if (access_mode != kNoAccess &&
        IsInstrumentable(iter_inst->representation().opcode) &&
        iter_inst->data()[0] != PREFIX_OP_SIZE) {
      BasicBlockAssembler bb_asm(iter_inst, &basic_block->instructions());
      Instruction::Representation inst = iter_inst->representation();
      InjectAsanHook(&bb_asm, operand,
          access_mode == kWriteAccess ? hook_write_ : hook_read_);
    }
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
