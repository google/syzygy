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

#include "syzygy/block_graph/transforms/fuzzing_transform.h"

#include "base/logging.h"
#include "base/string_util.h"
#include "base/stringprintf.h"
#include "syzygy/block_graph/basic_block_assembler.h"
#include "syzygy/block_graph/block_builder.h"
#include "syzygy/block_graph/block_util.h"
#include "syzygy/block_graph/analysis/liveness_analysis.h"
#include "syzygy/common/defs.h"

namespace block_graph {
namespace transforms {
namespace {

using block_graph::BasicBlock;
using block_graph::BasicBlockAssembler;
using block_graph::BasicCodeBlock;
using block_graph::Instruction;
using block_graph::Immediate;
using core::Register;

}  // namespace

const char LivenessFuzzingBasicBlockTransform::kTransformName[]
    = "LivenessFuzzingBasicBlockTransform";
const char FuzzingTransform::kTransformName[] = "FuzzingTransform";

bool LivenessFuzzingBasicBlockTransform::TransformBasicBlockSubGraph(
    BlockGraph* block_graph, BasicBlockSubGraph* subgraph) {
  DCHECK(block_graph != NULL);
  DCHECK(subgraph != NULL);

  // Perform the global liveness analysis.
  block_graph::analysis::LivenessAnalysis liveness;
  liveness.Analyze(subgraph);

  // Iterate through each basic block and instrument it.
  BasicBlockSubGraph::BBCollection::iterator bb_iter =
      subgraph->basic_blocks().begin();
  for (; bb_iter != subgraph->basic_blocks().end(); ++bb_iter) {
    BasicCodeBlock* bb = BasicCodeBlock::Cast(*bb_iter);
    if (bb == NULL)
      continue;

    block_graph::analysis::LivenessAnalysis::State state;
    liveness.GetStateAtExitOf(bb, &state);

    BasicBlock::Instructions& instructions = bb->instructions();

    if (instructions.empty())
      continue;

    BasicBlock::Instructions::iterator instr_iter = instructions.end();
    --instr_iter;

    while (true) {
      // Propagate liveness through the current instruction.
      Instruction instr = *instr_iter;
      liveness.PropagateBackward(instr, &state);

      // Rewrite dead registers.
      uint32 reg_code = core::kRegisterEax;
      for ( ; reg_code <= core::kRegisterEdi; ++reg_code) {
        Register reg(static_cast<core::RegisterCode>(reg_code));
        if (state.IsLive(reg))
          continue;

        BasicBlockAssembler assembly(instr_iter, &instructions);

        // Write some garbage in the dead register.
        assembly.mov(reg, Immediate(0xCCCCCCCC));
        --instr_iter;
      }

      if (!state.AreArithmeticFlagsLive()) {
        // Write some garbage to the flags register when they are not alive.
        BasicBlockAssembler assembly(instr_iter, &instructions);
        assembly.add(core::ebp, Immediate(0, core::kSize32Bit));
        --instr_iter;
      }

      // Move to the previous instruction.
      if (instr_iter == instructions.begin())
        break;
      --instr_iter;
    }
  }

  return true;
}

FuzzingTransform::FuzzingTransform() {
}

bool FuzzingTransform::OnBlock(
    BlockGraph* block_graph, BlockGraph::Block* block) {

  DCHECK(block_graph != NULL);
  DCHECK(block != NULL);
  if (block->type() != BlockGraph::CODE_BLOCK)
    return true;

  if (!CodeBlockAttributesAreBasicBlockSafe(block))
    return true;

  // Apply a basic block transform.
  LivenessFuzzingBasicBlockTransform liveness_transform;
  if (!ApplyBasicBlockSubGraphTransform(
          &liveness_transform, block_graph, block, NULL)) {
    return false;
  }

  return true;
}

}  // namespace transforms
}  // namespace block_graph
