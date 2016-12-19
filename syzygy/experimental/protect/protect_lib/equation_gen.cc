#include <string.h>
#include <algorithm>
#include <iostream>
#include <vector>
#include <type_traits>
#include <iterator>

#include "syzygy/core/disassembler_util.h"
#include "syzygy/assm/assembler.h"
#include "syzygy/assm/assembler_base.h"
#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/basic_block_assembler.h"
#include "syzygy/block_graph/basic_block_decomposer.h"

#include "syzygy/experimental/protect/protect_lib/equation_gen.h"

void GenerateMonomial(block_graph::BasicBlockAssembler &assm,
                      assm::Register32 &temp,
                      assm::Register32 source,
					  int exp,
					  int coef)
{
  // Result will be stored in temp
  if (exp == 0) {
    assm.mov(temp, block_graph::Immediate(coef, assm::ValueSize::kSize32Bit));
    return;
  }

  assm.mov(temp, source);
  exp--;

  while (exp > 0) {
    assm.imul(temp, source);
    exp--;
  }
}

void GenerateSingleVarPolinomial(block_graph::BasicBlockAssembler &assm,
  std::vector<assm::Register32>::iterator temp_regs_start,
  std::vector<assm::Register32>::iterator temp_regs_stop,
  assm::Register32 &acc, assm::Register32 source,
  std::vector<int> &source_exp, std::vector<int> &source_coef)
{
  if (temp_regs_start == temp_regs_stop) {
    assm.nop(4);
    return;
  }

  assm::Register32 monomial_temp = *temp_regs_start;

  GenerateMonomial(assm, acc, source, source_exp[0], source_coef[0]);

  for (int i = 1; i < (int)source_exp.size(); ++i) {
    GenerateMonomial(assm, monomial_temp, source, source_exp[i],
	                 source_coef[i]);
    assm.add(acc, monomial_temp);
  }
}

assm::ConditionCode Equation::Generate(
  block_graph::BasicBlockAssembler &assm,
  std::vector<assm::Register32> &temp_regs,
  std::vector<assm::Register32> &source_regs)
{
  assm::Register32 acc = temp_regs[0];
  assm::Register32 temp = acc;
  assm::Register32 source_x = source_regs[0];
  assm::Register32 source_y = source_regs[0];
  assm::ConditionCode ret = assm::ConditionCode::kNotEqual;

  GenerateSingleVarPolinomial(assm, temp_regs.begin() + 1, temp_regs.end(),
                              temp, source_x, this->x_exp, this->x_coef);

  if (source_regs.size() > 1) {
    temp = temp_regs[1];
    source_y = source_regs[1];

    GenerateSingleVarPolinomial(assm, temp_regs.begin() + 2, temp_regs.end(),
                                temp, source_y, this->y_exp, this->y_coef);

    assm.add(acc, temp);
  }

  // Generate condition
  assm.cmp(acc, block_graph::Immediate(0, assm::ValueSize::kSize8Bit));

  return ret;
}