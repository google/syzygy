#ifndef SYZYGY_PROTECT_PROTECT_LIB_EQUATION_GEN_H_
#define SYZYGY_PROTECT_PROTECT_LIB_EQUATION_GEN_H_

#include <vector>

#include "syzygy/assm/assembler.h"
#include "syzygy/assm/assembler_base.h"
#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/basic_block_assembler.h"

class Equation {
public:
  // Maximum of 2 unknown variables
  std::vector<int> x_exp;
  std::vector<int> x_coef;
  std::vector<int> y_exp;
  std::vector<int> y_coef;

  Equation(std::vector<int> x_exp, std::vector<int> x_coef,
    std::vector<int> y_exp, std::vector<int> y_coef) :
    x_exp(x_exp), x_coef(x_coef), y_exp(y_exp), y_coef(y_coef) {};

  assm::ConditionCode Generate(block_graph::BasicBlockAssembler &assm,
                               std::vector<assm::Register32> &temp_regs,
							   std::vector<assm::Register32> &source_regs);
};

#endif  // SYZYGY_PROTECT_PROTECT_LIB_EQUATION_CHECKER_H_