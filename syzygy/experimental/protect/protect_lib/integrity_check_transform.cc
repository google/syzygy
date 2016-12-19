// Copyright 2015 Google Inc. All Rights Reserved.
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
#include "syzygy/experimental/protect/protect_lib/integrity_check_transform.h"
#include <fstream>
#include <stack>
#include <algorithm>
#include <random>
#include "syzygy/assm/assembler.h"
#include "syzygy/assm/assembler_base.h"
#include "syzygy/block_graph/basic_block_assembler.h"
#include "syzygy/block_graph/basic_block_decomposer.h"
#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/block_builder.h"
#include "syzygy/block_graph/block_util.h"
#include "syzygy/optimize/transforms/subgraph_transform.h"
#include "syzygy/experimental/protect/protect_lib/code_randomizer.h"
#include "syzygy/experimental/protect/protect_lib/protect_utils.h"
#include <iostream>
//#define PRINT_BLOCK_NAMES
namespace protect {

namespace {

using block_graph::BasicBlockDecomposer;
using block_graph::BasicBlockSubGraph;
using block_graph::BlockBuilder;
using block_graph::BlockGraph;
using block_graph::BlockVector;
using block_graph::BasicBlock;
using block_graph::BasicCodeBlock;
using block_graph::Instruction;
using block_graph::BasicBlockReference;

typedef BasicBlockSubGraph::BBCollection BBCollection;
typedef BasicBlock::Instructions Instructions;
typedef BlockGraph::Block::ReferrerSet ReferrerSet;
typedef std::list<BlockGraph::Block*> BlockOrdering;

 // Retrieves a unique identifier for a basic block.
 // @param bb the basic block to be uniquely identifed.
 // @param subgraph basic block subgraph in which the basic block resides.
 // @return a unique ID for the basic block.
uint64_t GetBasicBlockId(const BasicBlock *bb,
                         const BasicBlockSubGraph *subgraph) {
  DCHECK(bb);
  DCHECK(subgraph);

  auto original_block = subgraph->original_block();
  DCHECK(original_block);

  return ((uint64_t)bb->offset() << 32) + original_block->id();
}

 // Retrieves the block where the _putwch_nolock function is declared.
 // @param bragph block graph where to search of the function.
 // @return the block where the function is declared.
block_graph::BlockGraph::Block* GetPutwchNolock(
    block_graph::BlockGraph* bgraph) {
  DCHECK(bgraph);
  block_graph::BlockGraph::Block *putwch_nolock = nullptr;

  auto it = bgraph->blocks().begin();
  for (; it != bgraph->blocks().end(); ++it)
   if ((*it).second.name().compare("_putwch_nolock") == 0) {
    putwch_nolock = bgraph->GetBlockById((*it).second.id());
    break;
   }
  return putwch_nolock;
}

 // Adds assembly code for response function to a block graph.
 // @param bgraph the block graph from where the response function is inserted.
 // @return the block containing the newly inseted response function.
BlockGraph::Block* AddResponseFunction(BlockGraph* bgraph) {
  DCHECK(bgraph);
  //TODO:BlockGraph::Block *response_function = GetPutwchNolock(bgraph);
  BasicBlockSubGraph* subgraph = new BasicBlockSubGraph();
  BlockGraph::Section* code_section = bgraph->FindOrAddSection(".text",
   0x60000000);
  std::string bb_name = "response_bb1";
  // Create the thunk for standard "load/store" (received address in EDX).
  BasicBlockSubGraph::BlockDescription* block_desc =
   subgraph->AddBlockDescription(bb_name, code_section->name(),
   BlockGraph::CODE_BLOCK, code_section->id(),
   1, 0);

  BasicCodeBlock* bb = subgraph->AddBasicCodeBlock(bb_name);
  block_desc->basic_block_order.push_back(bb);

  BasicBlock::Instructions::iterator inst_iter = bb->instructions().begin();
  block_graph::BasicBlockAssembler assm(inst_iter,
   &bb->instructions());

  assm.push(assm::eax); // eax contains the actual hash value
  // add size of instructions from hash function return up to response return
  assm.add(assm::ebx, block_graph::Immediate(0xe));
  assm.push(assm::ebx); // edx contains the address where to continue execution
  //TODO:assm.call(block_graph::Immediate(response_function, 0)); // print char
  assm.pop(assm::ebx); // edx gets changed by the previous call
  assm.mov(assm::ebx, block_graph::Immediate((uint32_t)0x0));
  assm.jmp(assm::ebx); // continue normal execution

  // Condense into a block.
  block_graph::BlockBuilder block_builder(bgraph);
  if (!block_builder.Merge(subgraph))
   return nullptr;

  return block_builder.new_blocks().rbegin()[0];
}

 // Adds assembly code for hash function in a block graph.
 // @param bgraph the block graph where the hash function is inserted.
 // @return the block containing the newly inserted hash function.
BlockGraph::Block* AddHashFunction(BlockGraph* bgraph) {
  DCHECK(bgraph);
  BlockGraph::Section* code_section = bgraph->FindOrAddSection(".text",
                                                               0x60000000);
  std::string bb_name = "hash_add_bb1";
  BasicBlockSubGraph* subgraph = new BasicBlockSubGraph();
  // Create the thunk for standard "load/store" (received address in EDX).
  BasicBlockSubGraph::BlockDescription* block_desc =
   subgraph->AddBlockDescription(bb_name, code_section->name(),
   BlockGraph::CODE_BLOCK, code_section->id(),
   1, 0);

  BasicCodeBlock* bb = subgraph->AddBasicCodeBlock(bb_name);
  block_desc->basic_block_order.push_back(bb);

  auto inst_iter = bb->instructions().begin();
  block_graph::BasicBlockAssembler assm(inst_iter,
   &bb->instructions());

  // Create following BB that contains outer loop head.
  bb_name = "hash_add_bb2";
  block_desc = subgraph->AddBlockDescription(bb_name, code_section->name(),
   BlockGraph::CODE_BLOCK,
   code_section->id(), 1, 0);

  bb = subgraph->AddBasicCodeBlock(bb_name);
  block_desc->basic_block_order.push_front(bb);

  // Function prolog.
  assm.push(assm::ebp);
  assm.mov(assm::ebp, assm::esp);

  assm.pop(assm::eax); // pop ebp
  assm.pop(assm::ebx); // pop return addres
  assm.xor(assm::eax, assm::eax); // set eax to 0
  // Get the base address of code section of this PE/DLL.
  auto block_it = bgraph->blocks().begin();
  for (; block_it != bgraph->blocks().end(); ++block_it) {
    BlockGraph::BlockType type = block_it->second.type();
    if (type == BlockGraph::BlockType::DATA_BLOCK)
      break;
  }
  BlockGraph::Block* first_block = bgraph->GetBlockById(block_it->second.id());
  // Get the start address of this basic block.
  assm.mov(assm::ebx, block_graph::Immediate(first_block, 0));
  // Compute hash of address.
  assm.add(assm::al, assm::bl);
  assm.add(assm::al, assm::bh);
  assm.shr(assm::ebx, block_graph::Immediate(0x10));
  assm.add(assm::al, assm::bl);
  assm.add(assm::al, assm::bh);
  // Save this hash of the address on the stack.
  assm.pop(assm::ebx); // This is the designeated slot for the hash of address.
  assm.pop(assm::ebx); // This is the designeated slot for the accumulator.
  assm.xor(assm::ebx, assm::ebx); // Set accumulator to 0.
  assm.push(assm::ebx); // Save accumulator.
  assm.push(assm::eax); // Save hash of address.

  assm.j(assm::ConditionCode::kEqual,
   block_graph::Immediate(bb));

  inst_iter = bb->instructions().begin();
  block_graph::BasicBlockAssembler assm2(inst_iter,
   &bb->instructions());

  // Begin outer loop over all checkees passed to the hash function.
  assm2.pop(assm::ebx); // Hash of address.
  assm2.pop(assm::eax); // Accumulator for hash.
  assm2.pop(assm::edx); // Get address of bb to hash.
  assm2.sub(assm::ecx, block_graph::Immediate(1));
  assm2.xchg(assm::ecx,
   assm::OperandBase<block_graph::UntypedReference>(assm::esp));
  assm2.push(assm::eax); // Accumulator for hash.
  assm2.push(assm::ebx); // Hash of address.
  assm2.sub(assm::eax, assm::eax); // Set eax to zero.

  // Create following BB that contains inner loop over bytes of checkee.
  bb_name = "hash_add_bb3";
  block_desc = subgraph->AddBlockDescription(bb_name,
                                             code_section->name(),
                                             BlockGraph::CODE_BLOCK,
                                             code_section->id(), 1, 0);

  BasicCodeBlock* bb2 = subgraph->AddBasicCodeBlock(bb_name);
  block_desc->basic_block_order.push_front(bb2);

  assm2.jmp(block_graph::Immediate(bb2));

  inst_iter = bb2->instructions().begin();
  block_graph::BasicBlockAssembler assm3(inst_iter,
   &bb2->instructions());

  // Begin inner loop over instruction bytes of current checkee.
  assm3.mov(assm::ebx,
   assm::OperandBase<block_graph::UntypedReference>(assm::edx));
  assm3.add(assm::al, assm::bl);
  assm3.add(assm::edx, block_graph::Immediate(1));
  assm3.sub(assm::ecx, block_graph::Immediate(1));
  assm3.test(assm::ecx, assm::ecx);
  assm3.j(assm::ConditionCode::kNotEqual, block_graph::Immediate(bb2));
  // End inner loop.

  // Subtract the hash of address from computed hash.
  assm3.pop(assm::ebx); // Hash of address.
  assm3.pop(assm::edx); // Accumulator for hash.
  assm3.pop(assm::ecx); // Ourter loop counter.
  assm3.xchg(assm::eax, // Load #checkees of checkee.
   assm::OperandBase<block_graph::UntypedReference>(assm::esp));
  assm3.imul(assm::ebx, assm::eax); // Multiply hash of address with #chekees
  assm3.and(assm::ebx, block_graph::Immediate(0xFF)); // Modulo 256.
  assm3.pop(assm::eax); // Get hash of the current checkee.
  assm3.sub(assm::al, assm::bl); // Cancel base addresses of checkees in hash.
  assm3.pop(assm::ebx); // Coeficient of current basic block.
  assm3.imul(assm::eax, assm::ebx); // Multiply hash with coeficient.
  assm3.and(assm::eax, block_graph::Immediate(0xFF)); // Modulo 256
  assm3.add(assm::dl, assm::al); // Accumulate hash.
  assm3.push(assm::edx); // Store accumulator for hash.
  // The hash of the address is on the stack at a distance of 4 stack slots.
  // Recover it because it was lost when ebx was multiplied by the #checkees of
  // this checkee.
  assm3.mov(assm::edx, block_graph::Operand(assm::esp,
   block_graph::Displacement((unsigned int)-0x10)));
  assm3.push(assm::edx); // Store hash of address.
  // Check outer loop boundary.
  assm3.test(assm::ecx, assm::ecx);
  assm3.j(assm::ConditionCode::kNotEqual, block_graph::Immediate(bb));
  // End outer loop.

  assm3.pop(assm::eax); // Throw away hash of adddress.
  assm3.pop(assm::eax); // Load final hash value.

  // Function epilog.
  assm3.mov(assm::esp, assm::ebp);
  assm3.pop(assm::ebp);
  // Jump over pivot byte.
  assm3.add(assm::OperandBase<block_graph::UntypedReference>(assm::esp),
            block_graph::Immediate(1));
  // Load return address of edx into ebx, to be used by response function.
  assm3.mov(assm::ebx,
            assm::OperandBase<block_graph::UntypedReference>(assm::esp));
  assm3.ret();

  // Condense into a block.
  block_graph::BlockBuilder block_builder(bgraph);
  if (!block_builder.Merge(subgraph))
   return nullptr;

  return block_builder.new_blocks().begin()[0];
}


 // Adds assembly code for xor hash function
 // @param bgraph - the block graph from where the subgraph was taken
 // @param subgraph - the subgraph containing basic blocks we want to transform
 // @return the block containing the hash function
 // Adds assembly code for hash function
 // @param bgraph - the block graph from where the subgraph was taken
 // @param subgraph - the subgraph containing basic blocks we want to transform
 // @return the block containing the hash function
BlockGraph::Block* AddXorHashFunction(BlockGraph* bgraph) {
  BlockGraph::Section* code_section = bgraph->FindOrAddSection(".text",
   0x60000000);
  std::string bb_name = "get_xeip";
  BasicBlockSubGraph* subgraph = new BasicBlockSubGraph();
  // Create the thunk for standard "load/store" (received address in EDX).
  BasicBlockSubGraph::BlockDescription* block_desc =
   subgraph->AddBlockDescription(bb_name, code_section->name(),
   BlockGraph::CODE_BLOCK, code_section->id(),
   1, 0);

  BasicCodeBlock* bb = subgraph->AddBasicCodeBlock(bb_name);
  block_desc->basic_block_order.push_back(bb);

  auto inst_iter = bb->instructions().begin();
  block_graph::BasicBlockAssembler assm(inst_iter, &bb->instructions());

  // Create following BB that contains outer loop head
  bb_name = "get_xeip2";
  block_desc = subgraph->AddBlockDescription(bb_name, code_section->name(),
   BlockGraph::CODE_BLOCK,
   code_section->id(), 1, 0);

  bb = subgraph->AddBasicCodeBlock(bb_name);
  block_desc->basic_block_order.push_front(bb);

  // function prolog
  assm.push(assm::ebp);
  assm.mov(assm::ebp, assm::esp);

  assm.pop(assm::eax); // pop ebp
  assm.pop(assm::eax); // pop return addres
  assm.j(assm::ConditionCode::kEqual,
   block_graph::Immediate(bb));

  inst_iter = bb->instructions().begin();
  block_graph::BasicBlockAssembler assm2(inst_iter,
   &bb->instructions());

  // begin outer loop
  assm2.pop(assm::eax); // accumulator for hash

  assm2.pop(assm::edx); // get address of bb to hash
  assm2.sub(assm::ecx, block_graph::Immediate(1)); // decrement outer loop iter
  assm2.xchg(assm::ecx, // swap outer loop iter with inner loop iter
  assm::OperandBase<block_graph::UntypedReference>(assm::esp));
  assm2.push(assm::eax); // save accumulator for hash
  assm2.sub(assm::eax, assm::eax); // set eax to zero

  // Create following BB that contains inner loop
  bb_name = "get_xeip3";
  block_desc = subgraph->AddBlockDescription(bb_name, code_section->name(),
                                             BlockGraph::CODE_BLOCK,
                                             code_section->id(), 1, 0);

  BasicCodeBlock* bb2 = subgraph->AddBasicCodeBlock(bb_name);
  block_desc->basic_block_order.push_front(bb2);

  assm2.jmp(block_graph::Immediate(bb2));

  inst_iter = bb2->instructions().begin();
  block_graph::BasicBlockAssembler assm3(inst_iter,
   &bb2->instructions());

  // begin inner loop
  assm3.mov(assm::ebx,
      assm::OperandBase<block_graph::UntypedReference>(assm::edx));
  assm3.xor(assm::al, assm::bl);
  assm3.add(assm::edx, block_graph::Immediate(1));
  assm3.sub(assm::ecx, block_graph::Immediate(1));
  assm3.test(assm::ecx, assm::ecx);
  assm3.j(assm::ConditionCode::kNotEqual, block_graph::Immediate(bb2));
  // end inner loop

  assm3.pop(assm::ebx); // hash accumulator
  assm3.pop(assm::ecx); // ourter loop counter
  assm3.xchg(assm::ecx, // swap outer loop iter with inner loop iter
             assm::OperandBase<block_graph::UntypedReference>(assm::esp));
  assm3.push(assm::ebx); // save accumulator for hash

  // Create following BB that contains 2nd inner loop
  bb_name = "get_xeip4";
  block_desc = subgraph->AddBlockDescription(bb_name, code_section->name(),
                                             BlockGraph::CODE_BLOCK,
                                             code_section->id(), 1, 0);

  BasicCodeBlock* bb3 = subgraph->AddBasicCodeBlock(bb_name);
  block_desc->basic_block_order.push_front(bb3);

  assm3.cmp(assm::ecx, block_graph::Immediate(0, assm::ValueSize::kSize32Bit));
  assm3.j(assm::ConditionCode::kNotEqual, block_graph::Immediate(bb3));

  inst_iter = bb3->instructions().begin();
  block_graph::BasicBlockAssembler assm4(inst_iter,
                                         &bb3->instructions());

  // begin 2nd inner loop
  assm4.mov(assm::ebx,
            assm::OperandBase<block_graph::UntypedReference>(assm::edx));
  assm4.add(assm::al, assm::bl);
  assm4.add(assm::edx, block_graph::Immediate(1));
  assm4.sub(assm::ecx, block_graph::Immediate(1));
  assm4.test(assm::ecx, assm::ecx);
  assm4.j(assm::ConditionCode::kNotEqual, block_graph::Immediate(bb3));
  assm4.mov(assm::ecx, block_graph::Immediate(bb));
  assm4.add(assm::ecx, block_graph::Immediate(0x34));
  assm4.jmp(assm::ecx);
  // end 2nd inner loop

  assm3.pop(assm::edx); // load hash accumulator
  assm3.pop(assm::ecx); // ourter loop counter
  assm3.and(assm::eax, block_graph::Immediate(0xFF));

  assm3.add(assm::dl, assm::al); // accumulate hash
  assm3.xor(assm::eax, assm::eax); // set eax to 0
  assm3.sub(assm::al, assm::dl); // al = -hash
  assm3.push(assm::eax); // store hash accumulator
  // check outer loop boundary
  assm3.test(assm::ecx, assm::ecx);
  assm3.j(assm::ConditionCode::kNotEqual, block_graph::Immediate(bb));
  // end outer loop
  assm3.pop(assm::eax); // final hash value

  // function epilog
  assm3.mov(assm::esp, assm::ebp);
  assm3.pop(assm::ebp);
  assm3.ret();

  // Condense into a block.
  block_graph::BlockBuilder block_builder(bgraph);
  if (!block_builder.Merge(subgraph))
   return NULL;

  return block_builder.new_blocks().begin()[0];
}

// Traverse the call-graph in reverse call order (callee to caller) and push
// blocks in post-order. The resulting ordering can be iterated to visit all
// blocks from leaf to root. The ordering has the guarantee that all callees
// have been visited before their callers (except for recursive calls and
// indirect calls).
// TODO(etienneb): Hoist this function into block_graph.
void FlattenCallGraphPostOrder(BlockGraph* block_graph, BlockOrdering* order) {
  DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);
  DCHECK_NE(reinterpret_cast<BlockOrdering*>(NULL), order);

 // The algorithms uses a std::stack allocated in the heap to avoid stack
 // overflow.
  std::stack<BlockGraph::Block*> stack;
  std::set<BlockGraph::Block*> visiting;

 // Traverse the call-graph in depth-first.
  BlockGraph::BlockMap& blocks = block_graph->blocks_mutable();
  auto block_iter = blocks.begin();
  for (; block_iter != blocks.end(); ++block_iter) {
   BlockGraph::Block* block = &block_iter->second;

   // This block is already visited.
   if (!visiting.insert(block).second)
    continue;

   // This block needs to be visited, add it to the stack.
   stack.push(block);

   // Follow the referrers.
   while (!stack.empty()) {
    block = stack.top();

    // Put unvisited referrers on the stack.
    typedef std::map<BlockGraph::BlockId,
     BlockGraph::Block*> OrderedBlockMap;
    OrderedBlockMap missing;
    bool missing_referrers = false;
    if (block->type() == BlockGraph::CODE_BLOCK) {
     const ReferrerSet& referrers = block->referrers();
     auto referrer = referrers.begin();
     for (; referrer != referrers.end(); ++referrer) {
      BlockGraph::Block* from = referrer->first;
      if (visiting.insert(from).second) {
       missing.insert(std::make_pair(from->id(), from));
       missing_referrers = true;
      }
     }
    }

    // Push missing referrers into the stack, ordered by block id.
    auto referrer = missing.begin();
    for (; referrer != missing.end(); ++referrer)
     stack.push(referrer->second);

    // When there are no missing referrers, this block is fully visited and
    // can be pushed in the ordering (post-order).
    if (!missing_referrers) {
     order->push_front(block);
     // Remove this block from the stack.
     DCHECK_EQ(block, stack.top());
     stack.pop();
    }
   }
  }
}

// Retrieves the basic block in the given subgraph at the given offset.
// @param subgraph the basic block subgraph where to search.
// @param offset the offset of the basic block to search for.
// @return the basic block object if found and NULL otherwise.
BasicBlock* GetBasicBlockAtOffset(const BasicBlockSubGraph *subgraph,
                                  const BasicBlock::Offset offset) {
  DCHECK(subgraph);
  DCHECK_LE(0, offset);

  auto it(subgraph->basic_blocks().begin());
  for (; it != subgraph->basic_blocks().end(); ++it) {
   if ((*it)->offset() == offset)
    return *it;
  }

  return nullptr;
}


}
// namespace

void IntegrityCheckTransform::PatchBlockReference(
    BasicBlock::Instructions::iterator inst_itr,
    block_graph::BlockGraph::Block* new_block,
    block_graph::BlockGraph::Offset new_offset,
    bool use_new_block = false){
  DCHECK(new_block);
  Instruction::BasicBlockReferenceMap &ref_block_map = inst_itr->references();
  auto instruction_references_it = ref_block_map.begin();
  BlockGraph::Offset reference_offset = instruction_references_it->first;

  BasicBlockReference old_bb_ref = instruction_references_it->second;
  BasicBlockReference new_bb_ref(old_bb_ref.reference_type(),
                                 old_bb_ref.size(),
                                 use_new_block ? new_block : old_bb_ref.block(),
                                 new_offset,
                                 new_offset);

  ref_block_map[reference_offset] = new_bb_ref;
}

void SplitChunkReferencelabels(const std::string label,
                               uint64_t *checkee_id,
                               int *chunkIndex){
  //split the string
  std::istringstream iss(label);
  std::vector<std::string> tokens;
  copy(std::istream_iterator<std::string>(iss),
       std::istream_iterator<std::string>(),
       back_inserter(tokens));

  *checkee_id = std::stoull(tokens.at(1));
  *chunkIndex = std::stoi(tokens.at(2));
}

void IntegrityCheckTransform::GenerateLabelToBlockMap(BlockGraph *bgraph) {
  BlockGraph::BlockMap &blocks = bgraph->blocks_mutable();
  auto it(blocks.begin());
  this->label_name_to_block_->clear();

  for (; it != blocks.end(); ++it) {
    auto label_map = it->second.labels();
    auto lab_it(label_map.begin());
    for (; lab_it != label_map.end(); ++lab_it) {
      (*this->label_name_to_block_)[lab_it->second.name()] =
        std::make_pair(&it->second, lab_it->first);
    }
  }
}

void IntegrityCheckTransform::UpdateLabelToBlockMap(BlockGraph::Block *block) {
  auto label_map = block->labels();
  auto lab_it(label_map.begin());
  for (; lab_it != label_map.end(); ++lab_it) {
    (*this->label_name_to_block_)[lab_it->second.name()] =
        std::make_pair(block, lab_it->first);
  }
}

bool IntegrityCheckTransform::PopulatePartitionKey(
    const block_graph::Instruction instr,
    uint8_t *num_abs_references) {
  auto references = instr.references();
  if (references.size() < 1)
    return false;

  auto it = references.begin();
  for (; it != references.end(); ++it) {
    block_graph::BlockGraph::ReferenceType type = it->second.reference_type();

    if (type == block_graph::BlockGraph::ReferenceType::ABSOLUTE_REF) {
      (*num_abs_references)++;
    }
  }
  return true;
}

void IntegrityCheckTransform::PopulateCheckMaps(std::set<uint64_t> part_block) {
  std::set<uint64_t> tmp = part_block;

  while (tmp.size() > 0) {
    // chose a random element
    int index = rand() % tmp.size();
    auto set_it = tmp.begin();
    std::advance(set_it, index);

    index = rand() % part_block.size();
    auto set_it2 = part_block.begin();
    std::advance(set_it2, index);

    // pick different blocks as the pair of checkees
    for (; set_it2 != part_block.end(); ++set_it2)
      if ((uint32_t)(*set_it) != (uint32_t)(*set_it2))
        break;

    // if reached the end of the list then start from beginning
    if (set_it2 == part_block.end())
      set_it2 = part_block.begin();

    // pick different blocks as the pair of checkees
    int i = 0;
    for (; i < index; ++i) {
      if ((uint32_t)(*set_it) != (uint32_t)(*set_it2))
        break;

      ++set_it2;
    }

    if (((uint32_t)(*set_it) == (uint32_t)(*set_it2)) && (i >= index)) {
      // skip this block of the partition
      tmp.erase(set_it);
      continue;
    }

    // use this when checkers are allowed to be in the same block as checkees
    std::map<uint64_t, int> tuple;
    tuple.insert(std::pair<uint64_t, int>(*set_it, 1));
    tuple.insert(std::pair<uint64_t, int>(*set_it2, -1));
    // use this when checkers are NOT allowed in the same block as checkees
    std::list<uint32_t> tuple_blocks;
    tuple_blocks.push_back((uint32_t)*set_it);
    tuple_blocks.push_back((uint32_t)*set_it2);

    uint64_t checker_id;
    if (!RandomlySelectChecker(tuple_blocks, &checker_id)) {
      tmp.erase(*set_it);
      continue;
    }

    // Populate checker / checkee maps
    (*this->checker_to_checkee_map_)[checker_id] = tuple;
    fprintf(this->pfile_, "%llx,", checker_id);
    auto list_it = tuple.begin();
    for (; list_it != tuple.end(); ++list_it) {
      this->is_bb_checked_map_[list_it->first] = 1;
      fprintf(this->pfile_, "%d * %llx,", list_it->second, list_it->first);
    }

    fprintf(this->pfile_, "\n");
    tmp.erase(set_it);
  }
}

//
bool IntegrityCheckTransform::RandomlySelectChecker(
    std::list<uint32_t> tuple_blocks,
    uint64_t *checker_id) {
  // Randomly select checker
  int index = rand() % this->precomputed_hashes_->size();
  auto map_it = this->precomputed_hashes_->begin();
  std::advance(map_it, index);

  // checker must not be in the list of checkees and preferrably does not check
  // other tuples as well
  while ((map_it != this->precomputed_hashes_->end()) &&
    ((std::find(tuple_blocks.begin(), tuple_blocks.end(),
    (uint32_t)(*map_it).first) != tuple_blocks.end()) ||
    (this->checker_to_checkee_map_->find((*map_it).first) !=
    this->checker_to_checkee_map_->end()) &&
    ((*this->checker_to_checkee_map_)[(*map_it).first].size() > 0)))
    map_it++;

  int i = 0;
  // if reached end of list then start from the begining and go until index
  if (map_it == this->precomputed_hashes_->end()) {
    map_it = this->precomputed_hashes_->begin();
    while ((i < index) &&
      ((std::find(tuple_blocks.begin(), tuple_blocks.end(),
      (uint32_t)(*map_it).first) != tuple_blocks.end()) ||
      (this->checker_to_checkee_map_->find((*map_it).first) !=
      this->checker_to_checkee_map_->end()) &&
      ((*this->checker_to_checkee_map_)[(*map_it).first].size() > 0))) {
      map_it++;
      i++;
    }
  }

  // if all checkers are already checking some tuple then we should only avoid
  // selecting the checker in the list of checkees
  if (i >= index) {
    while ((map_it != this->precomputed_hashes_->end()) &&
      ((std::find(tuple_blocks.begin(), tuple_blocks.end(),
      (uint32_t)(*map_it).first) != tuple_blocks.end()))) {
      map_it++;
    }

    int i = 0;
    // if reached end of list then start from the begining and go until index
    if (map_it == this->precomputed_hashes_->end()) {
      map_it = this->precomputed_hashes_->begin();
      while ((i < index) &&
        ((std::find(tuple_blocks.begin(), tuple_blocks.end(),
        (uint32_t)(*map_it).first) != tuple_blocks.end()))){
        map_it++;
        i++;
      }

      if (i >= index) {
        return false; // can't find a checker that satisfies all conditions
      }
    }
  }

  DCHECK(std::find(tuple_blocks.begin(), tuple_blocks.end(),
    (uint32_t)(*map_it).first) == tuple_blocks.end());

  *checker_id = (*map_it).first;
  return true;
}

#if defined COMPUTE_CHECKER_SIZE
uint64_t total_checker_size = 0;
#endif

char* MakeChunkLabel(const uint64_t chunk_bb_id, const uint32_t chunk_index,
                     const bool before_chunk_integrity_code_added = false){
  DCHECK(chunk_bb_id != MAXUINT64);
  char *buffersearch = new char[50];

  //only after chunk integrity code is prepended the first chunk label is
  //update to n %llu %lu format. Before that the first instruction refers to
  //the beginning of the block, which has %llu format
  if (before_chunk_integrity_code_added && chunk_index == 0){
    sprintf_s(buffersearch, 50, "%llu", chunk_bb_id);
  } else {
    sprintf_s(buffersearch, 50, "n %llu %lu", chunk_bb_id, chunk_index);
  }
  return buffersearch;
}

bool IntegrityCheckTransform::AddChunkIntegrityCheckCode(
    BasicCodeBlock* bb,
    BasicBlockSubGraph* subgraph,
    BlockGraph *block_graph){
  auto inst_iter = bb->instructions().begin();
  if (inst_iter == bb->instructions().end())
    return true;

  BlockGraph::Label label(inst_iter->label());
  uint64_t bb_id = GetBasicBlockIdByLabel(label, this->id_to_label_);

  if (bb_id == -1)
    return true;

  if ((*this->checker_to_checkee_map_)[bb_id].size() < 1)
    return true;

  //given that the begining of the checker block never has an absolute reference
  //therefore, it is the pointer for the first block chunk. So, we update it's
  //label to a the chunk of index zero within the block
  char *chunk_label = MakeChunkLabel(bb_id, 0);
  inst_iter->set_label(BlockGraph::Label(chunk_label, BlockGraph::CODE_LABEL));
  delete[] chunk_label;
  std::set<uint32_t> chunk_set = (*ic_chunk_checker_to_checkee_map_)[bb_id];
  CHECK(chunk_set.size() == this->num_chunks_per_block);

  block_graph::BasicBlockAssembler assm(inst_iter, &bb->instructions());

  uint32_t num_original_instr = bb->instructions().size();

  assm.push(assm::eax);
  assm.push(assm::ebx);
  assm.push(assm::ecx);
  assm.push(assm::edx);

  assm.mov(assm::ecx, block_graph::Immediate(chunk_set.size(),
                                             assm::ValueSize::kSize32Bit));

  auto chunk_iter = chunk_set.begin();
  uint32_t num_chunks = chunk_set.size();

  std::map<uint32_t, std::tuple<uint64_t, uint32_t>> reference_free_labels;
  for (uint32_t reference_index = 0; chunk_iter != chunk_set.end();
       ++chunk_iter, ++reference_index){

    auto chunk_info = (*ic_block_reference_free_chunks)[*chunk_iter];
    uint64_t chunk_bb_id = chunk_info.block_id_;
    uint32_t chunk_size = chunk_info.size_;
    uint32_t chunk_index = chunk_info.chunk_index_;

    //get chunk offset and block
    char *buffersearch = MakeChunkLabel(chunk_bb_id, chunk_index,true);
    auto found_label_it = label_name_to_block_->find(buffersearch);
    DCHECK(found_label_it != label_name_to_block_->end());
    delete[] buffersearch;
    BlockGraph::Block* chunk_block = found_label_it->second.first;
    uint32_t chunk_offset = found_label_it->second.second;

    assm.push(block_graph::Immediate(chunk_info.next_instruction_size_,
                                     assm::ValueSize::kSize32Bit));
    assm.push(block_graph::Immediate(chunk_size, assm::ValueSize::kSize32Bit));

    //keep the index of block instruction for labelling
    uint32_t label_instr_index = bb->instructions().size() -
	                             num_original_instr;
    reference_free_labels.insert(std::make_pair(label_instr_index,
                                 std::make_pair(chunk_bb_id, chunk_index)));

    assm.push(block_graph::Immediate(chunk_block, chunk_offset));
  }


  assm.push(block_graph::Immediate(0, assm::kSize32Bit));
  assm.call(block_graph::Immediate(this->xhash_block_, 0));
  uint32_t no_pushed_words = 3 * num_chunks + 1;
  assm.add(assm::esp, block_graph::Immediate(no_pushed_words * 4));
  assm.push(assm::eax);
  //test

  //Insert label at the beginning of the block
  inst_iter = bb->instructions().begin();
  label = BlockGraph::Label(std::to_string(bb_id),
                            BlockGraph::CODE_LABEL);
  inst_iter->set_label(label);


  uint32_t num_added_chunk_labels = 0;
  uint32_t label_index = 0;
  uint32_t new_size = 0;
  uint32_t num_added_instr = bb->instructions().size() - num_original_instr;
  for (uint32_t instruction_index = 0;
      inst_iter != bb->instructions().end() &&
      instruction_index < num_added_instr;
      ++instruction_index, ++inst_iter){
    new_size += inst_iter->size();
    auto label_it = reference_free_labels.find(label_index++);
    //add reference free labels
    if (label_it != reference_free_labels.end()){
      char  *buffer = new char[50];
      uint64_t chunk_bb_id = std::get <0>(label_it->second);
      uint32_t chunk_index = std::get<1>(label_it->second);
      sprintf_s(buffer, 50, "nrc %llu %lu", chunk_bb_id,
        chunk_index);
      label = BlockGraph::Label(buffer, BlockGraph::CODE_LABEL);
      delete[] buffer;
      inst_iter->set_label(label);
      ++num_added_chunk_labels;
      ++num_chunk_reference_labels;
    }
  } //end for


  //make sure all chunk block references are set
  DCHECK_EQ(num_added_chunk_labels, static_cast<uint32_t>(chunk_set.size()));


  //update size
  uint32_t old_size = (*this->basic_block_sizes_)[bb_id];
  (*this->basic_block_sizes_)[bb_id] = old_size + new_size;
#if defined COMPUTE_CHECKER_SIZE
  total_checker_size += old_size + new_size;
#endif
  return true;
}
void GetSizeTokenFromlabel(const std::string label,
                           uint64_t *checkee_id,
                           uint64_t *bb_id){
  //split the string
  std::istringstream iss(label);
  std::vector<std::string> tokens;
  copy(std::istream_iterator<std::string>(iss),
    std::istream_iterator<std::string>(),
    back_inserter(tokens));
  *checkee_id = std::stoull(tokens.at(1));
  *bb_id = std::stoull(tokens.at(2));
}

void GetBlockIdTokenFromlabel(const std::string label, uint64_t *checkee_id){
  //split the string
  std::istringstream iss(label);
  std::vector<std::string> tokens;
  copy(std::istream_iterator<std::string>(iss),
    std::istream_iterator<std::string>(),
    back_inserter(tokens));
  *checkee_id = std::stoull(tokens.at(1));
}

//keep track of chunk indexes to update xor hash after size changes
uint32_t last_visited_chunk_index = 0;
uint64_t last_visited_chunk_bb_id = 0;

bool IntegrityCheckTransform::PatchBlockReferencesAndSizes(
    BasicCodeBlock* bb,
    BasicBlockSubGraph* subgraph,
    BlockGraph *block_graph){
  bool found = false;

  auto inst_iter = bb->instructions().begin();
  if (inst_iter == bb->instructions().end()){
    return true;
  }

  BlockGraph::Label label(inst_iter->label());
  uint64_t block_id = GetBasicBlockIdByLabel(label, this->id_to_label_);

  std::string sizeLabel = "size ";
  std::string blockLabel = "block";
  std::string chunk_blocklabel = "nrc";
  std::string chunk_pointerlabel = "n ";
  std::string chunk_no_reference = "ref";
  std::string block_id_label = std::to_string(block_id);
  auto end_block = bb->instructions().end();
  for (; inst_iter != end_block; ++inst_iter)
  {
    if (!inst_iter->has_label())  continue;


    if (inst_iter->label().name()
        .compare(0, chunk_pointerlabel.length(), chunk_pointerlabel) == 0){
      // update last visited chunk index
      GetChunkTokensFromlabel(inst_iter->label().name(),
                              &last_visited_chunk_bb_id,
                              &last_visited_chunk_index);
    } else if (inst_iter->label().name()
               .compare(0, block_id_label.length(), block_id_label) == 0){
      last_visited_chunk_bb_id = block_id;
      last_visited_chunk_index = 0;
#pragma region patch_size
    } else if (inst_iter->label().name()
        .compare(0, sizeLabel.length(), sizeLabel) == 0){
      //extract block id for size retrieval
      uint64_t checkee_id = 0;
      uint64_t bb_id = 0;
      GetSizeTokenFromlabel(inst_iter->label().name(), &checkee_id, &bb_id);
      //modify bytes
      ++num_size_reference_patched_labels;
      auto old_data = inst_iter->GetMutableData();
      DCHECK(old_data[0] == 0x68);
      //if the block is checker then the new size must be bigger than the
      //old one
      uint32_t old_size = 0;
      for (int j = 0; j < sizeof(uint32_t) && old_data[j] != NULL; j++)
      {
        old_size |= old_data[j + 1] << j * 8;
      }
      uint8_t* new_data = new uint8_t[inst_iter->size()];
      new_data[0] = 0x68;
      uint32_t new_size = (*this->basic_block_sizes_)[checkee_id];
      for (int k = 0; k < sizeof(uint32_t); k++){
        uint8_t value = (new_size >> k * 8) & 0xFF;
        new_data[k + 1] = value;
      }

      //if the block is checker then the new size must be bigger than the
      //old one
      if ((*checker_to_checkee_map_)[checkee_id].size() > 0){
        DCHECK_GE(new_size, old_size);
      }

      if (*perform_chunk_checks_) {
        clock_t begin = clock();
        //we have to recompute chunk that inlcudes this size
        this->RecomputeXorChunks(bb_id, old_data, new_data,
            last_visited_chunk_bb_id,
            last_visited_chunk_index);
        clock_t end = clock();
        elapsed_secs_in_patching_chunks += double(end - begin) /
		                                   CLOCKS_PER_SEC;
      }
      for (uint8_t j = 0; j < inst_iter->size(); j++)
        old_data[j] = new_data[j];

      //prevent multiple patching
      inst_iter->set_label(block_graph::BlockGraph::Label());
      found++;
      delete[] new_data;
#pragma endregion
    } else if (inst_iter->label().name() //patch block
               .compare(0, blockLabel.length(), blockLabel) == 0){
      //extract block id for offset patching
      uint64_t checkee_id = 0;
      GetBlockIdTokenFromlabel(inst_iter->label().name(), &checkee_id);
#pragma region patch_block
      auto label_itr = label_name_to_block_->find(std::to_string(checkee_id));
      DCHECK(label_itr != label_name_to_block_->end());
      PatchBlockReference(inst_iter, label_itr->second.first,
        label_itr->second.second);
#pragma endregion
    } else if (inst_iter->label().name().compare(0, chunk_blocklabel.size(),
                                                 chunk_blocklabel) == 0){

      uint64_t checkee_id_for_patch = 0;
      int checkee_index_for_patch;
      SplitChunkReferencelabels(inst_iter->label().name(),
                                &checkee_id_for_patch,
                                &checkee_index_for_patch);
      CHECK(checkee_id_for_patch != 0);

      num_chunk_reference_patched_labels++;

      //find the offset of the reference free chunk within the checkee
      char  *chunk_label = MakeChunkLabel(checkee_id_for_patch,
                                          checkee_index_for_patch);
      auto label_to_block_it = label_name_to_block_->find(chunk_label);
      delete[] chunk_label;
      CHECK(label_to_block_it != label_name_to_block_->end());
#pragma region patch_chunk_offset
      //update instruction reference to the retrieved reference free
      //offset (label_to_block_it.second is a pair of <block,offset>)
      auto reference_free_block = label_to_block_it->second.first;
      uint32_t new_bb_ref_offset = label_to_block_it->second.second;

      PatchBlockReference(inst_iter, reference_free_block, new_bb_ref_offset);

#pragma endregion


    } else if (*perform_chunk_checks_ &&
               inst_iter->label().name().compare(0, chunk_no_reference.size(),
                                                 chunk_no_reference) == 0){
      //patch number of chunks per block
      uint64_t bb_id = 0;
      GetBlockIdTokenFromlabel(inst_iter->label().name(), &bb_id);
      //modify bytes
      ++num_no_chunk_patched_labels;
      auto old_data = inst_iter->GetMutableData();
      DCHECK(old_data[0] == 0x68);

      uint8_t* new_data = new uint8_t[inst_iter->size()];
      new_data[0] = 0x68;
      uint32_t old_size = 0;
      for (int j = 0; j < sizeof(uint32_t) && old_data[j] != NULL; j++)
      {
        old_size |= old_data[j + 1] << j * 8;
      }
      uint32_t new_size = old_size + this->num_chunks_per_block;
      for (int k = 0; k < sizeof(uint32_t); k++){
        uint8_t value = (new_size >> k * 8) & 0xFF;
        new_data[k + 1] = value;
      }

      //we have to recompute the chunk that includes this instruction(if any)
      this->RecomputeXorChunks(bb_id, old_data, new_data,
                               last_visited_chunk_bb_id,
                               last_visited_chunk_index);

      for (uint8_t j = 0; j < inst_iter->size(); j++)
        old_data[j] = new_data[j];

      //prevent multiple patching
      inst_iter->set_label(block_graph::BlockGraph::Label());
      found++;
      delete[] new_data;
    }
  } // end for

  return true;
}

bool IntegrityCheckTransform::RecomputeXorChunks(
    const uint64_t bb_id, const uint8_t old_size[],
    const uint8_t new_size[], const uint64_t chunk_bb_id,
	const uint32_t chunk_index){

  DCHECK_EQ(bb_id, chunk_bb_id);

  uint32_t vector_index =
    (*ic_block_chunk_index_map_)[GetChunkUniqueKey(chunk_bb_id,chunk_index)];

  DCHECK_GE(vector_index, static_cast<uint32_t>(0));
  DCHECK_LT(vector_index, ic_block_reference_free_chunks->size());

  auto chunk = (*ic_block_reference_free_chunks)[vector_index];
  DCHECK(chunk.block_id_ == chunk_bb_id && chunk.chunk_index_ == chunk_index);
  ////make sure we found the right chunk
  DCHECK(sizeof(old_size) == sizeof(new_size));

  uint8_t new_hash = chunk.hash_;
  for (uint32_t i = 0; i < sizeof(old_size); i++)
  {
    //cancel out previous value
    new_hash ^= old_size[i];
    //compute new hash
    new_hash ^= new_size[i];
  }

  chunk.hash_ = new_hash;
  (*ic_block_reference_free_chunks)[vector_index] = chunk;
  return true;
}

bool IsSize(BasicBlock::Instructions::iterator instruction_itr){
  std::string size_label = "size";
  if (instruction_itr->has_label() &&
      instruction_itr->label().name()
      .compare(0, size_label.length(), size_label) == 0){
    return true;
  }
  return false;
}
bool IsPivot(BasicBlock::Instructions::iterator instruction_itr){
  std::string pivot_label = "Pivot:";
  if (instruction_itr->has_label() &&
      instruction_itr->label().name()
      .compare(0, pivot_label.length(), pivot_label) == 0){
    return true;
  }
  return false;
}

bool HasAbsoluteReferences(BasicBlock::Instructions::iterator instruction_itr){
  if (instruction_itr->references().size() > 0){
    auto ref_it = instruction_itr->references().begin();
    for (; ref_it != instruction_itr->references().end(); ++ref_it){
      if (ref_it->second.reference_type() ==
          block_graph::BlockGraph::ReferenceType::ABSOLUTE_REF)
        return true;
    }
  }
  return false;
}

void
IntegrityCheckTransform::AddChunkIntoIndexMap(const uint64_t bb_id,
                                              const uint32_t chunk_index,
                                              const uint32_t vector_index){
  auto unique_chunk_key = GetChunkUniqueKey(bb_id,chunk_index);
  //make sure the key is really unique!
  DCHECK(ic_block_chunk_index_map_->find(unique_chunk_key) ==
         ic_block_chunk_index_map_->end());
  (*ic_block_chunk_index_map_)[unique_chunk_key] = vector_index;
}

void IntegrityCheckTransform::ComputeChunks(BasicCodeBlock* bb){
  auto inst_iter = bb->instructions().begin();
  if (inst_iter == bb->instructions().end())
    return;

  BlockGraph::Label label(inst_iter->label());
  uint64_t bb_id = GetBasicBlockIdByLabel(label, this->id_to_label_);
  if (bb_id == -1)
    return;
  std::map<uint64_t, int> checkee_list =
    (*this->checker_to_checkee_map_)[bb_id];

  if (checkee_list.size() < 1)
    return;

  //uint32_t reference_free_start_offset = 0;
  uint32_t reference_free_size = 0;
  uint8_t reference_free_hash = 0;
  uint32_t reference_free_index = 0;
  uint16_t size_in_bytes = 0;
  uint8_t num_found_pivots = 0;
  uint32_t current_inst_size = 0;
  std::string bb_id_label = std::to_string(bb_id);
  bool has_references=false;
  bool has_abs_references = false;
  bool is_pivot=false;
  // Process all instructions in BB
  for (; inst_iter != bb->instructions().end(); ++inst_iter) {

    current_inst_size = (*inst_iter).size();
    size_in_bytes += current_inst_size;
    const uint8_t *b2 = (*inst_iter).data();

    uint8_t instruction_hash = 0;
    for (uint32_t i = 0; i < current_inst_size; ++i){
      instruction_hash ^= (*b2);
      b2++;
    }
    if (IsPivot(inst_iter)){
      ++num_found_pivots;
    }
    has_abs_references = HasAbsoluteReferences(inst_iter);
    has_references = (inst_iter->references().size() > 0);

    is_pivot = IsPivot(inst_iter);
    if (!has_references && !is_pivot){
      //we cannot place two labels on the same instruction, so if the beginning
      //of the chunk has a label we skip it.
      //In order to keep the first instruction of the block in a chunk without
      //changing its label, we accept the block id label as a finger for the
      //beginning of the chunk.
      if (reference_free_size != 0 || !inst_iter->has_label()
          || inst_iter->label().name().compare(bb_id_label)==0){
        //this is the first instruction in the chunk where we place our label
        //we don't need to put label at the first instruction, because it has
        //block id label, first instruction label is detected when reference
        //free index equals zero
        if (reference_free_size == 0 && reference_free_index!=0){
          char  *buffer = MakeChunkLabel(bb_id, reference_free_index);
          auto label = BlockGraph::Label(buffer, BlockGraph::CODE_LABEL);
          delete[] buffer;
          DCHECK(!inst_iter->has_label());
          inst_iter->set_label(label);
        }
        //keep counting
        reference_free_size += current_inst_size;
        reference_free_hash ^= instruction_hash;
      }
    } else if (reference_free_size > 0){
      //add offset and size of the reference free chunk
      ic_block_reference_free_chunks->push_back(
          ChunkInfo(bb_id, reference_free_size, reference_free_hash,
                    reference_free_index,
                    has_abs_references?current_inst_size:0));
      AddChunkIntoIndexMap(bb_id, reference_free_index++,
          ic_block_reference_free_chunks->size() - 1);
      //once we add the chunk, we reset the size
      reference_free_size = 0;
      reference_free_hash = 0;
     }
  } //end for

  //the last chunk of the instructions need to be added (if any)
  if (reference_free_size > 0) {
    //add offset and size of the reference free chunk
    ic_block_reference_free_chunks->push_back(
       ChunkInfo(bb_id, reference_free_size, reference_free_hash,
                 reference_free_index, 0));
      AddChunkIntoIndexMap(bb_id, reference_free_index,
                           ic_block_reference_free_chunks->size() - 1);
    //once we add the chunk, we reset the size
    reference_free_size = reference_free_hash = 0;
  }

  //Exactly one pivot must be in each IC block
  DCHECK_EQ(num_found_pivots, 1);
}

uint8_t IntegrityCheckTransform::PrecomputeHash(
    BasicCodeBlock* bb,
    std::list<uint32_t> *offset_sizes,
    BasicBlockSubGraph* subgraph) {
  DCHECK_NE(reinterpret_cast<BasicCodeBlock*>(NULL), bb);

  if (bb->instructions().size() <= 0)
    return 0;

  uint16_t offset_in_bytes = 0;
  uint16_t size_in_bytes = 0;
  uint64_t bb_address = GetBasicBlockId(bb, subgraph);

  // Match and rewrite based on patterns.
  auto inst_iter = bb->instructions().begin();
  size_in_bytes = 0;
  uint8_t partition_key = 0;
  BlockGraph::Label label;

  label = BlockGraph::Label(std::to_string(bb_address),
                            BlockGraph::CODE_LABEL);
  inst_iter->set_label(label);

  (*this->id_to_label_)[bb_address] = label;
  fprintf(this->prefile_, "\n\n%llx\n", std::stoull(label.name()));

  // Process all instructions in BB
  for (; inst_iter != bb->instructions().end(); ++inst_iter) {
    uint32_t size = (*inst_iter).size();
    uint8_t nr_refs_in_key = partition_key;

    if (PopulatePartitionKey((*inst_iter), &partition_key)) {
      this->basic_block_has_ref_[bb_address] = true;

      int nr_added = partition_key - nr_refs_in_key;
      if (nr_added == 1) {
        uint64_t label_nr = bb_address + ((uint64_t)size_in_bytes << 32);
        label = BlockGraph::Label(std::to_string(label_nr),
                                  BlockGraph::CODE_LABEL);

        if (inst_iter->has_label()) {
          BlockGraph::Label existing_label = inst_iter->label();
        } else {
          inst_iter->set_label(label);
        }
      }
    }

    size_in_bytes += size;
  } // end for

  // put the last bytes in the basic block in the list of precomputed hashes
  if ((size_in_bytes > 0)) { // don't put chunks of 0 size on stack
    uint32_t offset_size = (offset_in_bytes << 16) | size_in_bytes;
    offset_sizes->push_front(offset_size);
  }

  // populate precomputed hashes and bb-sizes
  if (partition_key > 0) {
    std::set<uint64_t> v = this->partition_map_[partition_key];
    v.insert(bb_address);
    this->partition_map_[partition_key] = v;
    // save precomputed hash
    (*this->precomputed_hashes_)[bb_address] = 0;
    (*this->basic_block_sizes_)[bb_address] = size_in_bytes;

  } else if (size_in_bytes > 0) {
    std::set<uint64_t> v = this->partition_map_[0];
    v.insert(bb_address);
    this->partition_map_[0] = v;
    // save precomputed hash
    (*this->precomputed_hashes_)[bb_address] = 0;
    (*this->basic_block_sizes_)[bb_address] = size_in_bytes;
  }

  bb_address += ((uint64_t)offset_in_bytes << 32);
  return 1;
}

bool IntegrityCheckTransform::TransformBasicBlockSubGraph(
    BlockGraph* bgraph,
    BasicBlockSubGraph* subgraph,
    IntegrityCheckTransform::ProcessingType step) {
  DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), bgraph);

  if (step == IntegrityCheckTransform::ADD_HASH_AND_RESPONSE) {
    this->hash_block_ = AddHashFunction(bgraph);
    this->xhash_block_ = AddXorHashFunction(bgraph);
    this->response_block_ = AddResponseFunction(bgraph);

    return (this->hash_block_ && this->xhash_block_ && this->response_block_);

  } else {
    DCHECK_NE(reinterpret_cast<BasicBlockSubGraph*>(NULL), subgraph);
    std::list<uint32_t> instr_sizes;
    uint8_t min_instructions = 0;
    BasicBlockSubGraph::BBCollection& basic_blocks =
      subgraph->basic_blocks(); // set of BB to protect

    // Iterate over every basic block and insert integrity-checks
    for (auto it = basic_blocks.begin(); it != basic_blocks.end(); ++it) {
      BasicCodeBlock* bb = BasicCodeBlock::Cast(*it);
      if ((bb == NULL) || (bb->instructions().size() < min_instructions))
        continue;
      switch (step) {
      case IntegrityCheckTransform::PRECOMPUTE_HASHES: {
        PrecomputeHash(bb, &instr_sizes, subgraph);
        break;
      }
      case IntegrityCheckTransform::INSERT_CHECKS: {
        AddIntegrityCheckCode(bb, subgraph, bgraph);
        break;
      }
      case IntegrityCheckTransform::COMPUTE_CHUNKS:{
        ComputeChunks(bb);
        break;
      }
      case IntegrityCheckTransform::INSERT_CHUNK_CHECKS:{
        AddChunkIntegrityCheckCode(bb, subgraph, bgraph);
        break;
      }
      case IntegrityCheckTransform::PATCH_REFERENCES_SIZES: {
        PatchBlockReferencesAndSizes(bb, subgraph, bgraph);
        break;
      }
      default:
        DbgRaiseAssertionFailure();
        break;
      }
    } // end for
  } // end else
  return true;
}

uint8_t IntegrityCheckTransform::GetPartitionKey(uint64_t bb_id) {
  auto it = this->partition_map_.begin();
  for (; it != this->partition_map_.end(); ++it) {
    if (it->second.find(bb_id) != it->second.end())
      return it->first;
  }

  return 0;
}

void IntegrityCheckTransform::AddIntegrityCheckCode(
    BasicCodeBlock* bb,
    BasicBlockSubGraph* subgraph,
    BlockGraph *block_graph) {
  auto inst_iter = bb->instructions().begin();
  if (inst_iter == bb->instructions().end())
    return;

  BlockGraph::Label label(inst_iter->label());
  uint64_t bb_id = GetBasicBlockIdByLabel(label, this->id_to_label_);

  if (bb_id == -1)
    return;

  uint8_t hash = 0;
  std::map<uint64_t, int> checkee_list =
    (*this->checker_to_checkee_map_)[bb_id];

  if (checkee_list.size() < 1)
    return;

  // Count number of absolute references in basic block
  uint8_t no_abs_references = 0;
  // Count number of instructions in basic block
  uint32_t no_bb_instructions = bb->instructions().size();
  uint32_t no_orig_bb_instructions = bb->instructions().size();
  std::map<uint32_t, uint64_t> checkee_label_map;
  if (this->insert_file_ != NULL){
    fprintf(this->insert_file_, "%s,", label.name().c_str());
  }
  // Remove old label from the beginning of the original code
  inst_iter->set_label(BlockGraph::Label());

  block_graph::BasicBlockAssembler assm(inst_iter,
    &bb->instructions());

  //in case we add chunk checker these pushes will be added by the chunk
  //checker
  if (!*perform_chunk_checks_){
    assm.push(assm::eax);
    assm.push(assm::ebx);
    assm.push(assm::ecx);
    assm.push(assm::edx);
  }

  assm.lea(assm::ecx, block_graph::Operand(
                      block_graph::Displacement(checkee_list.size(),
                      assm::ValueSize::kSize32Bit)));

  uint32_t *checkee_size_index = new uint32_t[checkee_list.size()];
  uint32_t *checkee_reference_index = new uint32_t[checkee_list.size()];

  uint32_t pivot_instruction_index = 0;
  uint32_t sub_instruction_index = 0;
  uint32_t k = 0;
  uint32_t reference_index = 0;
  auto checkee_it = checkee_list.begin();
  int last_coefficient = 0;
  for (; checkee_it != checkee_list.end(); ++checkee_it) {

    if (last_coefficient == checkee_it->second){
      LOG(INFO) << "found equal coeffs";
    }
    last_coefficient = checkee_it->second;
    assm.push(block_graph::Immediate(checkee_it->second,
                                     assm::ValueSize::kSize32Bit));

    // push the number of checkees of the checkee
    uint32_t nr_of_checkees =
      (*this->checker_to_checkee_map_)[checkee_it->first].size();
    no_abs_references += nr_of_checkees + GetPartitionKey(bb_id) +
	                     this->num_chunks_per_block;
    //Here still we don't know how many chunks this checker is going to check
    //depending on the coverage config and total number of discovered chunks
    //this number should be added to the nr_of_chechees
    //nr_of_checkees += this->num_chunks_per_block;
    checkee_reference_index[reference_index++] =
        bb->instructions().size() - no_orig_bb_instructions;
    assm.push(block_graph::Immediate(nr_of_checkees,
                                     assm::ValueSize::kSize32Bit));

    // Count the number of instructions added so far into the basic block
    // This information is used to set a label on the following push instr
    checkee_size_index[k++] = bb->instructions().size() - no_bb_instructions;
    no_bb_instructions = bb->instructions().size();

    // push the size of the checkee
    uint32_t size_of_checkee = (*this->basic_block_sizes_)[checkee_it->first];
    assm.push(block_graph::Immediate(size_of_checkee,
                                     assm::ValueSize::kSize32Bit));

    BlockGraph::Label checkee_label =
      (*this->id_to_label_)[checkee_it->first];
    std::pair<BlockGraph::Block*, uint32_t> block_offset_pair =
      (*this->label_name_to_block_)[checkee_label.name()];
    BlockGraph::Block* checkee_block = block_offset_pair.first;
    uint32_t checkee_offset = block_offset_pair.second;

    DCHECK(checkee_block != NULL);

    checkee_label_map.insert(std::make_pair(
      bb->instructions().size() - no_orig_bb_instructions, checkee_it->first));
    if (this->insert_file_ != NULL){
      fprintf(this->insert_file_, "%s,", checkee_label.name().c_str());
    }
    if (checkee_block->id() != subgraph->original_block()->id()) {
      assm.push(block_graph::Immediate(checkee_block, checkee_offset));
    } else { // checkee is in the same subgraph as checker
      BasicBlock *checkee_bb =
        GetBasicBlockAtOffset(subgraph, checkee_offset);
      DCHECK(checkee_bb != NULL);
      assm.push(block_graph::Immediate(checkee_bb));
    }

    hash += (*this->precomputed_hashes_)[checkee_it->first] *
      checkee_it->second;
  }
  if (this->insert_file_ != NULL) {
    fprintf(this->insert_file_, "\n");
  }

  // 2 stack slots holding accumulator for hash and hash of return address
  assm.sub(assm::esp, block_graph::Immediate(0x8));

  // get size in bytes of the code inserted so far
  uint32_t call_offset = 0;
  uint32_t no_added_instructions = bb->instructions().size() -
    no_orig_bb_instructions;
  auto inst_iter3 = bb->instructions().begin();
  for (uint32_t k = 0; (inst_iter3 != bb->instructions().end()) &&
    (k < no_added_instructions); ++inst_iter3, ++k) {
    call_offset += inst_iter3->size();
  }
  this->basic_block_hash_call_offset_[bb_id] = call_offset;

  assm.call(block_graph::Immediate(this->hash_block_, 0));
  //keep the index of the pivot byte/instruction
  pivot_instruction_index =
    bb->instructions().size() - no_orig_bb_instructions;

  assm.data((uint8_t)0);
  //let the result be in the stack so later we can retrieve it
  uint32_t no_pushed_words = 4 * checkee_list.size() + 2;
  assm.add(assm::esp, block_graph::Immediate(no_pushed_words * 4));
  //checksum from the xor function must be added to the add checksum result
  if (*perform_chunk_checks_) {
    assm.pop(assm::ebx);
    assm.add(assm::al, assm::bl);
  } else {
    // If we are not checking chunks we don't need to pop the runtime computed
    // hash of the chunks. However, Syzygy loses the label added to the sub
    // instruction (next instruction) because it tries to disassemble the data
    // byte after the call to the hash function, which leads to different
    // instructions than during execution. Label will be misaligned. Adding
    // these instructions prevents runtime assertion check error about lost
    // labels.
    assm.push(block_graph::Immediate(0,assm::ValueSize::kSize32Bit));
    assm.pop(assm::ebx);
    assm.add(assm::al, assm::bl);
  }
  sub_instruction_index = bb->instructions().size() - no_orig_bb_instructions;
  assm.sub(assm::al, block_graph::Immediate(hash, assm::ValueSize::kSize8Bit));
  assm.data((uint8_t)0x66); // CBW
  assm.data((uint8_t)0x98);
  assm.xor(assm::al, assm::ah);
  assm.sub(assm::al, assm::ah);
  assm.sub(assm::al, block_graph::Immediate(no_abs_references,
    assm::ValueSize::kSize8Bit));
  assm.j(assm::ConditionCode::kAbove,
         block_graph::Immediate(this->response_block_, 0));

  assm.pop(assm::edx);
  assm.pop(assm::ecx);
  assm.pop(assm::ebx);
  assm.pop(assm::eax);

  // Add label to begining of integrity check
  label = BlockGraph::Label(std::to_string(bb_id),
    BlockGraph::CODE_LABEL);
  inst_iter = bb->instructions().begin();
  inst_iter->set_label(label);

  (*this->id_to_label_)[bb_id] = label;
  uint32_t num_no_chunk_added = 0;
  uint32_t ref_instruction_index = 0;
  // Update the size of the basic block to include integrity check code
  // and add the sub instruction label
  uint32_t new_size = 0;
  for (uint32_t s = 0; inst_iter != bb->instructions().end(); ++inst_iter, s++)
  {
    new_size += inst_iter->size();
    auto checkee_label_iter = checkee_label_map.find(s);
    if (checkee_label_iter != checkee_label_map.end()){
      char  *buffer = new char[50];
      sprintf_s(buffer, 50, "block %llu %llu",
                checkee_label_iter->second,bb_id);
      //LOG(INFO) << " Assigned pivot label: " << buffer;
      label = BlockGraph::Label(base::StringPiece(buffer),
        BlockGraph::CODE_LABEL);
      inst_iter->set_label(label);
      delete[] buffer;
    } else if (s == pivot_instruction_index) { // add the pivot label
      char  *buffer = new char[50];
      sprintf_s(buffer, 50, "Pivot:%llu", bb_id);
      //LOG(INFO) << " Assigned pivot label: " << buffer;
      label = BlockGraph::Label(base::StringPiece(buffer),
        BlockGraph::CODE_LABEL);
      inst_iter->set_label(label);
      delete[] buffer;
    } else if (s == sub_instruction_index) { // add the pivot label
      char  buffer[50];
      sprintf_s(buffer, 50, "sub %llu", bb_id);
      //LOG(INFO) << " Assigned pivot label: " << buffer;
      label = BlockGraph::Label(buffer, BlockGraph::CODE_LABEL);
      inst_iter->set_label(label);
    }
    else if (*perform_chunk_checks_ &&
             ref_instruction_index < checkee_list.size() &&
             s == checkee_reference_index[ref_instruction_index]) {
      // add the no_checkee label
      ++ref_instruction_index;
      char  *buffer = new char[50];
      sprintf_s(buffer, 50, "ref %llu", bb_id);
      //LOG(INFO) << " Assigned num chunk label: " << s <<" "<< buffer;
      label = BlockGraph::Label(base::StringPiece(buffer),
        BlockGraph::CODE_LABEL);
      inst_iter->set_label(label);
      num_no_chunk_labels++;
      num_no_chunk_added++;
      delete[] buffer;
    }
  }
  uint32_t old_size = (*this->basic_block_sizes_)[bb_id];
  DCHECK_GT(new_size, static_cast<uint32_t>(0x49));
  DCHECK(old_size < new_size);
  if (*perform_chunk_checks_){
    CHECK_EQ(num_no_chunk_added, checkee_list.size());
  }
  (*this->basic_block_sizes_)[bb_id] = new_size;// - call_offset;

  //Set iterator to the beginning of the list
  inst_iter = bb->instructions().begin();


  checkee_it = checkee_list.begin();
  // Add labels to instructions which push basic block size
  for (uint32_t k = 0; k < checkee_list.size(); ++k) {
    for (uint32_t j = 0; j < checkee_size_index[k]; ++j) {
      inst_iter++;
    }
    char  *buffer=new char[50];
    sprintf_s(buffer, 50, "size %llu %llu", checkee_it->first, bb_id);
    checkee_it++;
    label = BlockGraph::Label(base::StringPiece(buffer),
      BlockGraph::CODE_LABEL);
    inst_iter->set_label(label);
	  delete[] buffer;
    num_size_reference_labels++;
  }

  delete[] checkee_size_index;
  delete[] checkee_reference_index;
  return; //remove this when you have inner BB references
}
uint32_t num_protecting_blocks = 0;

bool IntegrityCheckTransform::ProcessAllBlocks(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    IntegrityCheckTransform::ProcessingType step) {
  BlockOrdering order;
  FlattenCallGraphPostOrder(block_graph, &order);
#if defined PRINT_BLOCK_NAMES
  std::ofstream blocknames_file;
  blocknames_file.open("block_names.csv");
#endif
  auto block_iter = order.begin();
  for (; block_iter != order.end(); ++block_iter) {
    BlockGraph::Block* block = *block_iter;
#if defined PRINT_BLOCK_NAMES
    if (!policy->BlockIsSafeToBasicBlockDecompose(block))
      continue;
    blocknames_file <<block->name()<<",\n";
    continue;
#endif
    if (!ShouldProcessBlock(block, this->target_names_))
      continue;
    // Use the decomposition policy to skip blocks that aren't eligible for
    // basic-block decomposition.
    if (!policy->BlockIsSafeToBasicBlockDecompose(block))
      continue;

    // Decompose block to basic blocks.
    BasicBlockSubGraph *subgraph = new BasicBlockSubGraph();
    BasicBlockDecomposer bb_decomposer(block, subgraph);
    if (!bb_decomposer.Decompose())
      return false;

    if (!TransformBasicBlockSubGraph(
      block_graph, subgraph, step)) {
      return false;
    }

    // Update the block-graph post transform.
    BlockBuilder builder(block_graph);
    if (!builder.Merge(subgraph)) {
      return false;
    }
    ++num_protecting_blocks;

    const BlockVector& blocks = builder.new_blocks();
    auto new_block = blocks.begin();
    for (; new_block != blocks.end(); ++new_block) {
      // This is needed until the labels refactoring.
      (*new_block)->set_attribute(BlockGraph::BUILT_BY_SYZYGY);

      if (step == INSERT_CHECKS || INSERT_CHUNK_CHECKS) {
        UpdateLabelToBlockMap(*new_block);
      }
    }
  }
#if defined PRINT_BLOCK_NAMES
  blocknames_file.close();
  exit(1);
#endif
  return true;
}

uint64_t
IntegrityCheckTransform::GetChunkOriginalBlockId(const ChunkInfo *chunk){
  if (chunk->original_block_id_ == 0){
    bool before_chunk_integrity_code_added = true;
    char* chunk_label = MakeChunkLabel(chunk->block_id_, chunk->chunk_index_,
                                       before_chunk_integrity_code_added);
    auto chunk_label_it = label_name_to_block_->find(chunk_label);
    CHECK(chunk_label_it != label_name_to_block_->end());
    delete[] chunk_label;
    chunk->original_block_id_ = chunk_label_it->second.first->id();
  }
  return chunk->original_block_id_;
}

std::set<uint32_t> IntegrityCheckTransform:: PickChunks(
    const std::vector<ChunkInfo> chunks_vector,
    const std::vector<uint32_t> partition_indexes,
    const uint32_t num_picks,
    const uint64_t checker_block_id,
    const std::vector<uint32_t>::iterator end_chunk_it,
    std::vector<uint32_t>::iterator last_visited_chunk,
    std::set<uint32_t> *unused_chunks){
  std::set<uint32_t> picked_set;


  //attempt to pick from unused chunks
  for (auto unused_chunk_it = unused_chunks->begin();
    unused_chunk_it != unused_chunks->end() && picked_set.size() < num_picks;){
    uint64_t chunk_orig_block_id = GetChunkOriginalBlockId(
      &chunks_vector[*unused_chunk_it]);
    if (chunk_orig_block_id != checker_block_id){
      picked_set.insert(*unused_chunk_it);
      unused_chunks->erase(unused_chunk_it);
      unused_chunk_it = unused_chunks->begin();
    }
    else {
      ++unused_chunk_it;
    }
  }

  //iterate over chunks
  for (; last_visited_chunk != end_chunk_it && picked_set.size() < num_picks;
        ++last_visited_chunk){
    uint64_t chunk_orig_block_id = GetChunkOriginalBlockId(
         &chunks_vector[*last_visited_chunk]);
    if (chunk_orig_block_id != checker_block_id){
      picked_set.insert(*last_visited_chunk);
    } else {
      unused_chunks->insert(*last_visited_chunk);
    }
  }//end for

  // if we don't have enough unique chunk, then we pick from
  // already visited chunks
  if (picked_set.size() < num_picks){
    for (auto index_it = partition_indexes.begin();
        index_it != partition_indexes.end() && picked_set.size() < num_picks;
        ++index_it){
      uint64_t chunk_orig_block_id = GetChunkOriginalBlockId(
          &chunks_vector[*index_it]);
      if (chunk_orig_block_id != checker_block_id){
        picked_set.insert(*index_it);
      }//end if
    }//end for
  }//end if

  DCHECK_EQ(picked_set.size(), num_picks);
  return picked_set;
}

std::map<uint64_t, std::set<uint32_t>>
IntegrityCheckTransform::GenerateChunkCombinations(
    const std::vector<ChunkInfo> chunks_vector,
    const float chunk_coverage, const bool enforce_unique_chunks,
    uint32_t *no_chunks_per_block){

  DCHECK_GT(chunk_coverage, static_cast<float>(0));
  DCHECK_LE(chunk_coverage, static_cast<float>(10));


  std::vector<ChunkInfo> temp_chunk_vector = chunks_vector;
  std::vector<uint32_t> temp_noref_chunk_vector;
  std::vector<uint32_t> temp_ref_chunk_vector;
  int i = 0;
  //partition chunks based on their next instruction's absolute reference
  //status
  for (auto chunk_it = temp_chunk_vector.begin();
      chunk_it != temp_chunk_vector.end(); ++chunk_it,++i){
    if (chunk_it->next_instruction_size_ == 0)
      temp_noref_chunk_vector.push_back(i);
    else
      temp_ref_chunk_vector.push_back(i);
  }

  //shuffle chunks to make sure that checkers check integrity of random blocks
  auto engine = std::default_random_engine{};
  std::shuffle(std::begin(temp_noref_chunk_vector),
               std::end(temp_noref_chunk_vector), engine);

  std::shuffle(std::begin(temp_ref_chunk_vector),
               std::end(temp_ref_chunk_vector), engine);

  //compute number of chunks according to the input coverage
  uint32_t total_chunk_checks = chunks_vector.size() * chunk_coverage;
  uint32_t num_ref_chunks = 0;
  int32_t num_noref_chunks = 0;
  //preference is to pick chunks with abs address at the end
  if (temp_ref_chunk_vector.size() >= total_chunk_checks) {
    num_ref_chunks = total_chunk_checks;
    num_noref_chunks = 0;
  } else if(chunk_coverage <= 1.0f) {
    num_ref_chunks = temp_ref_chunk_vector.size();
    num_noref_chunks = total_chunk_checks - num_ref_chunks;
  } else {
    num_ref_chunks = std::min(
        static_cast<uint32_t>(temp_ref_chunk_vector.size()* chunk_coverage),
        total_chunk_checks);
    num_noref_chunks = total_chunk_checks - num_ref_chunks;
  }

  uint32_t no_chunks_per_checker = total_chunk_checks /
      checker_to_checkee_map_->size();

  //the base address cancelation only works for even number of chunks
  if (no_chunks_per_checker % 2 != 0){
    LOG(INFO) << "current coverage does not generate even number of chunks, "
              << "thus the number of chunks was incremented!";
    no_chunks_per_checker++;
  }

  LOG(INFO) << "chunk coverage:" << chunk_coverage;
  LOG(INFO) << "#all chunks:" << total_chunk_checks;
  LOG(INFO) << "#chunks per checker:" << no_chunks_per_checker;
  LOG(INFO) << "#+chunks (with absolute instruction):" << num_ref_chunks;
  LOG(INFO) << "#^chunks (no absolute instruction):" << num_noref_chunks;
  *no_chunks_per_block = no_chunks_per_checker;

  DCHECK_GE(no_chunks_per_checker, static_cast<uint32_t>(1));

  auto checker_it = checker_to_checkee_map_->begin();
  std::set<uint32_t> unused_noref_chunks;
  std::set<uint32_t> unused_ref_chunks;
  std::map<uint64_t, std::set<uint32_t>> temp_assignment_map;
  auto noref_chunk_it = temp_noref_chunk_vector.begin();
  auto ref_chunk_it = temp_ref_chunk_vector.begin();

  auto noref_chunk_end_it = temp_noref_chunk_vector.end();
  auto ref_chunk__end_it = temp_ref_chunk_vector.end();

  while (checker_it != checker_to_checkee_map_->end()){
    std::set<uint32_t> chunks;
    uint64_t bb_id = checker_it->first;
    BlockGraph::Label checker_label = (*this->id_to_label_)[bb_id];
    auto checker_label_it = label_name_to_block_->find(checker_label.name());
    CHECK(checker_label_it != label_name_to_block_->end());
    uint64_t checker_block_id = checker_label_it->second.first->id();
    //first pick from no reference partition
    if (num_noref_chunks > 0){
      chunks = PickChunks(chunks_vector, temp_noref_chunk_vector,
                          no_chunks_per_checker, checker_block_id,
                          noref_chunk_end_it, noref_chunk_it,
                          &unused_noref_chunks);
      num_noref_chunks -= no_chunks_per_checker;
    } else { // pick the rest of chunks from reference chunks
      chunks = PickChunks(chunks_vector, temp_ref_chunk_vector,
                          no_chunks_per_checker, checker_block_id,
                          ref_chunk__end_it, ref_chunk_it,
                          &unused_ref_chunks);
    }
    temp_assignment_map[bb_id] = chunks;
    ++checker_it;
  }

  return temp_assignment_map;
}

void IntegrityCheckTransform::GenerateBasicBlockCombinations() {
  int partition_num = 1;
  int nr_size_one = 0;
  srand(time(NULL));

  FILE* part_file = NULL;
  fopen_s(&part_file, "partitions.csv", "w");
  if (part_file == NULL)
    LOG(INFO) << "Cannot open partition file";

  auto it_part = this->partition_map_.begin();
  for (; it_part != this->partition_map_.end(); ++it_part) {
    LOG(INFO) << "Partition #" << partition_num << " : ";
    LOG(INFO) << (*it_part).second.size();

    if ((*it_part).second.size() <= 1) {
      /*
      std::list<std::set<uint64_t>> checkOrder;
      checkOrder.push_back((*it_part).second);
      checkOrder.push_back((*it_part).second);
      */
      ++nr_size_one;
    } else { // there are multiple BBs in this partition
      PopulateCheckMaps((*it_part).second);
    }

    ++partition_num;
  }

  // check if any blocks are not checking anything
  auto checker_it = id_to_label_->begin();
  for (; checker_it != id_to_label_->end(); ++checker_it){
    auto checkee_list = (*checker_to_checkee_map_)[checker_it->first];
    if (checkee_list.size() == 0) { // then this BB is not checking other BBs.
      // Find a pair of basic blocks to check.
      it_part = this->partition_map_.begin();
      std::map<uint64_t, int> checkee_map;
      bool found_pair = false;

      for (; it_part != this->partition_map_.end(); ++it_part) {
        if (it_part->second.size() < 2) // partition is too small
          continue;
        // Check if partition has at least 2 BBs that are not in the same block
        // as the checker
        uint32_t checker_block = (uint32_t) checker_it->first;
        std::set<uint64_t> bbs_in_different_block;
        auto part_block_it = it_part->second.begin();

        for (; part_block_it != it_part->second.end(); ++part_block_it) {
          if (checker_block != ((uint32_t)*part_block_it))
            bbs_in_different_block.insert(*part_block_it);
        }
        if (bbs_in_different_block.size() > 1) { // use first 2 BBs
          auto checkee_it = bbs_in_different_block.begin();
          checkee_map[*checkee_it] = 1;
          checkee_it++;
          checkee_map[*checkee_it] = -1;
          found_pair = true;
          break;
        }
      }

      DCHECK(checkee_map.size() == 2);
      (*checker_to_checkee_map_)[checker_it->first] = checkee_map;
    }
  }

  fclose(part_file);

  LOG(INFO) << "nr_size_one : " << nr_size_one;
}

bool IntegrityCheckTransform::TransformBlockGraph(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {
  fopen_s(&this->pfile_, "integrityChecks.csv", "w");
  if (this->pfile_ == NULL)
    LOG(INFO) << "Cannot open graph file";

  if (!TransformBasicBlockSubGraph(
      block_graph, NULL,
      IntegrityCheckTransform::ADD_HASH_AND_RESPONSE)) {
    return false;
  }

  fopen_s(&this->prefile_, "preChecks.csv", "w");
  if (this->prefile_ == NULL)
    LOG(INFO) << "Cannot open graph file";

  num_protecting_blocks = 0;
  // Compute the hash of all basic blocks in all blocks of the block_graph.
  // This hash will be hard-coded inside the integrity-check-code inserted in
  // each basic block. It will be compared with the hash computed at runtime.
  if (!ProcessAllBlocks(policy, block_graph,
      IntegrityCheckTransform::PRECOMPUTE_HASHES))
    return false;

  if(num_protecting_blocks, this->target_names_.size())
    LOG(INFO) << "Failed to find some targets, protected blocks:"
              << num_protecting_blocks << " provided:"
              << this->target_names_.size();

  fclose(this->prefile_);

  GenerateBasicBlockCombinations();

  fclose(this->pfile_);

  int nr_not_checked = 0;
  int total_number = 0;
  //Print all nodes not checked by any other nodes
  auto map_it = this->precomputed_hashes_->begin();
  for (; map_it != this->precomputed_hashes_->end(); ++map_it) {
    if (this->is_bb_checked_map_.find((*map_it).first) ==
        this->is_bb_checked_map_.end()) {
      //LOG(INFO) << "BB " << (*mapIt).first << " is not checked ";
      ++nr_not_checked;
    }
    ++total_number;
  }

  int nr_3_combo_found = 0;
  LOG(INFO) << "Combo 3 Found: " << nr_3_combo_found;
  LOG(INFO) << "Not Checked: " << nr_not_checked;
  LOG(INFO) << "Total number:" << total_number;

  fopen_s(&this->insert_file_, "inserted-integrityChecks.csv", "w");
  if (this->insert_file_ == NULL)
    LOG(INFO) << "Cannot open graph file";

  GenerateLabelToBlockMap(block_graph);

  // Add the assembly code representing integrity checks in each basic block
  // that was picked to perform a dynamic check in the combination of basic
  // blocks (see method GenerateBasicBlockCombinations()).
  if (!ProcessAllBlocks(policy, block_graph,
      IntegrityCheckTransform::INSERT_CHECKS))
    return false;

  fclose(this->insert_file_);
  LOG(INFO) << "Inserting checks done";

  fopen_s(&this->fix_file_, "fixIntegrityChecks.csv", "w");
  if (this->fix_file_ == NULL)
    LOG(INFO) << "Cannot open graph file";

  if (*perform_chunk_checks_){
    if (!ProcessAllBlocks(policy, block_graph,
      IntegrityCheckTransform::COMPUTE_CHUNKS))
      return false;
    LOG(INFO) << "Computing integrity inter block chunks is done";

    //Require label update
    GenerateLabelToBlockMap(block_graph);


    //shuffle up integrity chunks
    *ic_chunk_checker_to_checkee_map_ = GenerateChunkCombinations(
      *ic_block_reference_free_chunks,
      chunk_checking_coverage,
      kForceUniqueChunks,
      &num_chunks_per_block);

    LOG(INFO) << "Shuffling integrity inter block chunks is done";

    if (!ProcessAllBlocks(policy, block_graph, INSERT_CHUNK_CHECKS))
      return false;
    LOG(INFO) << "Inserting chunk checks is done";
  } else {
    LOG(INFO) << "Xor chunk protection is switched off.";
  }
  //Require label update
  GenerateLabelToBlockMap(block_graph);

  // Patch inter block references that were broken by the insertion of
  // integrity checks.
  if (!ProcessAllBlocks(policy, block_graph,
      IntegrityCheckTransform::PATCH_REFERENCES_SIZES)) {
    return false;
  }

  LOG(INFO) << "Patching block references and sizes are done";
  LOG(INFO) << "Elapsed seconds in patching chunks(due to size changes:"
  <<elapsed_secs_in_patching_chunks;
  CHECK_EQ(num_chunk_reference_labels , num_chunk_reference_patched_labels);
  CHECK_EQ(num_no_chunk_labels, num_no_chunk_patched_labels);
  CHECK_EQ(num_size_reference_labels, num_size_reference_patched_labels);
  if (num_size_reference_labels != num_size_reference_patched_labels){
    LOG(ERROR) << "Some size labels were not patched, total lables:" <<
      num_size_reference_labels << " patched:"
      << num_size_reference_patched_labels;
  }

  //Require label update
  GenerateLabelToBlockMap(block_graph);

  fclose(this->fix_file_);

  std::map<uint64_t, uint32_t> checkee_count_checker;
  std::ofstream myfile;
  myfile.open("graph.csv");
  auto checker_it = this->checker_to_checkee_map_->begin();
  for (; checker_it != this->checker_to_checkee_map_->end();
       ++checker_it) {
	  for (auto checkee_it = checker_it->second.begin();
	       checkee_it != checker_it->second.end();
		     ++checkee_it) {
		  myfile << checker_it->first << "," << checkee_it->first << "\n";
		  ++checkee_count_checker[checkee_it->first];
	  }
  } //end for
  myfile.close();
  myfile.open("notbeingchecked.csv");
  checker_it = checker_to_checkee_map_->begin();
  for (; checker_it != this->checker_to_checkee_map_->end();
       ++checker_it) {
	  if (checkee_count_checker.find(checker_it->first) ==
		    checkee_count_checker.end()) {
		  myfile << checker_it->first << "\n";
	  }
  }
  myfile.close();
#if defined COMPUTE_CHECKER_SIZE
  myfile.open("checkersize.csv");
  myfile << "total checker size(byte):"<<total_checker_size;
  myfile.close();
#endif
  myfile.open("chunkinfo.csv");
  myfile << "total chunks:" << ic_block_reference_free_chunks->size();
  myfile << "total checked chunks:" << checker_to_checkee_map_->size() *
                                       num_chunks_per_block;
  myfile.close();
  myfile.open("chunkgraph.csv");
  for (auto chunk_checker_it = ic_chunk_checker_to_checkee_map_->begin();
       chunk_checker_it != ic_chunk_checker_to_checkee_map_->end();
	     ++chunk_checker_it) {
	  for (auto chunk_checkee_it = chunk_checker_it->second.begin();
	  chunk_checkee_it != chunk_checker_it->second.end();
		  ++chunk_checkee_it) {
		  myfile << chunk_checker_it->first << "," <<
			  (*ic_block_reference_free_chunks)[*chunk_checkee_it].block_id_
			  <<"\n";
	  }
  }
  myfile.close();
  return true;
}

IntegrityCheckTransform::~IntegrityCheckTransform() {
  ic_block_reference_free_chunks->clear();
  ic_block_chunk_index_map_->clear();
  ic_chunk_checker_to_checkee_map_->clear();
  //_CrtDumpMemoryLeaks();
}

// static vars
const char IntegrityCheckTransform::kTransformName[] =
"IntegrityCheckTransform";

}// namespace protect
