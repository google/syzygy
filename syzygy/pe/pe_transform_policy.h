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
//
// Declares the PE-specific transform policy object. This guides decisions made
// during image decomposition, basic-block decomposition, transforms and block
// building.

#ifndef SYZYGY_PE_PE_TRANSFORM_POLICY_H_
#define SYZYGY_PE_PE_TRANSFORM_POLICY_H_

#include "syzygy/block_graph/transform_policy.h"

namespace pe {

// The interface that guides image and basic-block transform decisions for PE
// files.
class PETransformPolicy : public block_graph::TransformPolicyInterface {
 public:
  PETransformPolicy();
  virtual ~PETransformPolicy() { }

  // @name TransformPolicyInterface implementation
  // @{
  virtual bool BlockIsSafeToBasicBlockDecompose(
      const BlockGraph::Block* block) const OVERRIDE;
  virtual bool ReferenceIsSafeToRedirect(
      const BlockGraph::Block* referrer,
      const BlockGraph::Reference& reference) const OVERRIDE;
  // @}

  bool allow_inline_assembly() const { return allow_inline_assembly_; }
  void set_allow_inline_assembly(bool value) {
    allow_inline_assembly_ = value;
  }

  // TODO(chrisha): When Decomposer disappears (the last place doing disassembly
  //     that is *not* the basic-block decomposer), make these protected member
  //     functions.

  // Internal implementation details. Exposed for unittesting.
  bool CodeBlockIsSafeToBasicBlockDecompose(
      const BlockGraph::Block* code_block) const;
  // Checks that the attributes (derived from symbol data) are consistent.
  static bool CodeBlockAttributesAreBasicBlockSafe(
      const BlockGraph::Block* code_block,
      bool allow_inline_assembly);
  // Checks that a block contains private symbols. These are required for
  // basic block disassembly.
  static bool CodeBlockHasPrivateSymbols(const BlockGraph::Block* code_block);
  // Checks that the code-data layout of the block is consistent. Assumes that
  // the block attributes have already been checked and are valid.
  static bool CodeBlockLayoutIsClConsistent(
      const BlockGraph::Block* code_block);
  // Checks that all outgoing references are consistent. Assumes that the block
  // attributes have already been checked and are valid.
  static bool CodeBlockReferencesAreClConsistent(
      const BlockGraph::Block* code_block);
  // Checks that all referrers are consistent. Assumes that the block layout has
  // already been checked and is valid.
  static bool CodeBlockReferrersAreClConsistent(
      const BlockGraph::Block* code_block);

 protected:
  // Block IDs are stable, unique and can't be reused. That makes them perfect
  // for a cache ID.
  typedef std::map<const BlockGraph::BlockId, bool> BlockResultCache;
  scoped_ptr<BlockResultCache> block_result_cache_;

  // Determines whether or not we will allow decomposition of blocks with
  // inline assembly.
  bool allow_inline_assembly_;

  DISALLOW_COPY_AND_ASSIGN(PETransformPolicy);
};

}  // namespace pe

#endif  // SYZYGY_PE_PE_TRANSFORM_POLICY_H_
