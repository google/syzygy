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
//
// Declares the basic block layout transform. This transform is responsible for
// applying a fully specified basic block layout, allowing for basic blocks to
// be ordered within a block, and split across blocks and sections. A basic
// block layout also specifies a section and block ordering. This transform
// modifies the provided order in-place so that it can be applied to the
// post-transform image using the standard ExplicitOrderer.

#ifndef SYZYGY_REORDER_TRANSFORMS_BASIC_BLOCK_LAYOUT_TRANSFORM_H_
#define SYZYGY_REORDER_TRANSFORMS_BASIC_BLOCK_LAYOUT_TRANSFORM_H_

#include "syzygy/block_graph/transforms/iterative_transform.h"
#include "syzygy/reorder/reorderer.h"

namespace reorder {
namespace transforms {

// A class that transforms a block graph at the basic block level, ordering
// basic blocks within blocks, and splitting basic blocks across blocks and
// sections (creating and modifying sections as necessary). Intended to be
// paired with an ExplicitOrderer in order to fully transform and order an
// image.
//
// There is no mechanism provided to explicitly delete a section. However, a
// section that contains no blocks post-ordering will be implicitly deleted.
//
// The provided Order is modified as follows:
//
// (1) Section specifications that cause new sections to be created will have
//     their id's filled out with the id of the newly created section.
// (2) Block specifications that include basic-block information (a non-empty
//     OffsetVector) will have their block pointer updated to point to the
//     newly created block, thus preventing the order from holding dangling
//     pointers. Additionally, the OffsetVector will be cleared as the BB
//     offsets are now meaningless in the context of the new block.
//
// Post-transformation the Order is a simply block-level ordering, with the
// BB-level ordering having been applied and extracted out of the Order. At
// this point it is able to be fed into an ExplicitOrderer for final ordering.
class BasicBlockLayoutTransform
    : public block_graph::transforms::IterativeTransformImpl<
          BasicBlockLayoutTransform> {
 public:
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::TransformPolicyInterface TransformPolicyInterface;
  typedef BlockGraph::RelativeAddress RelativeAddress;
  typedef Reorderer::Order Order;

  // Used for internal book-keeping. Exposed here so that anonymous helpers in
  // the implementation can access this.
  struct BlockInfo;
  typedef std::vector<BlockInfo> BlockInfos;

  // Constructor.
  // @param order the order specification to apply. The lifetime of this object
  //     must exceed that of any calls to TransformBlockGraph on this transform.
  //     This will be modified by the transformation. See class description for
  //     details.
  explicit BasicBlockLayoutTransform(Order* order);

  virtual ~BasicBlockLayoutTransform();

 private:
  // @name IterativeTransformImpl implementation.
  // @{
  friend block_graph::transforms::IterativeTransformImpl<
      BasicBlockLayoutTransform>;
  bool PreBlockGraphIteration(const TransformPolicyInterface* policy,
                              BlockGraph* block_graph,
                              BlockGraph::Block* header_block);
  bool OnBlock(const TransformPolicyInterface* policy,
               BlockGraph* block_graph,
               BlockGraph::Block* block);
  // @}

  // @name NamedBlockGraphTransformImpl implementation.
  // @{
  friend block_graph::transforms::NamedBlockGraphTransformImpl<
      BasicBlockLayoutTransform>;
  static const char kTransformName[];
  // @}

  bool FindOrCreateSections(BlockGraph* block_graph);
  bool FindOrCreateSection(BlockGraph* block_graph,
                           Order::SectionSpec* section_spec);

  // Builds the block information vector over order_.
  void BuildBlockInfos();

  // Gets the section ID associated with a given section specification.
  bool GetSectionId(const Order::SectionSpec* section_spec,
                    BlockGraph* block_graph,
                    BlockGraph::SectionId* section_id);

  // The ordering to be applied to the block graph by this transform.
  Order* order_;

  // A vector sorted by block-pointer, which allows efficient look-up of order
  // information for a particular source block.
  BlockInfos block_infos_;

  DISALLOW_COPY_AND_ASSIGN(BasicBlockLayoutTransform);
};

// A small helper structure used for efficiently looking up order information
// associated with a given source block.
struct BasicBlockLayoutTransform::BlockInfo {
  // This is a pointer to the block in the block_spec. We keep a copy of it
  // because it is our primary sort key and block_spec->block gets updated as
  // we work.
  const BlockGraph::Block* original_block;
  Order::SectionSpec* section_spec;
  Order::BlockSpec* block_spec;
};

// This basic block subgraph transform implements the layout described by the
// given BasicBlockMap. It is used by the BasicBlockLayoutTransform to
// transform individual blocks. This need not be publicly exposed, but is done
// so for ease of unittesting.
class BasicBlockSubGraphLayoutTransform
    : public block_graph::transforms::NamedBasicBlockSubGraphTransformImpl<
          BasicBlockSubGraphLayoutTransform> {
 public:
  typedef block_graph::BasicBlockSubGraph BasicBlockSubGraph;
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::TransformPolicyInterface TransformPolicyInterface;
  typedef Reorderer::Order Order;

  // When exploding a block, its basic blocks may end up being mapped across
  // multiple output blocks. This maps basic-blocks (as offsets in the original
  // block) to their output block (as an integer index) and position (as an
  // integer position).
  typedef std::pair<size_t, size_t> BlockPositionPair;  // (block, position).
  typedef std::map<Order::Offset, BlockPositionPair> BasicBlockMap;

  // Constructor.
  // @param bb_map The basic block map describing the layout of the basic blocks
  //     in the block to be transformed. This must not be empty and it must be
  //     well formed (block indices from 0 to block_count - 1, basic block
  //     position indices starting at 0 and contiguous).
  explicit BasicBlockSubGraphLayoutTransform(const BasicBlockMap& bb_map)
      : bb_map_(bb_map) {
    DCHECK(!bb_map.empty());
  }

  // @name BasicBlockSubGraphTransformInterface.
  // @{
  virtual bool TransformBasicBlockSubGraph(
      const TransformPolicyInterface* policy,
      BlockGraph* block_graph,
      BasicBlockSubGraph* basic_block_subgraph) override;
  // @}

 private:
  // @named NamedBasicBlockSubGraphTransformImpl implementation.
  // @{
  friend block_graph::transforms::NamedBasicBlockSubGraphTransformImpl<
      BasicBlockSubGraphLayoutTransform>;
  static const char kTransformName[];
  // @}

  // Creates the block descriptions and ensures their basic block lists are
  // all empty.
  typedef std::vector<BasicBlockSubGraph::BlockDescription*> BlockDescriptions;
  bool CreateBlockDescriptions(size_t block_count,
                               BasicBlockSubGraph* basic_block_subgraph,
                               BlockDescriptions* block_descs);

  const BasicBlockMap& bb_map_;

  DISALLOW_COPY_AND_ASSIGN(BasicBlockSubGraphLayoutTransform);
};

}  // namespace transforms
}  // namespace reorder

#endif  // SYZYGY_REORDER_TRANSFORMS_BASIC_BLOCK_LAYOUT_TRANSFORM_H_
