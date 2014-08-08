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
// Declaration of BasicBlockSubGraph class.

#ifndef SYZYGY_BLOCK_GRAPH_BASIC_BLOCK_SUBGRAPH_H_
#define SYZYGY_BLOCK_GRAPH_BASIC_BLOCK_SUBGRAPH_H_

#include <map>
#include <set>
#include <string>

#include "base/basictypes.h"
#include "base/strings/string_piece.h"
#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/block_graph.h"

namespace block_graph {

// A basic-block sub-graph describes the make-up and layout of one or
// more blocks as a set of code, data, and/or padding basic-blocks. Optionally,
// it holds a pointer to a block from which the sub-graph was originally
// derived.
//
// In manipulating the basic block sub-graph, note that the sub-graph
// acts as a basic-block factory and retains ownership of all basic-blocks
// that participate in the composition.
class BasicBlockSubGraph {
 public:
  typedef block_graph::BasicBlock BasicBlock;
  typedef block_graph::BasicCodeBlock BasicCodeBlock;
  typedef block_graph::BasicDataBlock BasicDataBlock;
  typedef block_graph::BasicEndBlock BasicEndBlock;
  typedef BasicBlock::BasicBlockType BasicBlockType;
  typedef std::list<BasicBlock*> BasicBlockOrdering;
  typedef block_graph::BlockGraph BlockGraph;
  typedef BlockGraph::Block Block;
  typedef BlockGraph::BlockType BlockType;
  typedef BlockGraph::Offset Offset;
  typedef BlockGraph::SectionId SectionId;
  typedef BlockGraph::Size Size;
  typedef BlockGraph::BlockAttributes BlockAttributes;

  // A structure describing a block (its properties, attributes, and
  // constituent ordered basic-blocks). A given basic-block may participate
  // in at most one BlockDescription at any time.
  struct BlockDescription {
    std::string name;
    std::string compiland_name;
    BlockType type;
    SectionId section;
    Size alignment;
    BlockAttributes attributes;
    BasicBlockOrdering basic_block_order;
  };

  typedef BlockGraph::BlockId BlockId;
  typedef std::list<BlockDescription> BlockDescriptionList;
  typedef std::set<BasicBlock*, BasicBlockIdLess> BBCollection;
  typedef std::map<const BasicBlock*, bool> ReachabilityMap;

  // Initialize a basic block sub-graph.
  BasicBlockSubGraph();
  // Releases all resources.
  ~BasicBlockSubGraph();

  // @name Accessors.
  // @{
  void set_original_block(const Block* block) { original_block_ = block; }
  const Block* original_block() const { return original_block_; }

  const BBCollection& basic_blocks() const { return  basic_blocks_; }
  BBCollection& basic_blocks() { return  basic_blocks_; }

  const BlockDescriptionList& block_descriptions() const {
    return block_descriptions_;
  }
  BlockDescriptionList& block_descriptions() { return block_descriptions_; }
  // @}

  // Initializes and returns a new block description.
  // @param name The name of the block.
  // @param compiland The name of the compiland associated with this block.
  // @param type The type of the block.
  // @param section The ID of the section in which the block should reside.
  // @param alignment The alignment of the block.
  //     (i.e., location % alignment == 0)
  // @param attributes The attributes of the block.
  // @returns A pointer to the newly created block description.
  BlockDescription* AddBlockDescription(const base::StringPiece& name,
                                        const base::StringPiece& compiland,
                                        BlockType type,
                                        SectionId section,
                                        Size alignment,
                                        BlockAttributes attributes);

  // Add a new basic code block to the sub-graph.
  // @param name A textual identifier for this basic block.
  // @returns A pointer to a newly allocated basic code block.
  BasicCodeBlock* AddBasicCodeBlock(const base::StringPiece& name);

  // Add a new basic data block to the sub-graph.
  // @param name A textual identifier for this basic block.
  // @param size The number of bytes this basic block occupied in the original
  //     block. Set to 0 if this is a generated basic block.
  // @param data The underlying data representing the basic data block.
  // @returns A pointer to a newly allocated basic data block representing the
  //     original source range [@p offset, @p offset + @p size), or NULL on
  //     ERROR. Ownership of the returned basic-block (if any) is retained
  //     by the composition.
  BasicDataBlock* AddBasicDataBlock(const base::StringPiece& name,
                                    Size size,
                                    const uint8* data);

  // Adds a basic end block to the sub-graph. This basic block is a zero sized
  // placeholder block that is simply for carrying labels and references
  // beyond the end of a block.
  // @returns a pointer to the newly allocated basic end block
  BasicEndBlock* AddBasicEndBlock();

  // Remove a basic block from the subgraph.
  // @param bb The basic block to remove.
  // @pre @p bb must be in the graph.
  void Remove(BasicBlock* bb);

  // Returns true if the basic-block composition is valid. This tests the
  // for following conditions.
  // 1. Each basic-block is used in at most one BlockDescription.
  // 2. Each code basic-block has valid successors.
  // 3. If there is an original block, then each of it's referrers is accounted
  //    for in the new composition.
  bool IsValid() const;

  // Traverses the basic-block subgraph and computes the reachability of all
  // basic-blocks starting from the entry-point.
  void GetReachabilityMap(ReachabilityMap* rm) const;

  // A helper function for querying a reachability map.
  static bool IsReachable(const ReachabilityMap& rm, const BasicBlock* bb);

  // Dump a text representation of this subgraph.
  // @param buf receives the text representation.
  // @returns true if this subgraph was successfully dumped, false otherwise.
  bool ToString(std::string* buf) const;

 protected:
  // @name Validation Functions.
  // @{
  bool MapsBasicBlocksToAtMostOneDescription() const;
  bool HasValidSuccessors() const;
  bool HasValidReferrers() const;
  // @}

  // The original block corresponding from which this sub-graph derives. This
  // is optional, and may be NULL.
  const Block* original_block_;

  // The set of basic blocks in this sub-graph. This includes any basic-blocks
  // created during the initial decomposition process, as well as any additional
  // basic-blocks synthesized thereafter.
  BBCollection basic_blocks_;

  // A list of block descriptions for the blocks that are to be created from
  // this basic block sub-graph.
  BlockDescriptionList block_descriptions_;

  // Our block ID allocator.
  BlockId next_block_id_;

 private:
  DISALLOW_COPY_AND_ASSIGN(BasicBlockSubGraph);
};

}  // namespace block_graph

#endif  // SYZYGY_BLOCK_GRAPH_BASIC_BLOCK_SUBGRAPH_H_
