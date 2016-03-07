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
// Declares an ordering that randomizes blocks within their respective sections.

#ifndef SYZYGY_BLOCK_GRAPH_ORDERERS_RANDOM_ORDERER_H_
#define SYZYGY_BLOCK_GRAPH_ORDERERS_RANDOM_ORDERER_H_

#include "syzygy/block_graph/orderers/named_orderer.h"
#include "syzygy/core/random_number_generator.h"

namespace block_graph {
namespace orderers {

class RandomOrderer
    : public block_graph::orderers::NamedOrdererImpl<RandomOrderer> {
 public:
  // Constructs a random-orderer that works over the specified block-graph.
  // Initializes the random-number generator using the current time.
  // @param default_shuffle_section if true then the blocks in each section will
  //     be shuffled. If false the blocks in the section will remain in the same
  //     order as input. This sets the default value that is initially applied
  //     to all sections. Individual sections may have their value changed using
  //     SetShuffleSection.
  explicit RandomOrderer(bool default_shuffle_section);

  // Constructs a random-orderer that works over the specified block-graph.
  // @param default_shuffle_section if true then the blocks in each section will
  //     be shuffled. If false the blocks in the section will remain in the same
  //     order as input. This sets the default value that is initially applied
  //     to all sections. Individual sections may have their value changed using
  //     SetShuffleSection.
  // @param seed the seed to be used by the random number generator.
  RandomOrderer(bool default_shuffle_section, uint32_t seed);

  // Configures whether or not the given section should have its blocks
  // shuffled. This overrides the default value specified in the constructor.
  // @param section the section to configure.
  // @param shuffle true if the section should be shuffled, false otherwise.
  void SetShuffleSection(const BlockGraph::Section* section, bool shuffle);

  // Determines whether or not the blocks will be shuffled for the given
  // section.
  bool ShouldShuffleSection(const BlockGraph::Section* section) const;

  // Applies this orderer to the provided block graph.
  //
  // @param ordered_block_graph the block graph to order.
  // @param header_block The header block of the block graph to transform.
  //     This transform does not use this value, so NULL may safely be passed
  //     in.
  // @returns true on success, false otherwise.
  virtual bool OrderBlockGraph(OrderedBlockGraph* ordered_block_graph,
                               BlockGraph::Block* header_block) override;

  static const char kOrdererName[];

 private:
  // Shuffles the blocks in the given section.
  void ShuffleBlocks(const OrderedBlockGraph::OrderedSection* section,
                     OrderedBlockGraph* obg);

  // The default shuffle setting.
  bool default_shuffle_section_;
  // The random number generator we use.
  core::RandomNumberGenerator rng_;

  // A per-section shuffle setting.
  typedef std::map<const BlockGraph::Section*, bool> ShuffleMap;
  ShuffleMap shuffle_map_;

  DISALLOW_COPY_AND_ASSIGN(RandomOrderer);
};

}  // namespace orderers
}  // namespace block_graph

#endif  // SYZYGY_BLOCK_GRAPH_ORDERERS_RANDOM_ORDERER_H_
