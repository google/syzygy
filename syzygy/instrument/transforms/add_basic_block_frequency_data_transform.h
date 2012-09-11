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
// Declares a block-graph transform to be used by the basic-block frequency
// tracking instrumentation to add a static BasicBlockFrequencyData object
// to the block graph.

#ifndef SYZYGY_INSTRUMENT_TRANSFORMS_ADD_BASIC_BLOCK_FREQUENCY_DATA_TRANSFORM_H_
#define SYZYGY_INSTRUMENT_TRANSFORMS_ADD_BASIC_BLOCK_FREQUENCY_DATA_TRANSFORM_H_

#include "syzygy/block_graph/transforms/named_transform.h"
#include "syzygy/core/address_space.h"

namespace instrument {
namespace transforms {

class AddBasicBlockFrequencyDataTransform
    : public block_graph::transforms::NamedBlockGraphTransformImpl<
          AddBasicBlockFrequencyDataTransform> {
 public:
  typedef block_graph::BlockGraph BlockGraph;

  // Construct a transform which adds a static basic-block frequency data
  // instance for use by @p agent_id.
  explicit AddBasicBlockFrequencyDataTransform(uint32 agent_id);

  // Return the block which holds basic-block frequency data. This will only
  // be non-NULL after a successful application of this transform.
  BlockGraph::Block* frequency_data_block() { return frequency_data_block_; }

  // BlockGraphTransformInterface Implementation.
  virtual bool TransformBlockGraph(BlockGraph* block_graph,
                                   BlockGraph::Block* header_block) OVERRIDE;

  // After applying the transform, this method can be used to allocate the
  // correct number of bytes for the default frequency data static buffer.
  // @param num_basic_blocks The number of frequency counters to allocate.
  // @param frequency_size The size (in bytes) of each frequency counter. This
  //     must be 1, 2 or 4.
  bool AllocateFrequencyDataBuffer(uint32 num_basic_blocks,
                                   uint8 frequency_size);

  // The transform name.
  static const char kTransformName[];

 protected:
  // The agent id to embed into the BasicBlockFrequencyData instance.
  uint32 agent_id_;

  // The statically allocated frequency data block that is added by the
  // transform. This becomes non-NULL after a successful application of the
  // transform.
  BlockGraph::Block* frequency_data_block_;
};

}  // transforms
}  // instrument

#endif  // SYZYGY_INSTRUMENT_TRANSFORMS_ADD_BASIC_BLOCK_FREQUENCY_DATA_TRANSFORM_H_
