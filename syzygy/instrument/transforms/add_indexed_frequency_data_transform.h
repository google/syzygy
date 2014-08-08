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
// Declares a block-graph transform to be used by the indexed frequency
// tracking instrumentation to add a static IndexedFrequencyData object to the
// block graph.

#ifndef SYZYGY_INSTRUMENT_TRANSFORMS_ADD_INDEXED_FREQUENCY_DATA_TRANSFORM_H_
#define SYZYGY_INSTRUMENT_TRANSFORMS_ADD_INDEXED_FREQUENCY_DATA_TRANSFORM_H_

#include "base/strings/string_piece.h"
#include "syzygy/block_graph/transforms/named_transform.h"
#include "syzygy/common/indexed_frequency_data.h"
#include "syzygy/core/address_space.h"

namespace instrument {
namespace transforms {

class AddIndexedFrequencyDataTransform
    : public block_graph::transforms::NamedBlockGraphTransformImpl<
          AddIndexedFrequencyDataTransform> {
 public:
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::TransformPolicyInterface TransformPolicyInterface;
  typedef common::IndexedFrequencyData IndexedFrequencyData;

  // Construct a transform which adds a static frequency data instance.
  // @param agent_id The agent that'll use those data.
  // @param freq_name The name of the frequency data block.
  // @param version The version of the data structure used to store the data.
  // @param indexed_frequency_data_size The size of the indexed_frequency_data
  //     structure or extended version. Instrumenters may add fields after the
  //     common part of the indexed_frequency_data structure.
  AddIndexedFrequencyDataTransform(uint32 agent_id,
                                   const base::StringPiece& freq_name,
                                   uint32 version,
                                   IndexedFrequencyData::DataType data_type,
                                   size_t indexed_frequency_data_size);

  // Return the block which holds the frequency data. This will only be non-NULL
  // after a successful application of this transform.
  BlockGraph::Block* frequency_data_block() { return frequency_data_block_; }

  // Returns the block which holds the frequency data buffer. This will only
  // be non-NULL after a successful application of this transform.
  BlockGraph::Block* frequency_data_buffer_block() {
    return frequency_data_buffer_block_;
  }

  // BlockGraphTransformInterface Implementation.
  virtual bool TransformBlockGraph(const TransformPolicyInterface* policy,
                                   BlockGraph* block_graph,
                                   BlockGraph::Block* header_block) OVERRIDE;

  // After applying the transform, this method can be used to allocate the
  // correct number of bytes for the default frequency data static buffer.
  // @param num_entries The number of frequency counters to allocate.
  // @param frequency_size The size (in bytes) of each frequency counter. This
  //     must be 1, 2 or 4.
  bool ConfigureFrequencyDataBuffer(uint32 num_entries,
                                    uint32 num_columns,
                                    uint8 frequency_size);

  // The transform name.
  static const char kTransformName[];

 protected:
  // The agent id to embed into the IndexFrequencyData instance.
  uint32 agent_id_;

  // The statically allocated frequency data block that is added by the
  // transform. This becomes non-NULL after a successful application of the
  // transform.
  BlockGraph::Block* frequency_data_block_;

  // The size of the statically allocated block.
  size_t frequency_data_block_size_;

  // The statically allocated frequency data buffer block that is added by the
  // transform. This becomes non-NULL after a successful application of the
  // transform. This is allocated as a separate block because it is
  // uninitialized and may be written to the image for free.
  BlockGraph::Block* frequency_data_buffer_block_;

  // Name of the frequency data block.
  std::string freq_name_;

  // Version of the data structure.
  uint32 version_;

  // The type of the data in the IndexFrequencyData instance.
  IndexedFrequencyData::DataType data_type_;
};

}  // namespace transforms
}  // namespace instrument

#endif  // SYZYGY_INSTRUMENT_TRANSFORMS_ADD_INDEXED_FREQUENCY_DATA_TRANSFORM_H_
