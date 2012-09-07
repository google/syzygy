// Copyright 2012 Google Inc.
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
// Implements the AddBasicBlockFrequencyDataTransform class.

#include "syzygy/instrument/transforms/add_basic_block_frequency_data_transform.h"

#include "syzygy/block_graph/typed_block.h"
#include "syzygy/common/basic_block_frequency_data.h"

namespace instrument {
namespace transforms {

using common::BasicBlockFrequencyData;
using common::kBasicBlockFrequencySectionName;
using common::kBasicBlockFrequencySectionCharacteristics;

const char AddBasicBlockFrequencyDataTransform::kTransformName[] =
    "AddBasicBlockFrequencyDataTransform";

AddBasicBlockFrequencyDataTransform::AddBasicBlockFrequencyDataTransform(
    uint32 agent_id) : agent_id_(agent_id), frequency_data_block_(NULL) {
}

bool AddBasicBlockFrequencyDataTransform::TransformBlockGraph(
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {
  DCHECK(block_graph != NULL);
  DCHECK(header_block != NULL);
  DCHECK(frequency_data_block_ == NULL);

  // We only allow this transformation to be performed once.
  // TODO(chrisha): Remove/rework the section handling once the parameterized
  //     entry-thunk is in use. Once the frequency data is passed as a param
  //     it doesn't matter where it lives in the image and this can be changed
  //     to FindOrAddSection.
  BlockGraph::Section* section =
      block_graph->FindSection(kBasicBlockFrequencySectionName);
  if (section != NULL) {
    LOG(ERROR) << "Block-graph already contains a frequency data section "
               << "(" << kBasicBlockFrequencySectionName << ").";
    return false;
  }

  // Add a new section for the frequency data.
  section = block_graph->AddSection(kBasicBlockFrequencySectionName,
                                    kBasicBlockFrequencySectionCharacteristics);
  if (section == NULL) {
    LOG(ERROR) << "Failed to add the basic-block frequency section.";
    return false;
  }

  // Add a block for the basic-block frequency data.
  BlockGraph::Block* block =
      block_graph->AddBlock(BlockGraph::DATA_BLOCK,
                            sizeof(BasicBlockFrequencyData),
                            "Basic-Block Frequency Data");
  if (block == NULL) {
    LOG(ERROR) << "Failed to add the basic-block frequency data block.";
    return false;
  }

  block->set_section(section->id());

  // Allocate the data that will be used to initialize the static instance.
  // The allocated bytes will be zero-initialized.
  BasicBlockFrequencyData* frequency_data =
      reinterpret_cast<BasicBlockFrequencyData*>(
          block->AllocateData(block->size()));
  if (frequency_data == NULL) {
    LOG(ERROR) << "Failed to allocate frequency data.";
    return false;
  }

  // Initialize the non-zero fields of the structure.
  frequency_data->agent_id = agent_id_;
  frequency_data->version = common::kBasicBlockFrequencyDataVersion;
  frequency_data->tls_index = TLS_OUT_OF_INDEXES;

  // Setup the frequency_data pointer such that it points to the next byte
  // after the BasicBlockFrequencyData structure. This allows the frequency
  // data block to simply be resized to accommodate the data buffer and the
  // pointer will already be setup.
  if (!block->SetReference(
          offsetof(BasicBlockFrequencyData, frequency_data),
                   BlockGraph::Reference(BlockGraph::ABSOLUTE_REF,
                                         BlockGraph::Reference::kMaximumSize,
                                         block,
                                         sizeof(BasicBlockFrequencyData),
                                         0))) {
    LOG(ERROR) << "Failed to initialize frequency_data buffer pointer.";
    return false;
  }

  // Remember the new block.
  frequency_data_block_ = block;

  // And we're done.
  return true;
}

bool AddBasicBlockFrequencyDataTransform::AllocateFrequencyDataBuffer(
    uint32 num_basic_blocks, uint8 frequency_size) {
  DCHECK_NE(0U, num_basic_blocks);
  DCHECK(frequency_size == 1 || frequency_size == 2 || frequency_size == 4);
  DCHECK(frequency_data_block_ != NULL);
  DCHECK_EQ(sizeof(BasicBlockFrequencyData),
            frequency_data_block_->data_size());

  // Resize the (virtual part of) the block to accommodate the data buffer.
  size_t buffer_size = num_basic_blocks * frequency_size;
  size_t total_size = sizeof(BasicBlockFrequencyData) + buffer_size;
  frequency_data_block_->set_size(total_size);

  // Update the related fields in the data structure.
  block_graph::TypedBlock<BasicBlockFrequencyData> frequency_data;
  frequency_data.Init(0, frequency_data_block_);
  frequency_data->num_basic_blocks = num_basic_blocks;
  frequency_data->frequency_size = frequency_size;

  // And we're done.
  return true;
}

}   // transforms
}  // instrument
