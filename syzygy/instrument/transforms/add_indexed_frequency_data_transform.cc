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
// Implements the AddIndexedFrequencyDataTransform class.

#include "syzygy/instrument/transforms/add_indexed_frequency_data_transform.h"

#include "syzygy/block_graph/typed_block.h"
#include "syzygy/pe/pe_utils.h"

namespace instrument {
namespace transforms {

const char AddIndexedFrequencyDataTransform::kTransformName[] =
    "AddFrequencyDataTransform";

AddIndexedFrequencyDataTransform::AddIndexedFrequencyDataTransform(
    uint32_t agent_id,
    const base::StringPiece& freq_name,
    uint32_t version,
    IndexedFrequencyData::DataType data_type,
    size_t indexed_frequency_data_size)
    : agent_id_(agent_id),
      freq_name_(freq_name.begin(), freq_name.end()),
      version_(version),
      data_type_(data_type),
      frequency_data_block_(NULL),
      frequency_data_block_size_(indexed_frequency_data_size),
      frequency_data_buffer_block_(NULL) {
  DCHECK_LE(sizeof(IndexedFrequencyData), indexed_frequency_data_size);
}

bool AddIndexedFrequencyDataTransform::TransformBlockGraph(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {
  DCHECK(block_graph != NULL);
  DCHECK(header_block != NULL);
  DCHECK(frequency_data_block_ == NULL);
  DCHECK(data_type_ != IndexedFrequencyData::INVALID_DATA_TYPE);

  // Get the read/write ".data" section. We will add our blocks to it.
  BlockGraph::Section* section = block_graph->FindOrAddSection(
      pe::kReadWriteDataSectionName, pe::kReadWriteDataCharacteristics);
  if (section == NULL) {
    LOG(ERROR) << "Failed to find/add read-write data section \""
               << pe::kReadWriteDataSectionName << "\".";
    return false;
  }

  // Add a block for the frequency data.
  BlockGraph::Block* data_block =
      block_graph->AddBlock(BlockGraph::DATA_BLOCK,
                            frequency_data_block_size_,
                            freq_name_);
  if (data_block == NULL) {
    LOG(ERROR) << "Failed to add the " << freq_name_ << " block.";
    return false;
  }

  // Add a block for the array of frequency data. We give this block an initial
  // size of 1 because drawing a reference to an empty block is not possible.
  BlockGraph::Block* buffer_block = block_graph->AddBlock(
      BlockGraph::DATA_BLOCK, 1, freq_name_ + " Buffer");
  if (buffer_block == NULL) {
    LOG(ERROR) << "Failed to allocate frequency data buffer block.";
    return false;
  }

  // Put them both in the data section.
  data_block->set_section(section->id());
  buffer_block->set_section(section->id());

  // Allocate the data that will be used to initialize the static instance.
  // The allocated bytes will be zero-initialized.
  IndexedFrequencyData* frequency_data =
      reinterpret_cast<IndexedFrequencyData*>(
          data_block->AllocateData(data_block->size()));
  if (frequency_data == NULL) {
    LOG(ERROR) << "Failed to allocate frequency data.";
    return false;
  }
  // Initialize the non-zero fields of the structure.
  frequency_data->agent_id = agent_id_;
  frequency_data->version = version_;
  frequency_data->data_type = data_type_;

  // Setup the frequency_data pointer such that it points to the newly allocated
  // buffer.
  if (!data_block->SetReference(
          offsetof(IndexedFrequencyData, frequency_data),
          BlockGraph::Reference(BlockGraph::ABSOLUTE_REF,
                                BlockGraph::Reference::kMaximumSize,
                                buffer_block,
                                0,
                                0))) {
    LOG(ERROR) << "Failed to initialize frequency_data buffer pointer.";
    return false;
  }

  // Remember the new blocks.
  frequency_data_block_ = data_block;
  frequency_data_buffer_block_ = buffer_block;

  // And we're done.
  return true;
}

bool AddIndexedFrequencyDataTransform::ConfigureFrequencyDataBuffer(
    uint32_t num_entries,
    uint32_t num_columns,
    uint8_t frequency_size) {
  DCHECK_NE(0U, num_entries);
  DCHECK_NE(0U, num_columns);
  DCHECK(frequency_size == 1 || frequency_size == 2 || frequency_size == 4);
  DCHECK(frequency_data_block_ != NULL);
  DCHECK(frequency_data_buffer_block_ != NULL);
  DCHECK_EQ(frequency_data_block_size_,
            frequency_data_block_->data_size());

  // Update the related fields in the data structure.
  block_graph::TypedBlock<IndexedFrequencyData> frequency_data;
  CHECK(frequency_data.Init(0, frequency_data_block_));
  frequency_data->num_entries = num_entries;
  frequency_data->num_columns = num_columns;
  frequency_data->frequency_size = frequency_size;

  // Resize the buffer block.
  size_t buffer_size = num_entries * num_columns * frequency_size;
  frequency_data_buffer_block_->set_size(buffer_size);

  // And we're done.
  return true;
}

}  // namespace transforms
}  // namespace instrument
