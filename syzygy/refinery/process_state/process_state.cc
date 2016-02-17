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

#include "syzygy/refinery/process_state/process_state.h"

#include <algorithm>

#include "syzygy/refinery/core/addressed_data.h"
#include "syzygy/refinery/process_state/process_state_util.h"

namespace refinery {

ProcessState::ProcessState() : has_exception(false), excepting_thread_id(0U) {
}

ProcessState::~ProcessState() {
}

const char* ProcessState::LayerName(LayerEnum layer) {
  switch (layer) {
#define LAYER_NAME_CASE(name) \
  case name##Layer:           \
    return #name;

    PROCESS_STATE_LAYERS(LAYER_NAME_CASE)

#undef LAYER_NAME_CASE
    default:
      return nullptr;
  }
}

ProcessState::LayerEnum ProcessState::LayerFromName(
    const base::StringPiece& layer_name) {
#define LAYER_FROM_NAME(name)      \
  if (layer_name == #name "Layer") \
    return name##Layer;
  PROCESS_STATE_LAYERS(LAYER_FROM_NAME)

#undef LAYER_FROM_NAME

  return UnknownLayer;
}

bool ProcessState::FindStackRecord(
    size_t thread_id,
    scoped_refptr<Record<Stack>>* record) {
  StackLayerPtr stack_layer;
  if (!FindLayer(&stack_layer))
    return false;

  for (StackRecordPtr stack : *stack_layer) {
    const Stack& stack_proto = stack->data();
    DCHECK(stack_proto.has_thread_info());
    DCHECK(stack_proto.thread_info().has_thread_id());
    if (stack_proto.thread_info().thread_id() == thread_id) {
      *record = stack;
      return true;
    }
  }

  return false;
}

bool ProcessState::GetAll(const AddressRange& range, void* data_ptr) {
  DCHECK(range.IsValid());

  // Get the bytes layer.
  BytesLayerPtr bytes_layer;
  if (!FindLayer(&bytes_layer))
    return false;

  // Search for a single record that spans the desired range.
  std::vector<BytesRecordPtr> matching_records;
  bytes_layer->GetRecordsSpanning(range, &matching_records);
  if (matching_records.empty())
    return false;
  DCHECK_EQ(1U, matching_records.size());

  // Copy the bytes.
  BytesRecordPtr bytes_record = matching_records[0];
  AddressedData record_data(
      bytes_record->range(),
      reinterpret_cast<const void*>(bytes_record->data().data().c_str()));

  return record_data.GetAt(range, data_ptr);
}

bool ProcessState::GetFrom(const AddressRange& range,
                           size_t* data_cnt,
                           void* data_ptr) {
  DCHECK(range.IsValid());

  // Find the single record that contains the head of the range.
  BytesRecordPtr record;
  if (!FindSingleRecord(range.start(), &record))
    return false;

  // Determine the range that can be served.
  Address available_end = std::min(range.end(), record->range().end());
  AddressRange available_range(range.start(), available_end - range.start());
  DCHECK(available_range.IsValid());

  // Serve request.
  *data_cnt = available_range.size();
  if (data_ptr == nullptr)
    return true;  // Actual bytes not requested.

  AddressedData record_data(
      record->range(),
      reinterpret_cast<const void*>(record->data().data().c_str()));
  if (!record_data.GetAt(available_range, reinterpret_cast<void*>(data_ptr)))
    return false;

  return true;
}

bool ProcessState::HasSome(const AddressRange& range) {
  // TODO(manzagop): implement.
  return false;
}

bool ProcessState::SetException(const Exception& candidate) {
  DCHECK(candidate.has_thread_id());

  if (has_exception)
    return false;  // There's already an exception.

  StackRecordPtr stack_record;
  if (!FindStackRecord(candidate.thread_id(), &stack_record))
    return false;  // Thread isn't in the process state.

  DCHECK(stack_record->mutable_data());
  ThreadInformation* thread_info =
      stack_record->mutable_data()->mutable_thread_info();
  DCHECK(!thread_info->has_exception());
  Exception* exception = thread_info->mutable_exception();
  *exception = candidate;

  has_exception = true;
  excepting_thread_id = exception->thread_id();

  return true;
}

bool ProcessState::GetExceptingThreadId(size_t* thread_id) {
  if (!has_exception)
    return false;

  *thread_id = excepting_thread_id;
  return true;
}

}  // namespace refinery
