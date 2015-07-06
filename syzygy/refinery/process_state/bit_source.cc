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

#include "syzygy/refinery/process_state/bit_source.h"

#include <vector>

#include "syzygy/refinery/core/addressed_data.h"
#include "syzygy/refinery/process_state/process_state.h"
#include "syzygy/refinery/process_state/process_state_util.h"

namespace refinery {

BitSource::BitSource(ProcessState* process_state)
    : process_state_(process_state) {
}

BitSource::~BitSource() {
}

bool BitSource::GetAll(const AddressRange& range, void* data_ptr) {
  DCHECK(range.IsValid());

  // Get the bytes layer.
  BytesLayerPtr bytes_layer;
  if (!process_state_->FindLayer(&bytes_layer))
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

// TODO(manzagop): implement.
// bool BitSource::GetFrom(const AddressRange& range,
//                         size_t* data_cnt,
//                         void* data_ptr) {
//   return false;
// }

// TODO(manzagop): implement.
// bool BitSource::HasSome(const AddressRange& range) {
//   return false;
// }

}  // namespace refinery
