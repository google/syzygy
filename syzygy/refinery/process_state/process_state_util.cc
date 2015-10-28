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

#include "syzygy/refinery/process_state/process_state_util.h"

#include "base/strings/utf_string_conversions.h"

namespace refinery {

namespace {

template <typename RecordType>
RecordType* CreateRecord(const AddressRange& range,
                         ProcessState* process_state) {
  DCHECK(range.IsValid());
  DCHECK(process_state);

  scoped_refptr<ProcessState::Layer<RecordType>> layer;
  process_state->FindOrCreateLayer(&layer);

  ProcessState::Layer<RecordType>::RecordPtr record;
  layer->CreateRecord(range, &record);

  return record->mutable_data();
}

}  // namespace

void AddModuleRecord(const AddressRange& range,
                     const uint32 checksum,
                     const uint32 timestamp,
                     const std::string& path,
                     ProcessState* process_state) {
  DCHECK(range.IsValid());
  DCHECK(process_state);

  Module* module_proto = CreateRecord<Module>(range, process_state);
  module_proto->set_checksum(checksum);
  module_proto->set_timestamp(timestamp);
  module_proto->set_name(path);
}

bool AddTypedBlockRecord(const AddressRange& range,
                         base::StringPiece16 data_name,
                         base::StringPiece16 type_name,
                         ProcessState* process_state) {
  DCHECK(range.IsValid());
  DCHECK(process_state);

  TypedBlock* typedblock_proto = CreateRecord<TypedBlock>(range, process_state);

  std::string data_name_narrow;
  if (!base::UTF16ToUTF8(data_name.data(), data_name.size(), &data_name_narrow))
    return false;
  typedblock_proto->set_data_name(data_name_narrow);

  std::string type_name_narrow;
  if (!base::UTF16ToUTF8(type_name.data(), type_name.size(), &type_name_narrow))
    return false;
  typedblock_proto->set_type_name(type_name_narrow);

  return true;
}

}  // namespace refinery
