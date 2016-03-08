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
#include "syzygy/core/address.h"
#include "syzygy/refinery/process_state/layer_traits.h"

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

ModuleLayerAccessor::ModuleLayerAccessor(ProcessState* process_state)
    : process_state_(process_state) {
  DCHECK(process_state);
}

void ModuleLayerAccessor::AddModuleRecord(const AddressRange& range,
                                          const uint32_t checksum,
                                          const uint32_t timestamp,
                                          const std::wstring& path) {
  DCHECK(range.IsValid());

  // Note: we set the preferred loading address to 0.
  pe::PEFile::Signature signature(path, core::AbsoluteAddress(0U), range.size(),
                                  checksum, timestamp);

  ModuleLayerPtr layer;
  process_state_->FindOrCreateLayer(&layer);
  ModuleId id = layer->mutable_data()->FindOrIndex(signature);

  Module* module_proto = CreateRecord<Module>(range, process_state_);
  module_proto->set_module_id(id);
}

bool ModuleLayerAccessor::GetModuleSignature(const Address va,
                                             pe::PEFile::Signature* signature) {
  DCHECK(signature);

  // Find the module record corresponding to the virtual address.
  ModuleRecordPtr module_record;
  if (!process_state_->FindSingleRecord(va, &module_record))
    return false;

  // Retrieve the signature.
  const Module& module = module_record->data();
  if (!GetModuleSignature(module.module_id(), signature))
    return false;

  // Set the signature's address.
  const AddressRange& module_range = module_record->range();
  if (!base::IsValueInRangeForNumericType<uint32_t>(module_range.start())) {
    LOG(ERROR) << "PE::Signature doesn't support 64bit addresses. Address: "
               << module_range.start();
    return false;
  }
  signature->base_address =
      core::AbsoluteAddress(base::checked_cast<uint32_t>(module_range.start()));

  return true;
}

bool ModuleLayerAccessor::GetModuleSignature(const ModuleId id,
                                             pe::PEFile::Signature* signature) {
  DCHECK_NE(kNoModuleId, id);
  DCHECK(signature);

  ModuleLayerPtr layer;
  process_state_->FindOrCreateLayer(&layer);
  return layer->data().Find(id, signature);
}

ModuleId ModuleLayerAccessor::GetModuleId(const Address va) {
  ModuleRecordPtr module_record;
  if (!process_state_->FindSingleRecord(va, &module_record))
    return kNoModuleId;
  return module_record->data().module_id();
}

ModuleId ModuleLayerAccessor::GetModuleId(
    const pe::PEFile::Signature& signature) {
  ModuleLayerPtr layer;
  process_state_->FindOrCreateLayer(&layer);
  return layer->data().Find(signature);
}

bool AddTypedBlockRecord(const AddressRange& range,
                         base::StringPiece16 data_name,
                         ModuleId module_id,
                         TypeId type_id,
                         ProcessState* process_state) {
  DCHECK(range.IsValid());
  DCHECK(process_state);

  TypedBlock* typedblock_proto = CreateRecord<TypedBlock>(range, process_state);

  std::string data_name_narrow;
  if (!base::UTF16ToUTF8(data_name.data(), data_name.size(), &data_name_narrow))
    return false;
  typedblock_proto->set_data_name(data_name_narrow);

  typedblock_proto->set_module_id(module_id);
  typedblock_proto->set_type_id(type_id);

  return true;
}

}  // namespace refinery
