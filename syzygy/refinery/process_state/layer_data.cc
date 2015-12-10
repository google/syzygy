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

#include "syzygy/refinery/process_state/layer_data.h"

namespace refinery {

std::size_t PESignatureHasher::operator()(
    pe::PEFile::Signature const& s) const {
  base::MD5Context ctx;
  base::MD5Init(&ctx);

  uint32_t base_address = s.base_address.value();
  base::MD5Update(
      &ctx, base::StringPiece(reinterpret_cast<const char*>(s.path.data()),
                              s.path.size() * sizeof(wchar_t)));
  base::MD5Update(
      &ctx, base::StringPiece(reinterpret_cast<const char*>(&base_address),
                              sizeof(base_address)));
  base::MD5Update(
      &ctx, base::StringPiece(reinterpret_cast<const char*>(&s.module_size),
                              sizeof(s.module_size)));
  base::MD5Update(
      &ctx, base::StringPiece(reinterpret_cast<const char*>(&s.module_checksum),
                              sizeof(s.module_checksum)));
  base::MD5Update(&ctx, base::StringPiece(reinterpret_cast<const char*>(
                                              &s.module_time_date_stamp),
                                          sizeof(s.module_time_date_stamp)));
  base::MD5Digest digest;
  base::MD5Final(&digest, &ctx);

  // Note: only using the first bytes of the digest.
  return *reinterpret_cast<size_t*>(&digest);
}

ModuleLayerData::ModuleLayerData() {
}

ModuleId ModuleLayerData::Find(const pe::PEFile::Signature& signature) const {
  auto it = signature_to_id_.find(signature);
  if (it != signature_to_id_.end())
    return it->second;
  return kNoModuleId;
}

ModuleId ModuleLayerData::FindOrIndex(const pe::PEFile::Signature& signature) {
  ModuleId id = Find(signature);
  if (id != kNoModuleId)
    return id;

  id = signature_to_id_.size();

  signature_to_id_[signature] = id;
  signatures_.push_back(signature);

  return id;
}

bool ModuleLayerData::Find(ModuleId id,
                           pe::PEFile::Signature* signature) const {
  if (id >= signatures_.size())
    return false;

  *signature = signatures_[id];
  return true;
}

}  // namespace refinery
