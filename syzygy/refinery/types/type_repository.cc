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

#include "syzygy/refinery/types/type_repository.h"

#include "base/logging.h"
#include "syzygy/refinery/types/type.h"

namespace refinery {

TypeRepository::TypeRepository() : is_signature_set_(false) {
}

TypeRepository::TypeRepository(const pe::PEFile::Signature& signature)
    : is_signature_set_(true), signature_(signature) {
}

TypeRepository::~TypeRepository() {
}

TypePtr TypeRepository::GetType(TypeId id) const {
  auto it = types_.find(id);
  if (it == types_.end())
    return nullptr;
  return it->second;
}

TypeId TypeRepository::AddType(TypePtr type) {
  DCHECK(type);
  TypeId id = types_.size() + 1;

  bool result = AddTypeWithId(type, id);

  // Check that the adding was successful.
  DCHECK(result);

  return id;
}

bool TypeRepository::AddTypeWithId(TypePtr type, TypeId id) {
  DCHECK(type);

  // Check that the ID is unassigned.
  if (types_.find(id) != types_.end())
    return false;

  type->SetRepository(this, id);
  types_[id] = type;

  return true;
}

bool TypeRepository::GetModuleSignature(pe::PEFile::Signature* signature) {
  DCHECK(signature);

  if (!is_signature_set_)
    return false;
  *signature = signature_;
  return true;
}

size_t TypeRepository::size() const {
  return types_.size();
}

TypeRepository::Iterator TypeRepository::begin() const {
  return Iterator(types_.begin());
}

TypeRepository::Iterator TypeRepository::end() const {
  return Iterator(types_.end());
}

TypeNameIndex::TypeNameIndex(scoped_refptr<TypeRepository> repository) {
  DCHECK(repository);
  for (auto type : *repository)
    name_index_.insert(std::make_pair(type->GetName(), type));
}

TypeNameIndex::~TypeNameIndex() {
}

void TypeNameIndex::GetTypes(const base::string16& name,
                             std::vector<TypePtr>* types) const {
  DCHECK(types);
  types->clear();

  auto match = name_index_.equal_range(name);
  for (auto it = match.first; it != match.second; ++it)
    types->push_back(it->second);
}

}  // namespace refinery
