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

TypeRepository::TypeRepository() {
}

TypeRepository::~TypeRepository() {
}

TypePtr TypeRepository::GetType(TypeId id) {
  auto it = types_.find(id);
  if (it == types_.end())
    return nullptr;
  return it->second;
}

TypeId TypeRepository::AddType(TypePtr type) {
  DCHECK(type);
  TypeId id = types_.size() + 1;

  // Check that the ID is unassigned.
  DCHECK(types_.find(id) == types_.end());

  type->SetRepository(this, id);
  types_[id] = type;

  return id;
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

}  // namespace refinery
