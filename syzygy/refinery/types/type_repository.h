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

#ifndef SYZYGY_REFINERY_TYPES_TYPE_REPOSITORY_H_
#define SYZYGY_REFINERY_TYPES_TYPE_REPOSITORY_H_

#include <iterator>

#include "base/macros.h"
#include "base/containers/hash_tables.h"
#include "base/memory/ref_counted.h"

namespace refinery {

typedef size_t TypeId;
class Type;
using TypePtr = scoped_refptr<Type>;

// Keeps type instances, assigns them an ID and vends them out by ID on demand.
class TypeRepository {
 public:
  class Iterator;

  TypeRepository();
  ~TypeRepository();

  // Retrieve a type by @p id.
  TypePtr GetType(TypeId id);
  // Add @p type and get its assigned id.
  // @pre @p type must not be in any repository.
  TypeId AddType(TypePtr type);

  // @name Accessors.
  // @{
  size_t size() const;
  Iterator begin() const;
  Iterator end() const;
  // @}

 private:
  base::hash_map<TypeId, TypePtr> types_;

  DISALLOW_COPY_AND_ASSIGN(TypeRepository);
};

class TypeRepository::Iterator : public std::iterator<
    std::input_iterator_tag, TypePtr> {
 public:
  Iterator() {}
  const TypePtr& operator*() const { return it_->second; }
  Iterator& operator=(const Iterator& other) {
    it_ = other.it_;
    return *this;
  }
  const Iterator& operator++() {
    ++it_;
    return *this;
  }
  bool operator==(const Iterator& other) const {
    return it_ == other.it_;
  }
  bool operator!=(const Iterator& other) const {
    return it_ != other.it_;
  }

 private:
  friend TypeRepository;
  explicit Iterator(const base::hash_map<TypeId, TypePtr>::const_iterator& it)
      : it_(it) {}

  base::hash_map<TypeId, TypePtr>::const_iterator it_;
};

}  // namespace refinery

#endif  // SYZYGY_REFINERY_TYPES_TYPE_REPOSITORY_H_
