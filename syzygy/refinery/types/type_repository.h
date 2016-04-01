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
#include <map>
#include <vector>

#include "base/macros.h"
#include "base/containers/hash_tables.h"
#include "base/memory/ref_counted.h"
#include "syzygy/pe/pe_file.h"

namespace refinery {

typedef size_t TypeId;
class Type;
using TypePtr = scoped_refptr<Type>;

// Keeps type instances, assigns them an ID and vends them out by ID on demand.
// TODO(manzagop): cleave the interface so as to obtain something immutable.
// TODO(manzagop): abstract the module id away from a pe file signature.
class TypeRepository : public base::RefCounted<TypeRepository> {
 public:
  class Iterator;

  // TODO(manzagop): make it mandatory to provide a module signature.
  TypeRepository();
  explicit TypeRepository(const pe::PEFile::Signature& signature);

  // Retrieve a type by @p id.
  TypePtr GetType(TypeId id) const;

  // Add @p type and get its assigned id.
  // @pre @p type must not be in any repository.
  TypeId AddType(TypePtr type);

  // Add @p type and with @p id if the give id is free.
  // @pre @p type must not be in any repository and @p id must be free.
  // @returns true on success, failure typically means id is already taken.
  bool AddTypeWithId(TypePtr type, TypeId id);


  // Get the signature for the module this type represents.
  bool GetModuleSignature(pe::PEFile::Signature* signature);

  // @name Accessors.
  // @{
  size_t size() const;
  Iterator begin() const;
  Iterator end() const;
  // @}

 private:
  friend class base::RefCounted<TypeRepository>;
  ~TypeRepository();

  bool is_signature_set_;
  pe::PEFile::Signature signature_;
  std::unordered_map<TypeId, TypePtr> types_;

  DISALLOW_COPY_AND_ASSIGN(TypeRepository);
};

class TypeRepository::Iterator
    : public std::iterator<std::input_iterator_tag, TypePtr> {
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
  bool operator==(const Iterator& other) const { return it_ == other.it_; }
  bool operator!=(const Iterator& other) const { return it_ != other.it_; }

 private:
  friend TypeRepository;
  explicit Iterator(
      const std::unordered_map<TypeId, TypePtr>::const_iterator& it)
      : it_(it) {}

  std::unordered_map<TypeId, TypePtr>::const_iterator it_;
};

// The TypeNameIndex provides name-based indexing for types.
// @note The underlying TypeRepository should not be modified.
// @note Name-based indexing, as well as support for name collisions (using a
//     multimap) are necessary as long as we rely on DIA. DIA does not expose
//     mangled names (at least not the fully mangled names?) nor the PDB ids
//     (DIA ids are not stable as they're based on the parse order).
// TODO(manzagop): relocate to where this is used once it exists.
// TODO(manzagop): remove once DIA is no-longer used.
class TypeNameIndex : public base::RefCounted<TypeNameIndex> {
 public:
  explicit TypeNameIndex(scoped_refptr<TypeRepository> repository);

  // Retrieve matching @p types by @p name.
  void GetTypes(const base::string16& name, std::vector<TypePtr>* types) const;

 private:
  friend class base::RefCounted<TypeNameIndex>;
  ~TypeNameIndex();

  std::multimap<base::string16, TypePtr> name_index_;
};

}  // namespace refinery

#endif  // SYZYGY_REFINERY_TYPES_TYPE_REPOSITORY_H_
