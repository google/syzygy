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

#ifndef SYZYGY_REFINERY_TYPES_TYPE_H_
#define SYZYGY_REFINERY_TYPES_TYPE_H_

#include <stdint.h>
#include <functional>
#include <vector>

#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/strings/string16.h"

namespace refinery {

// A base class for all Type subclasses.
// All instances of Type and subclasses are immutable.
class Type : public base::RefCounted<Type> {
 public:
  typedef uint8_t Flags;

  // The set of type classes is closed, each type is enumerated here.
  enum TypeKind {
    BasicKind,
    BitfieldKind,
    UserDefinedKind,
    PointerKind,
  };

  enum CV {
    FLAG_CONST        = 0x0001,
    FLAG_VOLATILE     = 0x0002,
  };

  // @name Accessors
  // @{
  const base::string16& name() const { return name_; }
  size_t size() const { return size_; }
  TypeKind kind() const { return kind_; }
  // @}

  // Safely down-cast this to @p SubType.
  // @param out the subtype to cast this to.
  // @returns true on success, false on failure.
  template <class SubType>
  bool CastTo(scoped_refptr<SubType>* out);

 protected:
  friend class base::RefCounted<Type>;
  Type(TypeKind kind, const base::string16& name, size_t size);
  virtual ~Type() = 0;

 private:
  // The kind of this type is, synonymous with its class.
  const TypeKind kind_;
  // Name of type.
  const base::string16 name_;
  // Size of type.
  const size_t size_;

  DISALLOW_COPY_AND_ASSIGN(Type);
};

using TypePtr = scoped_refptr<Type>;

// A hash functor for types.
struct TypeHash : public std::unary_function<Type, size_t> {
  size_t operator()(const TypePtr& type);
};

// An equality comparator for types.
struct TypeIsEqual : public std::binary_function<Type, Type, bool> {
  bool operator()(const TypePtr& a, const TypePtr& b);
};

// Represents a basic type, such as e.g. an int, char, void, etc.
class BasicType : public Type {
 public:
  static const TypeKind ID = BasicKind;

  // Creates a new basictype with name @p name and size @p size.
  BasicType(const base::string16& name, size_t size);

 private:
  DISALLOW_COPY_AND_ASSIGN(BasicType);
};

using BasicTypePtr = scoped_refptr<BasicType>;

// Represents a bitfield.
class BitfieldType : public Type {
 public:
  static const TypeKind ID = BitfieldKind;

  // Creates a new bitfield.
  BitfieldType(const base::string16& name,
               size_t size,
               size_t bit_length,
               size_t bit_offset);

  // @name Accessors.
  // @{
  size_t bit_length() const { return bit_length_; }
  size_t bit_offset() const { return bit_offset_; }
  // @}

 private:
  const size_t bit_length_;
  const size_t bit_offset_;

  DISALLOW_COPY_AND_ASSIGN(BitfieldType);
};

using BitfieldTypePtr = scoped_refptr<BitfieldType>;

// Represents a user defined type such as a struct, union or a class.
class UserDefinedType : public Type {
 public:
  class Field;
  typedef std::vector<Field> Fields;

  static const TypeKind ID = UserDefinedKind;

  // Creates a new user defined type with name @p name, size @p size and
  // the supplied @p fields.
  UserDefinedType(const base::string16& name,
                  size_t size,
                  const Fields& fields);

  // Accessor.
  const Fields& fields() const { return fields_; }

 private:
  const Fields fields_;

  DISALLOW_COPY_AND_ASSIGN(UserDefinedType);
};

using UserDefinedTypePtr = scoped_refptr<UserDefinedType>;

// Represents a field in a user defined type.
class UserDefinedType::Field {
 public:
  // TODO(siggi): How to represent VTables/Interfaces?

  // Creates a new field.
  // @param name the name of the field.
  // @param offset the byte offset of the field within the UDT.
  //    Note that many bitfield fields can share the same offset within a UDT,
  //    as can fields in a union.
  // @param size the byte size of the field.
  // @param flags any combination of Flags, denoting properties of the field.
  // @param type the type of the field.
  // TODO(siggi): Maybe the size of the type is sufficient?
  Field(const base::string16& name,
        ptrdiff_t offset,
        Flags flags,
        const TypePtr& type);

  // @name Accessors.
  // @{
  const base::string16& name() const { return name_; }
  ptrdiff_t offset() const { return offset_; }
  const TypePtr& type() const { return type_; }

  bool is_const() const { return (flags_ & FLAG_CONST) != 0; }
  bool is_volatile() const { return (flags_ & FLAG_VOLATILE) != 0; }
  // @}

 private:
  const base::string16 name_;
  const ptrdiff_t offset_;
  const Flags flags_;
  const TypePtr type_;
};

// Represents a pointer to some other type.
class PointerType : public Type {
 public:
  static const TypeKind ID = PointerKind;

  // Creates a new pointer type with name @p name, size @p size, pointing to
  // an object of type @p type.
  PointerType(const base::string16& name,
              size_t size,
              Flags flags,
              const TypePtr& type);

  // Accessors.
  // @{
  TypePtr type() const { return type_; }
  bool is_const() const { return (flags_ & FLAG_CONST) != 0; }
  bool is_volatile() const { return (flags_ & FLAG_VOLATILE) != 0; }
  // @}

 private:
  // Stores the CV qualifiers of this pointer.
  const Flags flags_;
  const TypePtr type_;
};

using PointerTypePtr = scoped_refptr<PointerType>;

template <class SubType>
bool Type::CastTo(scoped_refptr<SubType>* out) {
  DCHECK(out);
  if (SubType::ID != kind()) {
    *out = nullptr;
    return false;
  }

  *out = static_cast<SubType*>(this);
  return true;
}

}  // namespace refinery

#endif  // SYZYGY_REFINERY_TYPES_TYPE_H_
