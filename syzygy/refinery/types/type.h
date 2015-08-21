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

// fwd.
class TypeRepository;
typedef size_t TypeId;

// A sentinel value for uninitialized types.
const TypeId kNoTypeId = static_cast<TypeId>(-1);

// A base class for all Type subclasses. Types are owned by a type repository,
// which can vend out type instances by ID on demand.
class Type : public base::RefCounted<Type> {
 public:
  typedef uint8_t Flags;

  // The set of type classes is closed, each type is enumerated here.
  enum TypeKind {
    BASIC_TYPE_KIND,
    USER_DEFINED_TYPE_KIND,
    POINTER_TYPE_KIND,
    ARRAY_TYPE_KIND,
    FUNCTION_TYPE_KIND,
    WILDCARD_TYPE_KIND,
  };

  enum CV_FLAGS {
    FLAG_CONST        = 0x0001,
    FLAG_VOLATILE     = 0x0002,
  };

  // @name Accessors
  // @{
  TypeRepository* repository() const { return repository_; }
  TypeId type_id() const { return type_id_; }
  const base::string16& name() const { return name_; }
  const base::string16& decorated_name() const { return decorated_name_; }
  size_t size() const { return size_; }
  TypeKind kind() const { return kind_; }
  // @}

  // Safely down-cast this to @p SubType.
  // @param out the subtype to cast this to.
  // @returns true on success, false on failure.
  template <class SubType>
  bool CastTo(scoped_refptr<SubType>* out);

  // Set the name of the type.
  void SetName(const base::string16& name);

  // Set the decorated name of the type.
  void SetDecoratedName(const base::string16& decorated_name);

 protected:
  friend class base::RefCounted<Type>;

  // This constructor will eventually be removed.
  Type(TypeKind kind, const base::string16& name, size_t size);
  // This is the way to go.
  Type(TypeKind kind,
       const base::string16& name,
       const base::string16& decorated_name,
       size_t size);
  virtual ~Type() = 0;

 private:
  friend class TypeRepository;
  void SetRepository(TypeRepository* repository, TypeId type_id);

  // The type repository this type belongs to and its ID in the repository.
  TypeRepository* repository_;
  TypeId type_id_;

  // The kind of this type is, synonymous with its class.
  const TypeKind kind_;
  // Size of type.
  const size_t size_;
  // Name of type.
  base::string16 name_;
  // Decorated name of type.
  base::string16 decorated_name_;

  DISALLOW_COPY_AND_ASSIGN(Type);
};

using TypePtr = scoped_refptr<Type>;

// Constant for no type flags.
const Type::Flags kNoTypeFlags = 0x0000;

// Represents a basic type, such as e.g. an int, char, void, etc.
class BasicType : public Type {
 public:
  static const TypeKind ID = BASIC_TYPE_KIND;

  // Creates a new basictype with name @p name and size @p size.
  // Sets decorated_name equal to name as basic types have no decorated names.
  BasicType(const base::string16& name, size_t size);

 private:
  DISALLOW_COPY_AND_ASSIGN(BasicType);
};

using BasicTypePtr = scoped_refptr<BasicType>;

// Represents a user defined type such as a struct, union or a class.
class UserDefinedType : public Type {
 public:
  class Field;
  typedef std::vector<Field> Fields;

  static const TypeKind ID = USER_DEFINED_TYPE_KIND;

  // Creates a new user defined type with name @p name, size @p size.
  // This creates an un-finalized UDT with no fields.
  // This will eventually be deleted.
  UserDefinedType(const base::string16& name, size_t size);

  // Creates a new user defined type with name @p name, decorated name @p
  // decorated_name and size @p size.
  // This creates an un-finalized UDT with no fields.
  UserDefinedType(const base::string16& name,
                  const base::string16& decorated_name,
                  size_t size);

  // Retrieves the type associated with field @p field_no.
  // @pre field_no < fields().size().
  // @pre SetRepository has been called.
  TypePtr GetFieldType(size_t field_no) const;

  // Accessor.
  const Fields& fields() const { return fields_; }

  // Finalize the type by providing it with a field list.
  // @param fields the fields for the type.
  // @note this can only be called once per type instance.
  void Finalize(const Fields& fields);

 private:
  Fields fields_;

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
  // @param flags any combination of Flags, denoting properties of the field.
  // @param bit_pos if this field is a bitfield, this is the bit position.
  // @param bit_len if this field is a bitfield, this is the bit length.
  // @param type_id the type ID of the field.
  // @note bit_pos and bit_len must be in the range 0..63.
  // @note When bit_len is zero it signifies that the field is not a bitfield.
  Field(const base::string16& name,
        ptrdiff_t offset,
        Flags flags,
        size_t bit_pos,
        size_t bit_len,
        TypeId type_id);

  // @name Accessors.
  // @{
  const base::string16& name() const { return name_; }
  ptrdiff_t offset() const { return offset_; }
  TypeId type_id() const { return type_id_; }
  size_t bit_pos() const { return bit_pos_; }
  size_t bit_len() const { return bit_len_; }
  bool is_const() const { return (flags_ & FLAG_CONST) != 0; }
  bool is_volatile() const { return (flags_ & FLAG_VOLATILE) != 0; }
  // @}

  bool operator==(const Field& o) const;

 private:
  const base::string16 name_;
  const ptrdiff_t offset_;
  const Flags flags_;
  const size_t bit_pos_ : 6;
  const size_t bit_len_ : 6;
  const TypeId type_id_;
};

// Represents a pointer to some other type.
class PointerType : public Type {
 public:
  static const TypeKind ID = POINTER_TYPE_KIND;

  // Enum describing two pointer modes - regular pointer or reference.
  enum Mode {
    PTR_MODE_PTR = 0x00,
    PTR_MODE_REF = 0x01,
  };

  // Creates a new (non-finalized) pointer type with size @p size and value @p
  // ptr_mode which determines whether this is actually pointer or reference.
  explicit PointerType(size_t size, Mode ptr_mode);

  // Accessors.
  // @{
  TypeId content_type_id() const { return content_type_id_; }
  bool is_const() const { return (flags_ & FLAG_CONST) != 0; }
  bool is_volatile() const { return (flags_ & FLAG_VOLATILE) != 0; }
  Mode ptr_mode() const { return ptr_mode_; }
  // @}

  // Retrieves the type this pointer refers to.
  // @pre SetRepository has been called.
  TypePtr GetContentType() const;

  // Finalize the pointer type with @p flags and @p content_type_id.
  void Finalize(Flags flags, TypeId content_type_id);

 private:
  // Stores the CV qualifiers of the pointee.
  Flags flags_;
  // Stores the type this pointer points to.
  TypeId content_type_id_;

  // Determines whether this is a reference or an actual pointer.
  Mode ptr_mode_;
};

using PointerTypePtr = scoped_refptr<PointerType>;

// Represents an array of some other type.
class ArrayType : public Type {
 public:
  static const TypeKind ID = ARRAY_TYPE_KIND;

  explicit ArrayType(size_t size);

  // Accessors.
  // @{
  TypeId index_type_id() const { return index_type_id_; }
  size_t num_elements() const { return num_elements_; }
  TypeId element_type_id() const { return element_type_id_; }

  bool is_const() const { return (flags_ & FLAG_CONST) != 0; }
  bool is_volatile() const { return (flags_ & FLAG_VOLATILE) != 0; }
  // @}

  // @name Retrieve the index/element types.
  // @pre SetRepository has been called.
  // @{
  TypePtr GetIndexType() const;
  TypePtr GetElementType() const;
  // @}

  // Finalize the array type.
  void Finalize(Flags flags,
                TypeId index_type_id,
                size_t num_elements,
                TypeId element_type_id);

 private:
  // The CV qualifiers for the elements.
  Flags flags_;

  // The type ID for the the index type.
  TypeId index_type_id_;

  // The number of elements in this array.
  size_t num_elements_;

  // The type ID for the element type.
  TypeId element_type_id_;
};

using ArrayTypePtr = scoped_refptr<ArrayType>;

// Represents a function type.
class FunctionType : public Type {
 public:
  class ArgumentType {
   public:
    // Creates a new argument.
    // @param flags any combination of Flags, denoting properties of the
    // argument.
    // @param type_id the type ID of the argument.
    ArgumentType(Flags flags, TypeId type_id);

    // Default assignment operator.
    ArgumentType& operator=(const ArgumentType&) = default;

    // @name Accessors.
    // @{
    TypeId type_id() const { return type_id_; }
    bool is_const() const { return (flags_ & FLAG_CONST) != 0; }
    bool is_volatile() const { return (flags_ & FLAG_VOLATILE) != 0; }
    // @}

    bool operator==(const ArgumentType& other) const;

   private:
    Flags flags_;
    TypeId type_id_;
  };

  typedef std::vector<ArgumentType> Arguments;
  enum CallConvention;

  static const TypeKind ID = FUNCTION_TYPE_KIND;

  // Creates a new (non-finalized) function type.
  // @param call_convention calling convention of this function.
  // @param containing_class_id type index of the containing class.
  explicit FunctionType(CallConvention call_convention,
                        TypeId containing_class_id);

  // Retrieves the type associated with argument @p arg_no.
  // @pre arg_no < arguments().size().
  // @pre SetRepository has been called.
  TypePtr GetArgumentType(size_t arg_no) const;

  // Retrieves the type associated with the return value.
  // @pre SetRepository has been called.
  TypePtr GetReturnType() const;

  // Retrieves the type associated with the containing class.
  // @pre containing_class_ != kNoTypeId
  // @pre SetRepository has been called.
  TypePtr GetContainingClassType() const;

  // @name Accessors.
  // @{
  const Arguments& argument_types() const { return arg_types_; }
  const CallConvention call_convention() const { return call_convention_; }
  const TypeId containing_class_id() const { return containing_class_id_; }
  const ArgumentType& return_type() const { return return_type_; }
  // @}

  // @returns true if this is a member function.
  bool IsMemberFunction() const { return containing_class_id_ != kNoTypeId; }

  // Finalize the type by providing it with an argument list and return value.
  // @param return_value the return value of the type.
  // @param args the arguments for the type.
  // @note this can only be called once per type instance.
  void Finalize(const ArgumentType& return_type, const Arguments& arg_types);

 private:
  //  Stores the arguments.
  Arguments arg_types_;

  // The return value.
  ArgumentType return_type_;

  // The calling convention of this function.
  CallConvention call_convention_;

  // The type index of the containing class or KNoTypeId if this is not a member
  // function.
  TypeId containing_class_id_;

  DISALLOW_COPY_AND_ASSIGN(FunctionType);
};

using FunctionTypePtr = scoped_refptr<FunctionType>;

// Enum representing different calling conventions, the values are the same as
// the ones used in the PDB stream.
enum FunctionType::CallConvention {
  CALL_NEAR_C = 0x00,
  CALL_FAR_C = 0x01,
  CALL_NEAR_PASCAL = 0x02,
  CALL_FAR_PASCAL = 0x03,
  CALL_NEAR_FASTCALL = 0x04,
  CALL_FAR_FASTCALL = 0x05,
  CALL_SKIPPED = 0x06,
  CALL_NEAR_STDCALL = 0x07,
  CALL_FAR_STDCALL = 0x08,
  CALL_NEAR_SYSCALL = 0x09,
  CALL_FAR_SYSCALL = 0x0A,
  CALL_THIS_CALL = 0x0B,
  CALL_MIPS_CALL = 0x0C,
  CALL_GENERIC = 0x0D,
  CALL_ALPHACALL = 0x0E,
  CALL_PPCCALL = 0x0F,
  CALL_SHCALL = 0x10,
  CALL_ARMCALL = 0x11,
  CALL_AM33CALL = 0x12,
  CALL_TRICALL = 0x13,
  CALL_SH5CALL = 0x14,
  CALL_M32RCALL = 0x15,
  CALL_CLRCALL = 0x16,
  CALL_RESERVED = 0x17  // first unused call enumeration
};

// Represents an otherwise unsupported type.
// TODO(siggi): This is a stub, which needs to go away ASAP.
class WildcardType : public Type {
 public:
  static const TypeKind ID = WILDCARD_TYPE_KIND;

  // Creates a new wildcard type with name @p name, size @p size.
  WildcardType(const base::string16& name, size_t size);
  // Creates a new wildcard type with name @p name, @p decorated_name and
  // size @p size.
  WildcardType(const base::string16& name,
               const base::string16& decorated_name,
               size_t size);
};

using WildcardTypePtr = scoped_refptr<WildcardType>;

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
