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
#include "syzygy/refinery/types/type.h"

#include "base/md5.h"
#include "base/strings/string_piece.h"
#include "syzygy/refinery/types/type_namer.h"
#include "syzygy/refinery/types/type_repository.h"

namespace refinery {

Type::Type(TypeKind kind,
           size_t size)
    : repository_(nullptr),
      type_id_(kNoTypeId),
      kind_(kind),
      size_(size) {
}

Type::~Type() {
}

base::string16 Type::GetName() const {
  base::string16 name;
  if (TypeNamer::GetName(this, &name))
    return name;
  return kUnknownTypeName;
}

base::string16 Type::GetDecoratedName() const {
  base::string16 name;
  if (TypeNamer::GetDecoratedName(this, &name))
    return name;
  return kUnknownTypeName;
}

void Type::SetRepository(TypeRepository* repository, TypeId type_id) {
  DCHECK(repository);
  DCHECK(!repository_);
  DCHECK_EQ(kNoTypeId, type_id_);
  DCHECK_NE(kNoTypeId, type_id);

  repository_ = repository;
  type_id_ = type_id;
}

NamedType::NamedType(TypeKind kind,
                     size_t size,
                     const base::string16& name,
                     const base::string16& decorated_name)
    : Type(kind, size), name_(name), decorated_name_(decorated_name) {
}

NamedType::~NamedType() {
}

BasicType::BasicType(const base::string16& name, size_t size)
    : NamedType(BASIC_TYPE_KIND, size, name, name) {
}

UserDefinedType::UserDefinedType(const base::string16& name,
                                 size_t size,
                                 UdtKind udt_kind)
    : is_fwd_decl_(false),
      udt_kind_(udt_kind),
      NamedType(USER_DEFINED_TYPE_KIND, size, name, name) {
}

UserDefinedType::UserDefinedType(const base::string16& name,
                                 const base::string16& decorated_name,
                                 size_t size,
                                 UdtKind udt_kind)
    : is_fwd_decl_(false),
      udt_kind_(udt_kind),
      NamedType(USER_DEFINED_TYPE_KIND, size, name, decorated_name) {
}

TypePtr UserDefinedType::GetFieldType(size_t field_no) const {
  DCHECK(repository());
  DCHECK(!is_fwd_decl_);
  DCHECK_GT(fields_.size(), field_no);

  return repository()->GetType(fields_[field_no]->type_id());
}

TypePtr UserDefinedType::GetFunctionType(size_t function_no) const {
  DCHECK(repository());
  DCHECK(!is_fwd_decl_);
  DCHECK_GT(functions_.size(), function_no);

  return repository()->GetType(functions_[function_no].type_id());
}

void UserDefinedType::Finalize(Fields* fields, Functions* functions) {
  DCHECK(!is_fwd_decl_);
  DCHECK_EQ(0U, fields_.size());
  DCHECK_EQ(0U, functions_.size());
  DCHECK(fields);
  DCHECK(functions);

  fields_.swap(*fields);
  functions_.swap(*functions);
}

void UserDefinedType::SetIsForwardDeclaration() {
  DCHECK(!is_fwd_decl_);
  DCHECK_EQ(0U, fields_.size());
  DCHECK_EQ(0U, functions_.size());

  is_fwd_decl_ = true;
}

UserDefinedType::Field::Field(FieldKind kind,
                              ptrdiff_t offset,
                              TypeId type_id,
                              TypeRepository* repository)
    : kind_(kind), offset_(offset), type_id_(type_id), repository_(repository) {
  DCHECK_NE(kNoTypeId, type_id);
  DCHECK(repository);
}

TypePtr UserDefinedType::Field::GetType() const {
  DCHECK(repository_);
  return repository_->GetType(type_id_);
}

bool UserDefinedType::Field::operator==(const Field& o) const {
  return IsEqual(o);
}

bool UserDefinedType::Field::IsEqual(const Field& o) const {
  return kind_ == o.kind_ && offset_ == o.offset_ && type_id_ == o.type_id_;
}

UserDefinedType::Field::~Field() {
}

UserDefinedType::BaseClassField::BaseClassField(ptrdiff_t offset,
                                                TypeId type_id,
                                                TypeRepository* repository)
    : Field(BASE_CLASS_KIND, offset, type_id, repository) {
}

UserDefinedType::MemberField::MemberField(const base::string16& name,
                                          ptrdiff_t offset,
                                          Type::Flags flags,
                                          size_t bit_pos,
                                          size_t bit_len,
                                          TypeId type_id,
                                          TypeRepository* repository)
    : Field(MEMBER_KIND, offset, type_id, repository),
      name_(name),
      flags_(flags),
      bit_pos_(bit_pos),
      bit_len_(bit_len) {
  DCHECK_GE(63u, bit_pos);
  DCHECK_GE(63u, bit_len);
}

bool UserDefinedType::MemberField::IsEqual(const Field& o) const {
  if (!Field::IsEqual(o))
    return false;

  const MemberField* o_member = static_cast<const MemberField*>(&o);

  return name_ == o_member->name_ && flags_ == o_member->flags_ &&
         bit_pos_ == o_member->bit_pos_ && bit_len_ == o_member->bit_len_;
}

UserDefinedType::VfptrField::VfptrField(ptrdiff_t offset,
                                        TypeId type_id,
                                        TypeRepository* repository)
    : Field(VFPTR_KIND, offset, type_id, repository) {
}

UserDefinedType::Function::Function(const base::string16& name, TypeId type_id)
    : name_(name), type_id_(type_id) {
  DCHECK_NE(kNoTypeId, type_id);
}

bool UserDefinedType::Function::operator==(const Function& other) const {
  return name_ == other.name_ && type_id_ == other.type_id_;
}

PointerType::PointerType(size_t size, Mode ptr_mode)
    : Type(POINTER_TYPE_KIND, size),
      flags_(kNoTypeFlags),
      content_type_id_(kNoTypeId),
      ptr_mode_(ptr_mode) {
}

TypePtr PointerType::GetContentType() const {
  DCHECK(repository());

  return repository()->GetType(content_type_id());
}

void PointerType::Finalize(Flags flags, TypeId content_type_id) {
  DCHECK_EQ(kNoTypeFlags, flags_);
  DCHECK_EQ(kNoTypeId, content_type_id_);
  DCHECK_NE(kNoTypeId, content_type_id);

  flags_ = flags;
  content_type_id_ = content_type_id;
}

ArrayType::ArrayType(size_t size)
    : Type(ARRAY_TYPE_KIND, size),
      index_type_id_(kNoTypeId),
      num_elements_(0),
      element_type_id_(kNoTypeId) {
}

TypePtr ArrayType::GetIndexType() const {
  DCHECK(repository());

  return repository()->GetType(index_type_id_);
}

TypePtr ArrayType::GetElementType() const {
  DCHECK(repository());

  return repository()->GetType(element_type_id_);
}

void ArrayType::Finalize(Flags flags,
                         TypeId index_type_id,
                         size_t num_elements,
                         TypeId element_type_id) {
  DCHECK_EQ(kNoTypeId, index_type_id_);
  DCHECK_EQ(0U, num_elements_);
  DCHECK_EQ(kNoTypeId, element_type_id_);

  flags_ = flags;
  index_type_id_ = index_type_id;
  num_elements_ = num_elements;
  element_type_id_ = element_type_id;
}

FunctionType::FunctionType(CallConvention call_convention)
    : Type(FUNCTION_TYPE_KIND, 0),
      call_convention_(call_convention),
      containing_class_id_(kNoTypeId),
      return_type_(kNoTypeFlags, kNoTypeId) {
}

FunctionType::ArgumentType::ArgumentType(Flags flags, TypeId type_id)
    : flags_(flags), type_id_(type_id) {
}

bool FunctionType::ArgumentType::operator==(const ArgumentType& other) const {
  return flags_ == other.flags_ && type_id_ == other.type_id_;
}

void FunctionType::Finalize(const ArgumentType& return_type,
                            const Arguments& arg_types,
                            TypeId containing_class_id) {
  DCHECK_EQ(0U, arg_types_.size());
  DCHECK_EQ(kNoTypeId, return_type_.type_id());

  return_type_ = return_type;
  arg_types_ = arg_types;
  containing_class_id_ = containing_class_id;
}

TypePtr FunctionType::GetArgumentType(size_t arg_no) const {
  DCHECK(repository());
  DCHECK_GT(arg_types_.size(), arg_no);

  return repository()->GetType(arg_types_[arg_no].type_id());
}

TypePtr FunctionType::GetReturnType() const {
  DCHECK(repository());

  return repository()->GetType(return_type_.type_id());
}

TypePtr FunctionType::GetContainingClassType() const {
  DCHECK(repository());
  DCHECK(containing_class_id_ != kNoTypeId);

  return repository()->GetType(containing_class_id_);
}

GlobalType::GlobalType(const base::string16& name,
                       uint64_t rva,
                       TypeId data_type_id,
                       size_t size)
    : NamedType(GLOBAL_TYPE_KIND, size, name, name),
      rva_(rva),
      data_type_id_(data_type_id) {
}

TypePtr GlobalType::GetDataType() const {
  DCHECK(repository());
  return repository()->GetType(data_type_id_);
}

WildcardType::WildcardType(const base::string16& name, size_t size)
    : NamedType(WILDCARD_TYPE_KIND, size, name, name) {
}

WildcardType::WildcardType(const base::string16& name,
                           const base::string16& decorated_name,
                           size_t size)
    : NamedType(WILDCARD_TYPE_KIND, size, name, decorated_name) {
}

}  // namespace refinery
