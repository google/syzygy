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

#include "syzygy/refinery/types/pdb_crawler.h"

#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "syzygy/common/align.h"
#include "syzygy/pdb/pdb_reader.h"
#include "syzygy/pdb/pdb_type_info_stream_enum.h"
#include "syzygy/pdb/gen/pdb_type_info_records.h"
#include "syzygy/pe/cvinfo_ext.h"
#include "syzygy/refinery/types/type.h"
#include "syzygy/refinery/types/type_repository.h"

namespace refinery {

namespace {

namespace cci = Microsoft_Cci_Pdb;

const uint16_t kNoLeafType = static_cast<uint16_t>(-1);

class TypeCreator {
 public:
  explicit TypeCreator(TypeRepository* repository);
  ~TypeCreator();

  // Crawls @p stream, creates all types and assigns names to pointers.
  // @returns true on success, false on failure.
  bool CreateTypes(scoped_refptr<pdb::PdbStream> stream);

 private:
  // The following functions parse objects from the data stream.
  // @returns pointer to the created object or nullptr on failure.
  TypePtr CreateUserDefinedType(TypeId type_id);
  TypePtr CreateBasicPointerType(TypeId type_id);
  TypePtr CreatePointerType(TypeId type_id);
  TypePtr CreateArrayType(TypeId type_id);
  TypePtr CreateFunctionType(TypeId type_id);
  TypePtr CreateBasicType(TypeId type_id);
  TypePtr CreateWildcardType(TypeId type_id);

  // The following functions parse records but do not save them in the type
  // repository. Instead they just pass out the flags (and bit field values)
  // to the caller. However they ensure parsing of the underlying types.
  // @returns pointer to the type underlying the modifier.
  TypePtr ReadModifier(TypeId type_id, Type::Flags* flags);
  TypePtr ReadPointer(TypeId type_id, Type::Flags* flags);
  TypePtr ReadBitfield(TypeId type_id,
                       Type::Flags* flags,
                       size_t* bit_pos,
                       size_t* bit_len);

  // Assigns names to all pointer, array and function types that have been
  // created.
  // @returns true on success, false on failure.
  bool EnsureTypeName(TypePtr type);
  bool AssignPointerName(PointerTypePtr ptr);
  bool AssignArrayName(ArrayTypePtr array);
  bool AssignFunctionName(FunctionTypePtr function);

  // Processes a member field and inserts it into given field list.
  // @param member pointer to the member type record.
  // @param fields pointer to the field list.
  // @returns true on success, false on failure.
  bool ProcessMember(pdb::LeafMember* member, UserDefinedType::Fields* fields);

  // Processes one method field and adds it as a member function in the member
  // function list.
  // @param method pointer to the one method type record.
  // @param functions pointer to the member function list.
  // @returns true on success, false on failure.
  bool ProcessOneMethod(pdb::LeafOneMethod* method,
                        UserDefinedType::Functions* functions);

  // Processes overloaded method field and add the member functions to the given
  // list.
  // @param method pointer to the method type record.
  // @param functions pointer to the member function list.
  // @returns true on success, false on failure.
  bool ProcessMethod(pdb::LeafMethod* method,
                     UserDefinedType::Functions* functions);

  // Parses field list from the data stream and populates the UDT with fields
  // and member functions.
  // @param fields pointer to the field list.
  // @param functions pointer to the member function list.
  // @returns true on success, false on failure.
  bool ReadFieldlist(TypeId type_id,
                     UserDefinedType::Fields* fields,
                     UserDefinedType::Functions* functions);

  // Parses arglist from the data stream and populates the given list of
  // argument types.
  // @param args pointer to the the argument list.
  // @returns true on success, false on failure.
  bool ReadArglist(TypeId type_id, FunctionType::Arguments* args);

  // Parses type given by a type from the PDB type info stream.
  // @param type_id index of the type to create.
  // @returns pointer to the created object.
  TypePtr CreateType(TypeId type_id);

  // Returns the leaf type of a record with given type index.
  // @param type_id type index of the record.
  // @returns type of the record, -1 as an error sentinel.
  uint16_t GetLeafType(TypeId type_id);

  // Does a first pass through the stream making the map of type indices for
  // UDT and saves indices of all types that will get translated to the type
  // repo.
  // @returns true on success, false on failure.
  bool PrepareData();

  // Checks if type object exists and constructs one if it does not.
  // @param type_id type index of the type.
  // @returns pointer to the type object.
  TypePtr FindOrCreateTypeImpl(TypeId type_id);

  // The following functions are called during parsing to recurse deeper and
  // validate the references we expect to be there. For better description see
  // the file pdb_type_info_stream_description.md in the pdb directory.
  TypePtr FindOrCreateBasicType(TypeId type_id);
  TypePtr FindOrCreateIndexingType(TypeId type_id);
  TypePtr FindOrCreateIntegralBasicType(TypeId type_id);
  TypePtr FindOrCreateStructuredType(TypeId type_id);
  TypePtr FindOrCreateInheritableType(TypeId type_id);
  TypePtr FindOrCreateUserDefinedType(TypeId type_id);
  TypePtr FindOrCreateModifiableType(TypeId type_id);
  TypePtr FindOrCreateSpecificType(TypeId type_id, uint16_t type);

  // The following function also propagate the flags and bit field information
  // to their parents.
  TypePtr FindOrCreateOptionallyModifiedType(TypeId type_id,
                                             Type::Flags* flags);
  TypePtr FindOrCreateBitfieldType(TypeId type_id, Type::Flags* flags);
  TypePtr FindOrCreatePointableType(TypeId type_id, Type::Flags* flags);
  TypePtr FindOrCreateMemberType(TypeId type_id,
                                 Type::Flags* flags,
                                 size_t* bit_pos,
                                 size_t* bit_len);

  // @returns name for a basic type specified by its @p type.
  static base::string16 BasicTypeName(uint16_t type);

  // @returns size for a basic type specified by its @p type.
  static size_t BasicTypeSize(uint16_t type);

  // @returns name for a leaf specified by its @p type.
  static base::string16 LeafTypeName(uint16_t type);

  // @returns size of a pointer given its @p ptr type info record.
  static size_t PointerSize(const pdb::LeafPointer& ptr);

  // Computes size of a pointer to member function or data.
  // @param pmtype CV_pmtype field of the pointer.
  // @param ptrtype CV_ptrtype field of the pointer.
  // @returns size of a member field pointer.
  static size_t MemberPointerSize(cci::CV_pmtype pmtype,
                                  cci::CV_ptrtype ptrtype);

  // Pulls CV_prmode out of basic type index.
  // @param type_id type index of a basic type.
  // @returns the CV_prmode field.
  static cci::CV_prmode TypeIndexToPrMode(TypeId type_id);

  // Construct string of CV modifiers.
  // @param is_const true if type is const.
  // @param is_volatile true if type is volatile.
  // @returns the string of CV modifiers.
  static base::string16 GetCVMod(bool is_const, bool is_volatile);

  // Creates Type::Flags from the individual bool values.
  // @param is_const true if type is const.
  // @param is_volatile true if type is volatile.
  // @returns type flags.
  static Type::Flags CreateTypeFlags(bool is_const, bool is_volatile);

  // Checks if the type gets translated to a type repository.
  // @param type the type of this record.
  // @returns true if this record gets translated to the repository.
  static bool IsImportantType(uint32_t type);

  // Checks if this is actually pointer encoded in basic type index.
  // @param type_id type index of the record.
  // @returns true if the record is pointer.
  bool IsBasicPointerType(TypeId type_id);

  // Pointer to the type info repository.
  TypeRepository* repository_;

  // Type info enumerator used to traverse the stream.
  pdb::TypeInfoEnumerator type_info_enum_;

  // Direct access to the Pdb stream inside the type info enumerator.
  scoped_refptr<pdb::PdbStream> stream_;

  // Hash to map forward references to the right UDT records. For each unique
  // decorated name of an UDT, it contains type index of the class definition.
  base::hash_map<base::string16, TypeId> udt_map;

  // Hash to store the pdb leaf types of the individual records. Indexed by type
  // indices.
  base::hash_map<TypeId, uint16_t> types_map_;

  // Vector of records to process.
  std::vector<TypeId> records_to_process_;
};

TypePtr TypeCreator::CreatePointerType(TypeId type_id) {
  DCHECK_EQ(GetLeafType(type_id), cci::LF_POINTER);

  if (!type_info_enum_.SeekRecord(type_id))
    return nullptr;

  pdb::LeafPointer type_info;
  if (!type_info.Initialize(stream_.get())) {
    LOG(ERROR) << "Unable to read type info record.";
    return nullptr;
  }

  // Save type information.
  size_t size = PointerSize(type_info);
  PointerType::Mode ptr_mode = PointerType::PTR_MODE_PTR;
  if (type_info.attr().ptrmode == cci::CV_PTR_MODE_REF)
    ptr_mode = PointerType::PTR_MODE_REF;

  PointerTypePtr created = new PointerType(size, ptr_mode);
  if (!repository_->AddTypeWithId(created, type_id))
    return nullptr;

  // Try to find the object in the repository.
  TypeId pointee_id = type_info.body().utype;
  Type::Flags pointee_flags = kNoTypeFlags;
  TypePtr pointee_type = FindOrCreatePointableType(pointee_id, &pointee_flags);
  if (pointee_type == nullptr)
    return nullptr;

  // Setting the flags from the child node - this is needed because of
  // different semantics between PDB file and Type interface. In PDB pointer
  // has a const flag when it's const, while here pointer has a const flag if
  // it points to a const type.
  created->Finalize(pointee_flags, pointee_type->type_id());
  return created;
}

TypePtr TypeCreator::CreateBasicPointerType(TypeId type_id) {
  DCHECK(IsBasicPointerType(type_id));
  TypeId basic_index = type_id & (cci::CV_PRIMITIVE_TYPE::CV_TMASK |
                                  cci::CV_PRIMITIVE_TYPE::CV_SMASK);
  if (FindOrCreateBasicType(basic_index) == nullptr)
    return nullptr;

  // Get pointer size.
  size_t size = 0;
  cci::CV_prmode prmode = TypeIndexToPrMode(type_id);
  switch (prmode) {
    case cci::CV_TM_NPTR32:
      size = 4;
      break;
    case cci::CV_TM_NPTR64:
      size = 8;
      break;
    case cci::CV_TM_NPTR128:
      size = 16;
      break;
    default:
      return nullptr;
  }

  // Create and finalize type.
  PointerTypePtr pointer_type =
      new PointerType(size, PointerType::PTR_MODE_PTR);
  pointer_type->Finalize(kNoTypeFlags, basic_index);

  if (!repository_->AddTypeWithId(pointer_type, type_id))
    return nullptr;
  return pointer_type;
}

TypePtr TypeCreator::ReadPointer(TypeId type_id, Type::Flags* flags) {
  DCHECK(flags);
  DCHECK_EQ(GetLeafType(type_id), cci::LF_POINTER);

  if (!type_info_enum_.SeekRecord(type_id))
    return nullptr;

  pdb::LeafPointer type_info;
  if (!type_info.Initialize(stream_.get())) {
    LOG(ERROR) << "Unable to read type info record.";
    return nullptr;
  }

  *flags =
      CreateTypeFlags(type_info.attr().isconst, type_info.attr().isvolatile);
  if (!stream_->Seek(0))
    return nullptr;

  return FindOrCreateSpecificType(type_info_enum_.type_id(), cci::LF_POINTER);
}

TypePtr TypeCreator::ReadModifier(TypeId type_id, Type::Flags* flags) {
  DCHECK(flags);
  DCHECK_EQ(GetLeafType(type_id), cci::LF_MODIFIER);

  if (!type_info_enum_.SeekRecord(type_id))
    return nullptr;

  pdb::LeafModifier type_info;
  if (!type_info.Initialize(stream_.get())) {
    LOG(ERROR) << "Unable to read type info record.";
    return nullptr;
  }

  TypePtr underlying_type = FindOrCreateModifiableType(type_info.body().type);
  if (underlying_type == nullptr)
    return nullptr;

  *flags = CreateTypeFlags(type_info.attr().mod_const,
                           type_info.attr().mod_volatile);
  return underlying_type;
}

bool TypeCreator::ReadFieldlist(TypeId type_id,
                                UserDefinedType::Fields* fields,
                                UserDefinedType::Functions* functions) {
  DCHECK(fields);
  DCHECK(functions);
  DCHECK_EQ(GetLeafType(type_id), cci::LF_FIELDLIST);

  if (!type_info_enum_.SeekRecord(type_id))
    return nullptr;

  size_t leaf_end = stream_->pos() + type_info_enum_.len();

  // Make our local copy of the data. This is necessary to avoid clutter with
  // deeper levels of recursion.
  scoped_refptr<pdb::PdbByteStream> local_stream(new pdb::PdbByteStream());
  local_stream->Init(stream_.get());

  while (local_stream->pos() < leaf_end) {
    uint16_t leaf_type = 0;
    if (!local_stream->Read(&leaf_type, 1)) {
      LOG(ERROR) << "Unable to read the type of a list field.";
      return false;
    }

    switch (leaf_type) {
      case cci::LF_MEMBER: {
        pdb::LeafMember type_info;
        if (!type_info.Initialize(local_stream.get()) ||
            !ProcessMember(&type_info, fields)) {
          return false;
        }
        break;
      }
      case cci::LF_BCLASS: {
        pdb::LeafBClass type_info;
        if (!type_info.Initialize(local_stream.get()))
          return false;
        break;
      }
      case cci::LF_VBCLASS:
      case cci::LF_IVBCLASS: {
        pdb::LeafVBClass type_info;
        if (!type_info.Initialize(local_stream.get()))
          return false;
        break;
      }
      case cci::LF_ENUMERATE: {
        pdb::LeafEnumerate type_info;
        if (!type_info.Initialize(local_stream.get()))
          return false;
        break;
      }
      case cci::LF_FRIENDFCN: {
        pdb::LeafFriendFcn type_info;
        if (!type_info.Initialize(local_stream.get()))
          return false;
        break;
      }
      case cci::LF_STMEMBER: {
        pdb::LeafSTMember type_info;
        if (!type_info.Initialize(local_stream.get()))
          return false;
        break;
      }
      case cci::LF_METHOD: {
        pdb::LeafMethod type_info;
        if (!type_info.Initialize(local_stream.get()) ||
            !ProcessMethod(&type_info, functions)) {
          return false;
        }
        break;
      }
      case cci::LF_NESTTYPE: {
        pdb::LeafNestType type_info;
        if (!type_info.Initialize(local_stream.get()))
          return false;
        break;
      }
      case cci::LF_VFUNCTAB: {
        pdb::LeafVFuncTab type_info;
        if (!type_info.Initialize(local_stream.get()))
          return false;
        break;
      }
      case cci::LF_FRIENDCLS: {
        pdb::LeafFriendCls type_info;
        if (!type_info.Initialize(local_stream.get()))
          return false;
        break;
      }
      case cci::LF_ONEMETHOD: {
        pdb::LeafOneMethod type_info;
        if (!type_info.Initialize(local_stream.get()) ||
            !ProcessOneMethod(&type_info, functions)) {
          return false;
        }
        break;
      }
      case cci::LF_VFUNCOFF: {
        pdb::LeafVFuncOff type_info;
        if (!type_info.Initialize(local_stream.get()))
          return false;
        break;
      }
      default: {
        NOTREACHED();
        break;
      }
    }
    // The records are aligned.
    local_stream->Seek(common::AlignUp(local_stream->pos(), 4));
  }
  return true;
}

bool TypeCreator::ReadArglist(TypeId type_id,
                              FunctionType::Arguments* arglist) {
  DCHECK(arglist);
  DCHECK_EQ(GetLeafType(type_id), cci::LF_ARGLIST);

  if (!type_info_enum_.SeekRecord(type_id))
    return nullptr;

  // Make our local copy of the data. This is necessary to avoid clutter with
  // deeper levels of recursion.
  scoped_refptr<pdb::PdbByteStream> stream(new pdb::PdbByteStream());
  stream->Init(stream_.get());

  uint32_t num_args = 0;
  if (!stream->Read(&num_args, 1))
    return false;

  while (arglist->size() < num_args) {
    uint32_t arg_type_id = 0;
    if (!stream->Read(&arg_type_id, 1)) {
      LOG(ERROR) << "Unable to read the type index of an argument.";
      return false;
    }

    Type::Flags flags = kNoTypeFlags;
    TypePtr arg_type = FindOrCreateOptionallyModifiedType(arg_type_id, &flags);
    if (arg_type == nullptr)
      return false;

    arglist->push_back(FunctionType::ArgumentType(flags, arg_type->type_id()));
  }
  return true;
}

TypePtr TypeCreator::CreateUserDefinedType(TypeId type_id) {
  DCHECK(GetLeafType(type_id) == cci::LF_CLASS ||
         GetLeafType(type_id) == cci::LF_STRUCTURE);

  if (!type_info_enum_.SeekRecord(type_id))
    return nullptr;

  pdb::LeafClass type_info;
  if (!type_info.Initialize(stream_.get())) {
    LOG(ERROR) << "Unable to read type info record.";
    return nullptr;
  }

  if (type_info.property().fwdref) {
    // Find the type index of the class.
    auto real_class_id = udt_map.find(type_info.decorated_name());
    if (real_class_id == udt_map.end()) {
      // This is a forward reference without real class record.
      // TODO(mopler): Add forward declaration flag in the UDT type.
      UserDefinedTypePtr udt = new UserDefinedType(
          type_info.name(), type_info.decorated_name(), type_info.size());
      if (!repository_->AddTypeWithId(udt, type_id))
        return nullptr;
      return udt;
    }

    // Force parsing of the class.
    return FindOrCreateSpecificType(real_class_id->second,
                                    type_info_enum_.type());
  } else {
    // Create UDT of the class and find its fieldlist.
    UserDefinedTypePtr udt = new UserDefinedType(
        type_info.name(), type_info.decorated_name(), type_info.size());
    if (!repository_->AddTypeWithId(udt, type_id))
      return nullptr;

    UserDefinedType::Fields fieldlist;
    UserDefinedType::Functions functionlist;
    if (!ReadFieldlist(type_info.body().field, &fieldlist, &functionlist))
      return false;

    udt->Finalize(fieldlist, functionlist);
    return udt;
  }
}

TypePtr TypeCreator::CreateArrayType(TypeId type_id) {
  DCHECK_EQ(GetLeafType(type_id), cci::LF_ARRAY);

  if (!type_info_enum_.SeekRecord(type_id))
    return nullptr;

  pdb::LeafArray type_info;
  if (!type_info.Initialize(stream_.get())) {
    LOG(ERROR) << "Unable to read type info record.";
    return nullptr;
  }

  ArrayTypePtr array_type = new ArrayType(type_info.size());
  if (!repository_->AddTypeWithId(array_type, type_id))
    return false;

  // Find the types in the repository.
  Type::Flags flags = kNoTypeFlags;
  TypeId index_id = type_info.body().idxtype;
  TypeId elem_id = type_info.body().elemtype;
  TypePtr index_type = FindOrCreateIndexingType(index_id);
  TypePtr elem_type = FindOrCreateOptionallyModifiedType(elem_id, &flags);
  if (index_type == nullptr || elem_type == nullptr)
    return false;

  size_t num_elements = 0;
  // TODO(mopler): Once we load everything test against the size not being zero.
  if (elem_type->size() != 0)
    num_elements = type_info.size() / elem_type->size();
  array_type->Finalize(flags, index_type->type_id(), num_elements,
                       elem_type->type_id());
  return array_type;
}

TypePtr TypeCreator::CreateFunctionType(TypeId type_id) {
  DCHECK(GetLeafType(type_id) == cci::LF_PROCEDURE ||
         GetLeafType(type_id) == cci::LF_MFUNCTION);

  if (!type_info_enum_.SeekRecord(type_id))
    return nullptr;

  FunctionType::CallConvention call_convention;
  TypeId return_type_id = kNoTypeId;
  TypeId containing_class_id = kNoTypeId;
  TypeId arglist_id = kNoTypeId;

  if (type_info_enum_.type() == cci::LF_PROCEDURE) {
    // Load the procedure record.
    pdb::LeafProcedure type_info;
    if (!type_info.Initialize(stream_.get())) {
      LOG(ERROR) << "Unable to read type info record.";
      return nullptr;
    }

    call_convention =
        static_cast<FunctionType::CallConvention>(type_info.body().calltype);
    return_type_id = type_info.body().rvtype;
    arglist_id = type_info.body().arglist;
  } else if (type_info_enum_.type() == cci::LF_MFUNCTION) {
    // Load the member function record.
    pdb::LeafMFunction type_info;
    if (!type_info.Initialize(stream_.get())) {
      LOG(ERROR) << "Unable to read type info record.";
      return nullptr;
    }

    call_convention =
        static_cast<FunctionType::CallConvention>(type_info.body().calltype);
    return_type_id = type_info.body().rvtype;
    arglist_id = type_info.body().arglist;
    containing_class_id = type_info.body().classtype;
  } else {
    return nullptr;
  }

  FunctionTypePtr function_type = new FunctionType(call_convention);
  if (!repository_->AddTypeWithId(function_type, type_id))
    return false;

  Type::Flags flags = kNoTypeFlags;
  TypePtr return_type =
      FindOrCreateOptionallyModifiedType(return_type_id, &flags);
  if (return_type == nullptr)
    return false;

  // If this is a member function parse the containing class.
  if (containing_class_id != kNoTypeId) {
    TypePtr class_type = FindOrCreateStructuredType(containing_class_id);
    if (class_type == nullptr)
      return nullptr;

    containing_class_id = class_type->type_id();
  }

  // Parse the argument list.
  FunctionType::Arguments arglist;
  if (!ReadArglist(arglist_id, &arglist))
    return false;

  function_type->Finalize(
      FunctionType::ArgumentType(flags, return_type->type_id()), arglist,
      containing_class_id);
  return function_type;
}

TypePtr TypeCreator::ReadBitfield(TypeId type_id,
                                  Type::Flags* flags,
                                  size_t* bit_pos,
                                  size_t* bit_len) {
  DCHECK(flags);
  DCHECK(bit_pos);
  DCHECK(bit_len);
  DCHECK(GetLeafType(type_id) == cci::LF_BITFIELD);

  if (!type_info_enum_.SeekRecord(type_id))
    return nullptr;

  pdb::LeafBitfield type_info;
  if (!type_info.Initialize(stream_.get())) {
    LOG(ERROR) << "Unable to read type info record.";
    return nullptr;
  }

  const size_t kMaxBitfieldValue = 63;
  if (type_info.body().position > kMaxBitfieldValue ||
      type_info.body().length > kMaxBitfieldValue) {
    LOG(ERROR) << "The bit position or length of bitfield is too large.";
    return nullptr;
  }

  *bit_pos = type_info.body().position;
  *bit_len = type_info.body().length;

  TypeId underlying_id = type_info.body().type;
  *flags = kNoTypeFlags;

  return FindOrCreateBitfieldType(underlying_id, flags);
}

bool TypeCreator::EnsureTypeName(TypePtr type) {
  if (!type->name().empty())
    return true;

  switch (type->kind()) {
    case Type::POINTER_TYPE_KIND: {
      PointerTypePtr ptr;
      if (!type->CastTo(&ptr))
        return false;

      if (!AssignPointerName(ptr))
        return false;

      DCHECK_NE(L"", ptr->name());
      DCHECK_NE(L"", ptr->decorated_name());
      break;
    }
    case Type::ARRAY_TYPE_KIND: {
      ArrayTypePtr array;
      if (!type->CastTo(&array))
        return false;

      if (!AssignArrayName(array))
        return false;

      DCHECK_NE(L"", array->name());
      DCHECK_NE(L"", array->decorated_name());
      break;
    }
    case Type::FUNCTION_TYPE_KIND: {
      FunctionTypePtr function;
      if (!type->CastTo(&function))
        return false;

      if (!AssignFunctionName(function))
        return false;

      DCHECK_NE(L"", function->name());
      DCHECK_NE(L"", function->decorated_name());
      break;
    }
    // Rest of the types should have their names set up.
    case Type::USER_DEFINED_TYPE_KIND:
    case Type::BASIC_TYPE_KIND: {
      DCHECK_NE(L"", type->name());
      break;
    }
  }

  return true;
}

bool TypeCreator::AssignArrayName(ArrayTypePtr array) {
  TypePtr element_type = array->GetElementType();
  base::string16 name;
  base::string16 decorated_name;
  if (element_type) {
    if (!EnsureTypeName(element_type))
      return false;
    name = element_type->name();
    decorated_name = element_type->decorated_name();
  }

  name.append(GetCVMod(array->is_const(), array->is_volatile()));
  decorated_name.append(GetCVMod(array->is_const(), array->is_volatile()));

  base::StringAppendF(&name, L"[%d]", array->num_elements());
  base::StringAppendF(&decorated_name, L"[%d]", array->num_elements());

  array->SetDecoratedName(name);
  array->SetName(name);
  return true;
}

bool TypeCreator::AssignPointerName(PointerTypePtr ptr) {
  TypePtr content_type = ptr->GetContentType();
  base::string16 name;
  base::string16 decorated_name;
  if (content_type) {
    if (!EnsureTypeName(content_type))
      return false;
    name = content_type->name();
    decorated_name = content_type->decorated_name();
  }

  name.append(GetCVMod(ptr->is_const(), ptr->is_volatile()));
  decorated_name.append(GetCVMod(ptr->is_const(), ptr->is_volatile()));

  if (ptr->ptr_mode() == PointerType::PTR_MODE_PTR) {
    name.append(L"*");
    decorated_name.append(L"*");
  } else {
    name.append(L"&");
    decorated_name.append(L"&");
  }

  ptr->SetName(name);
  ptr->SetDecoratedName(decorated_name);
  return true;
}

bool TypeCreator::AssignFunctionName(FunctionTypePtr function) {
  TypePtr return_type = function->GetReturnType();
  base::string16 name;
  base::string16 decorated_name;
  if (return_type) {
    if (!EnsureTypeName(return_type))
      return false;
    name = return_type->name();
    decorated_name = return_type->decorated_name();
  }

  name.append(L" (");
  decorated_name.append(L" (");

  TypePtr class_type = function->GetContainingClassType();
  if (class_type) {
    if (!EnsureTypeName(class_type))
      return false;
    name.append(class_type->name() + L"::)(");
    decorated_name.append(class_type->decorated_name() + L"::)(");
  }

  // Get the argument types names.
  std::vector<base::string16> arg_names;
  std::vector<base::string16> arg_decorated_names;
  for (size_t i = 0; i < function->argument_types().size(); ++i) {
    TypePtr arg_type = function->GetArgumentType(i);
    if (arg_type) {
      if (!EnsureTypeName(arg_type))
        return false;

      // Append the names, if the argument type is T_NOTYPE then this is a
      // C-style variadic function like printf and we append "..." instead.
      if (arg_type->type_id() == cci::T_NOTYPE) {
        arg_names.push_back(L"...");
        arg_decorated_names.push_back(L"...");
      } else {
        const FunctionType::ArgumentType& arg = function->argument_types()[i];
        base::string16 CV_mods = GetCVMod(arg.is_const(), arg.is_volatile());
        arg_names.push_back(arg_type->name() + CV_mods);
        arg_decorated_names.push_back(arg_type->decorated_name() + CV_mods);
      }
    }
  }

  name.append(base::JoinString(arg_names, L", "));
  decorated_name.append(base::JoinString(arg_decorated_names, L", "));

  name.append(L")");
  decorated_name.append(L")");

  function->SetName(name);
  function->SetDecoratedName(name);
  return true;
}

TypeCreator::TypeCreator(TypeRepository* repository) : repository_(repository) {
  DCHECK(repository);
}

TypeCreator::~TypeCreator() {
}

bool TypeCreator::ProcessMember(pdb::LeafMember* member,
                                UserDefinedType::Fields* fields) {
  DCHECK(member);
  DCHECK(fields);

  // TODO(mopler): Should we store the access protection and other info?
  // Get the member info.
  TypeId member_id = member->body().index;
  Type::Flags flags = kNoTypeFlags;
  size_t bit_pos = 0;
  size_t bit_len = 0;
  TypePtr member_type =
      FindOrCreateMemberType(member_id, &flags, &bit_pos, &bit_len);
  if (member_type == nullptr)
    return false;

  fields->push_back(UserDefinedType::Field(member->name(), member->offset(),
                                           flags, bit_pos, bit_len,
                                           member_type->type_id()));
  return true;
}

bool TypeCreator::ProcessOneMethod(pdb::LeafOneMethod* method,
                                   UserDefinedType::Functions* functions) {
  DCHECK(method);
  DCHECK(functions);

  // Parse the function type.
  TypeId function_id = method->body().index;
  if (FindOrCreateSpecificType(function_id, cci::LF_MFUNCTION) == nullptr)
    return false;

  functions->push_back(UserDefinedType::Function(method->name(), function_id));
  return true;
}

bool TypeCreator::ProcessMethod(pdb::LeafMethod* method,
                                UserDefinedType::Functions* functions) {
  DCHECK(method);
  DCHECK(functions);

  // Seek the method list record.
  if (!type_info_enum_.SeekRecord(method->body().mList) ||
      type_info_enum_.type() != cci::LF_METHODLIST) {
    return false;
  }

  // We need a local copy of the data in order to load the records.
  scoped_refptr<pdb::PdbByteStream> local_stream(new pdb::PdbByteStream());
  local_stream->Init(stream_.get());

  uint16_t count = method->body().count;
  while (count > 0) {
    pdb::MethodListRecord method_record;
    if (!method_record.Initialize(local_stream.get())) {
      LOG(ERROR) << "Unable to read method list record.";
      return false;
    }

    // Parse the function type.
    TypeId function_id = method_record.body().index;
    if (FindOrCreateSpecificType(function_id, cci::LF_MFUNCTION) == nullptr)
      return false;

    functions->push_back(
        UserDefinedType::Function(method->name(), function_id));

    count--;
  }
  return true;
}

base::string16 TypeCreator::BasicTypeName(uint16_t type) {
  switch (type) {
// Just return the name of the type.
#define SPECIAL_TYPE_NAME(record_type, type_name, size) \
  case cci::record_type: return L#type_name;
    SPECIAL_TYPE_NAME_CASE_TABLE(SPECIAL_TYPE_NAME)
#undef SPECIAL_TYPE_NAME
  }
  return L"unknown_basic_type";
}

size_t TypeCreator::BasicTypeSize(uint16_t type) {
  switch (type) {
// Just return the size of the type.
#define SPECIAL_TYPE_NAME(record_type, type_name, size) \
  case cci::record_type: return size;
    SPECIAL_TYPE_NAME_CASE_TABLE(SPECIAL_TYPE_NAME)
#undef SPECIAL_TYPE_NAME
  }
  return 0;
}

base::string16 TypeCreator::LeafTypeName(uint16_t leaf_type) {
  switch (leaf_type) {
// Just return the name of the enum.
#define LEAF_TYPE_NAME(record_type, unused) \
  case cci::record_type: {                  \
    return L#record_type;                   \
  }
    LEAF_CASE_TABLE(LEAF_TYPE_NAME)
#undef LEAF_TYPE_NAME
    default:
      return L"UnknownLeaf";
  }
}

size_t TypeCreator::PointerSize(const pdb::LeafPointer& ptr) {
  size_t size = 0;
  const cci::CV_ptrtype ptrtype =
      static_cast<cci::CV_ptrtype>(ptr.attr().ptrtype);
  // Set the size of the pointer.
  switch (ptr.attr().ptrmode) {
    // The size of a regular pointer or reference can be deduced from its type.
    // TODO(mopler): Investigate references.
    case cci::CV_PTR_MODE_PTR:
    case cci::CV_PTR_MODE_REF: {
      if (ptrtype == cci::CV_PTR_NEAR32)
        size = 4;
      else if (ptrtype == cci::CV_PTR_64)
        size = 8;
      break;
    }
    // However in case of a member field pointer, its size depends on the
    // properties of the containing class. The pointer contains extra
    // information about the containing class.
    case cci::CV_PTR_MODE_PMFUNC:
    case cci::CV_PTR_MODE_PMEM: {
      const cci::CV_pmtype pmtype = static_cast<cci::CV_pmtype>(ptr.pmtype());
      size = MemberPointerSize(pmtype, ptrtype);
      break;
    }
  }
  return size;
}

size_t TypeCreator::MemberPointerSize(cci::CV_pmtype pmtype,
                                      cci::CV_ptrtype ptrtype) {
  DCHECK(ptrtype == cci::CV_PTR_NEAR32 || ptrtype == cci::CV_PTR_64);

  // The translation of modes to pointer sizes depends on the compiler. The
  // following values have been determined experimentally. For details see
  // https://github.com/google/syzygy/wiki/MemberPointersInPdbFiles.
  if (ptrtype == cci::CV_PTR_NEAR32) {
    switch (pmtype) {
      case cci::CV_PMTYPE_Undef:
        return 0;
      case cci::CV_PMTYPE_D_Single:
        return 4;
      case cci::CV_PMTYPE_D_Multiple:
        return 4;
      case cci::CV_PMTYPE_D_Virtual:
        return 8;
      case cci::CV_PMTYPE_D_General:
        return 12;
      case cci::CV_PMTYPE_F_Single:
        return 4;
      case cci::CV_PMTYPE_F_Multiple:
        return 8;
      case cci::CV_PMTYPE_F_Virtual:
        return 12;
      case cci::CV_PMTYPE_F_General:
        return 16;
    }
  } else if (ptrtype == cci::CV_PTR_64) {
    switch (pmtype) {
      case cci::CV_PMTYPE_Undef:
        return 0;
      case cci::CV_PMTYPE_D_Single:
        return 4;
      case cci::CV_PMTYPE_D_Multiple:
        return 4;
      case cci::CV_PMTYPE_D_Virtual:
        return 8;
      case cci::CV_PMTYPE_D_General:
        return 12;
      case cci::CV_PMTYPE_F_Single:
        return 8;
      case cci::CV_PMTYPE_F_Multiple:
        return 16;
      case cci::CV_PMTYPE_F_Virtual:
        return 16;
      case cci::CV_PMTYPE_F_General:
        return 24;
    }
  }
  // It seems that VS doesn't use the other pointer types in PDB files.
  NOTREACHED();
  return 0;
}

bool TypeCreator::IsImportantType(uint32_t type) {
  switch (type) {
    case cci::LF_CLASS:
    case cci::LF_STRUCTURE:
    case cci::LF_ARRAY:
    case cci::LF_POINTER:
    case cci::LF_PROCEDURE:
    case cci::LF_MFUNCTION:
      return true;
  }
  return false;
}

base::string16 TypeCreator::GetCVMod(bool is_const, bool is_volatile) {
  base::string16 suffix;
  if (is_const)
    suffix += L" const";
  if (is_volatile)
    suffix += L" volatile";
  return suffix;
}

Type::Flags TypeCreator::CreateTypeFlags(bool is_const, bool is_volatile) {
  Type::Flags flags = kNoTypeFlags;
  if (is_const)
    flags |= Type::FLAG_CONST;
  if (is_volatile)
    flags |= Type::FLAG_VOLATILE;
  return flags;
}

uint16_t TypeCreator::GetLeafType(TypeId type_id) {
  if (type_id < cci::CV_PRIMITIVE_TYPE::CV_FIRST_NONPRIM)
    return type_id;

  auto it = types_map_.find(type_id);
  if (it == types_map_.end()) {
    LOG(ERROR) << "Couldn't find record with type index " << type_id
               << " in the types map.";
    return kNoLeafType;
  } else {
    return it->second;
  }
}

bool TypeCreator::IsBasicPointerType(TypeId type_id) {
  if (type_id >= cci::CV_PRIMITIVE_TYPE::CV_FIRST_NONPRIM)
    return false;

  // T_PVOID is used to encode std::nullptr_t which we save as a basic type.
  if (type_id == cci::T_PVOID)
    return false;

  if (TypeIndexToPrMode(type_id) == cci::CV_TM_DIRECT)
    return false;

  return true;
}

cci::CV_prmode TypeCreator::TypeIndexToPrMode(TypeId type_id) {
  return static_cast<cci::CV_prmode>(
      (type_id & cci::CV_PRIMITIVE_TYPE::CV_MMASK) >>
      cci::CV_PRIMITIVE_TYPE::CV_MSHIFT);
}

TypePtr TypeCreator::CreateBasicType(TypeId type_id) {
  DCHECK(type_id < cci::CV_PRIMITIVE_TYPE::CV_FIRST_NONPRIM);

  BasicTypePtr basic_type =
      new BasicType(BasicTypeName(type_id), BasicTypeSize(type_id));

  // Save type and additional info.
  if (!repository_->AddTypeWithId(basic_type, type_id))
    return nullptr;
  return basic_type;
}

TypePtr TypeCreator::CreateWildcardType(TypeId type_id) {
  base::string16 name = LeafTypeName(GetLeafType(type_id));
  TypePtr wildcard_type = new WildcardType(name, name, 0);
  if (!repository_->AddTypeWithId(wildcard_type, type_id))
    return nullptr;
  return wildcard_type;
}

TypePtr TypeCreator::FindOrCreateTypeImpl(TypeId type_id) {
  TypePtr type = repository_->GetType(type_id);
  if (type != nullptr)
    return type;

  // We need to create new type object.
  // Check if it is a regular type index.
  if (type_id >= type_info_enum_.type_info_header().type_min) {
    return CreateType(type_id);
  } else {
    // Check if this is actually a pointer.
    if (IsBasicPointerType(type_id)) {
      return CreateBasicPointerType(type_id);
    } else {
      // Otherwise create the basic type.
      return CreateBasicType(type_id);
    }
  }
}

TypePtr TypeCreator::FindOrCreateIndexingType(TypeId type_id) {
  if (type_id == cci::T_ULONG || type_id == cci::T_UQUAD)
    return FindOrCreateTypeImpl(type_id);

  return nullptr;
}

TypePtr TypeCreator::FindOrCreateIntegralBasicType(TypeId type_id) {
  TypeId type_mask = (type_id & cci::CV_PRIMITIVE_TYPE::CV_TMASK) >>
                     cci::CV_PRIMITIVE_TYPE::CV_TSHIFT;

  if (type_mask == cci::CV_SIGNED || type_mask == cci::CV_UNSIGNED ||
      type_mask == cci::CV_INT || type_mask == cci::CV_BOOLEAN) {
    return FindOrCreateBasicType(type_id);
  }

  return nullptr;
}

TypePtr TypeCreator::FindOrCreateBasicType(TypeId type_id) {
  if (type_id < cci::CV_PRIMITIVE_TYPE::CV_FIRST_NONPRIM &&
      !IsBasicPointerType(type_id)) {
    return FindOrCreateTypeImpl(type_id);
  }

  return nullptr;
}

TypePtr TypeCreator::FindOrCreateInheritableType(TypeId type_id) {
  uint16_t type = GetLeafType(type_id);
  if (type == cci::LF_CLASS || type == cci::LF_STRUCTURE)
    return FindOrCreateTypeImpl(type_id);

  return nullptr;
}

TypePtr TypeCreator::FindOrCreateStructuredType(TypeId type_id) {
  uint16_t type = GetLeafType(type_id);
  if (type == cci::LF_UNION)
    return FindOrCreateTypeImpl(type_id);

  return FindOrCreateInheritableType(type_id);
}

TypePtr TypeCreator::FindOrCreateUserDefinedType(TypeId type_id) {
  uint16_t type = GetLeafType(type_id);
  if (type == cci::LF_ENUM)
    return FindOrCreateTypeImpl(type_id);

  return FindOrCreateStructuredType(type_id);
}

TypePtr TypeCreator::FindOrCreateModifiableType(TypeId type_id) {
  uint16_t type = GetLeafType(type_id);

  if (type < cci::CV_PRIMITIVE_TYPE::CV_FIRST_NONPRIM)
    return FindOrCreateBasicType(type_id);

  return FindOrCreateUserDefinedType(type_id);
}

TypePtr TypeCreator::FindOrCreateOptionallyModifiedType(TypeId type_id,
                                                        Type::Flags* flags) {
  DCHECK(flags);
  uint16_t type = GetLeafType(type_id);
  *flags = kNoTypeFlags;

  if (type == cci::LF_MODIFIER)
    return ReadModifier(type_id, flags);

  if (type == cci::LF_POINTER)
    return ReadPointer(type_id, flags);

  if (type == cci::LF_ARRAY)
    return FindOrCreateTypeImpl(type_id);

  if (IsBasicPointerType(type_id))
    return FindOrCreateTypeImpl(type_id);

  return FindOrCreateModifiableType(type_id);
}

TypePtr TypeCreator::FindOrCreateBitfieldType(TypeId type_id,
                                              Type::Flags* flags) {
  DCHECK(flags);
  uint16_t type = GetLeafType(type_id);
  *flags = kNoTypeFlags;

  if (type == cci::LF_MODIFIER) {
    TypePtr type = ReadModifier(type_id, flags);
    // TODO(mopler): Once we load enums change the name test to type test.
    if (type->kind() == Type::BASIC_TYPE_KIND || type->name() == L"LF_ENUM")
      return type;

    return nullptr;
  }

  if (type == cci::LF_ENUM)
    return FindOrCreateTypeImpl(type_id);

  return FindOrCreateIntegralBasicType(type_id);
}

TypePtr TypeCreator::FindOrCreateMemberType(TypeId type_id,
                                            Type::Flags* flags,
                                            size_t* bit_pos,
                                            size_t* bit_len) {
  DCHECK(flags);
  DCHECK(bit_pos);
  DCHECK(bit_len);

  uint16_t type = GetLeafType(type_id);
  *flags = kNoTypeFlags;
  *bit_pos = 0;
  *bit_len = 0;

  if (type == cci::LF_BITFIELD)
    return ReadBitfield(type_id, flags, bit_pos, bit_len);

  return FindOrCreateOptionallyModifiedType(type_id, flags);
}

TypePtr TypeCreator::FindOrCreatePointableType(TypeId type_id,
                                               Type::Flags* flags) {
  DCHECK(flags);
  *flags = kNoTypeFlags;
  uint16_t type = GetLeafType(type_id);

  if (type == cci::LF_MFUNCTION || type == cci::LF_PROCEDURE ||
      type == cci::LF_VTSHAPE) {
    return FindOrCreateTypeImpl(type_id);
  }

  return FindOrCreateOptionallyModifiedType(type_id, flags);
}

TypePtr TypeCreator::FindOrCreateSpecificType(TypeId type_id, uint16_t type) {
  DCHECK_NE(kNoLeafType, type);
  uint16_t this_type = GetLeafType(type_id);

  if (this_type != type)
    return nullptr;

  return FindOrCreateTypeImpl(type_id);
}

TypePtr TypeCreator::CreateType(TypeId type_id) {
  switch (GetLeafType(type_id)) {
    case cci::LF_CLASS:
    case cci::LF_STRUCTURE: {
      return CreateUserDefinedType(type_id);
    }
    case cci::LF_POINTER: {
      return CreatePointerType(type_id);
    }
    case cci::LF_ARRAY: {
      return CreateArrayType(type_id);
    }
    case cci::LF_PROCEDURE:
    case cci::LF_MFUNCTION: {
      return CreateFunctionType(type_id);
    }
    default: { return CreateWildcardType(type_id); }
  }
}

bool TypeCreator::PrepareData() {
  while (!type_info_enum_.EndOfStream()) {
    if (!type_info_enum_.NextTypeInfoRecord())
      return false;

    types_map_.insert(
        std::make_pair(type_info_enum_.type_id(), type_info_enum_.type()));

    // We remember ids of the types that we will later descend into.
    if (IsImportantType(type_info_enum_.type()))
      records_to_process_.push_back(type_info_enum_.type_id());

    if (type_info_enum_.type() == cci::LF_CLASS ||
        type_info_enum_.type() == cci::LF_STRUCTURE) {
      pdb::LeafClass type_info;
      if (!type_info.Initialize(stream_.get())) {
        LOG(ERROR) << "Unable to read type info record.";
        return false;
      }

      // Add the map from decorated name to type index. This overwrites any
      // preceding records of the same name because we want to remember the
      // last one. We can get multiple declarations of the same name, for
      // example all the unnamed nested structures get assigned the name
      // <unnamed-tag>.
      if (!type_info.property().fwdref)
        udt_map[type_info.decorated_name()] = type_info_enum_.type_id();
    }
  }

  return type_info_enum_.ResetStream();
}

bool TypeCreator::CreateTypes(scoped_refptr<pdb::PdbStream> stream) {
  DCHECK(stream);

  if (!type_info_enum_.Init(stream.get())) {
    LOG(ERROR) << "Unable to initialize type info stream enumerator.";
    return false;
  }

  const TypeId kSmallestUnreservedIndex = 0x1000;
  if (type_info_enum_.type_info_header().type_min < kSmallestUnreservedIndex) {
    LOG(ERROR) << "Degenerate stream with type indices in the reserved range.";
    return false;
  }

  stream_ = type_info_enum_.GetDataStream();

  // Create the map of forward declarations and populate the process queue.
  if (!PrepareData())
    return false;

  // Process every important type.
  for (TypeId type_id : records_to_process_) {
    if (FindOrCreateTypeImpl(type_id) == nullptr)
      return false;
  }

  // And assign type names.
  for (auto type : *repository_) {
    if (!EnsureTypeName(type))
      return false;
  }

  return true;
}

}  // namespace

PdbCrawler::PdbCrawler() {
}

PdbCrawler::~PdbCrawler() {
}

bool PdbCrawler::InitializeForFile(const base::FilePath& path) {
  pdb::PdbReader reader;
  pdb::PdbFile pdb_file;

  if (!reader.Read(path, &pdb_file)) {
    LOG(ERROR) << "Failed to read PDB file " << path.value() << ".";
    return false;
  }

  stream_ = pdb_file.GetStream(pdb::kTpiStream);
  return true;
}

bool PdbCrawler::GetTypes(TypeRepository* types) {
  DCHECK(types);
  DCHECK(stream_);

  TypeCreator creator(types);

  return creator.CreateTypes(stream_);
}

}  // namespace refinery
