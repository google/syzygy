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

#include <string>
#include <vector>

#include "base/bind.h"
#include "base/logging.h"
#include "base/strings/pattern.h"
#include "base/strings/string16.h"
#include "base/strings/stringprintf.h"
#include "syzygy/common/align.h"
#include "syzygy/core/address.h"
#include "syzygy/pdb/omap.h"
#include "syzygy/pdb/pdb_dbi_stream.h"
#include "syzygy/pdb/pdb_file.h"
#include "syzygy/pdb/pdb_reader.h"
#include "syzygy/pdb/pdb_reader.h"
#include "syzygy/pdb/pdb_symbol_record.h"
#include "syzygy/pdb/pdb_type_info_stream_enum.h"
#include "syzygy/pdb/pdb_util.h"
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
  TypeCreator(TypeRepository* repository, pdb::PdbStream* stream);
  ~TypeCreator();

  // Crawls @p stream_, creates all types and assigns names to pointers.
  // @returns true on success, false on failure.
  bool CreateTypes();

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

  // Processes a base class field and inserts it into given field list.
  // @param bclass pointer to the (non-virtual) base class field record.
  // @param fields pointer to the field list.
  // @returns true on success, false on failure.
  bool ProcessBClass(pdb::LeafBClass* bclass, UserDefinedType::Fields* fields);

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

  // Helper function for processesing a virtual function field and inserting it
  // into given field list.
  // @param id the type identifier of the virtual function field.
  // @param offset the offset of the field within the containing class.
  // @param fields pointer to the field list.
  // @returns true on success, false on failure.
  bool ProcessVFunc(TypeId id,
                    ptrdiff_t offset,
                    UserDefinedType::Fields* fields);

  // Processes a virtual function at offset field and inserts it into given
  // field list.
  // @param vfunc pointer to the virtual function at offset field record.
  // @param fields pointer to the field list.
  // @returns true on success, false on failure.
  bool ProcessVFuncOff(pdb::LeafVFuncOff* vfunc,
                       UserDefinedType::Fields* fields);

  // Processes a virtual function field and inserts it into given field list.
  // @param vfunc pointer to the virtual function field record.
  // @param fields pointer to the field list.
  // @returns true on success, false on failure.
  bool ProcessVFuncTab(pdb::LeafVFuncTab* vfunc,
                       UserDefinedType::Fields* fields);

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
  // TODO(manzagop): Add a typedef for the leaf type.
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

  // Accessors for forward references caching.
  bool CacheUserDefinedTypeForwardDeclaration(TypeId fwd_id, TypeId class_id);
  TypeId LookupConcreteClassForForwardDeclaration(TypeId type_id);

  // @returns name for a basic type specified by its @p type.
  static base::string16 BasicTypeName(size_t type);

  // @returns size for a basic type specified by its @p type.
  static size_t BasicTypeSize(size_t type);

  // @returns name for a leaf specified by its @p type.
  static base::string16 LeafTypeName(size_t type);

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

  // Hash to map forward references to the right UDT records. For each unique
  // decorated name of an UDT, it contains type index of the class definition.
  std::unordered_map<base::string16, TypeId> udt_map_;

  // Hash to store the pdb leaf types of the individual records. Indexed by type
  // indices.
  std::unordered_map<TypeId, uint16_t> types_map_;

  // Hash which stores for each forward declaration the type index of the
  // actual class type.
  std::unordered_map<TypeId, TypeId> fwd_reference_map_;

  // Vector of records to process.
  std::vector<TypeId> records_to_process_;
};

TypePtr TypeCreator::CreatePointerType(TypeId type_id) {
  DCHECK_EQ(GetLeafType(type_id), cci::LF_POINTER);

  if (!type_info_enum_.SeekRecord(type_id))
    return nullptr;

  pdb::TypeInfoEnumerator::BinaryTypeRecordReader reader(
      type_info_enum_.CreateRecordReader());
  common::BinaryStreamParser parser(&reader);
  pdb::LeafPointer type_info;
  if (!type_info.Initialize(&parser)) {
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

  pdb::TypeInfoEnumerator::BinaryTypeRecordReader reader(
      type_info_enum_.CreateRecordReader());
  common::BinaryStreamParser parser(&reader);
  pdb::LeafPointer type_info;
  if (!type_info.Initialize(&parser)) {
    LOG(ERROR) << "Unable to read type info record.";
    return nullptr;
  }

  *flags =
      CreateTypeFlags(type_info.attr().isconst, type_info.attr().isvolatile);

  return FindOrCreateSpecificType(type_info_enum_.type_id(), cci::LF_POINTER);
}

TypePtr TypeCreator::ReadModifier(TypeId type_id, Type::Flags* flags) {
  DCHECK(flags);
  DCHECK_EQ(GetLeafType(type_id), cci::LF_MODIFIER);

  if (!type_info_enum_.SeekRecord(type_id))
    return nullptr;

  pdb::TypeInfoEnumerator::BinaryTypeRecordReader reader(
      type_info_enum_.CreateRecordReader());
  common::BinaryStreamParser parser(&reader);
  pdb::LeafModifier type_info;
  if (!type_info.Initialize(&parser)) {
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
    return false;

  // Grab the leaf size, as sub-parsing moves the enumerator.
  size_t leaf_size = type_info_enum_.len();
  pdb::TypeInfoEnumerator::BinaryTypeRecordReader local_reader(
      type_info_enum_.CreateRecordReader());
  common::BinaryStreamParser local_parser(&local_reader);
  while (local_reader.Position() < leaf_size) {
    uint16_t leaf_type = 0;
    if (!local_parser.Read(&leaf_type)) {
      LOG(ERROR) << "Unable to read the type of a list field.";
      return false;
    }

    switch (leaf_type) {
      case cci::LF_MEMBER: {
        pdb::LeafMember type_info;
        if (!type_info.Initialize(&local_parser) ||
            !ProcessMember(&type_info, fields)) {
          return false;
        }
        break;
      }
      case cci::LF_BCLASS: {
        pdb::LeafBClass type_info;
        if (!type_info.Initialize(&local_parser) ||
            !ProcessBClass(&type_info, fields)) {
          return false;
        }
        break;
      }
      case cci::LF_VBCLASS:
      case cci::LF_IVBCLASS: {
        pdb::LeafVBClass type_info;
        if (!type_info.Initialize(&local_parser))
          return false;
        break;
      }
      case cci::LF_ENUMERATE: {
        pdb::LeafEnumerate type_info;
        if (!type_info.Initialize(&local_parser))
          return false;
        break;
      }
      case cci::LF_FRIENDFCN: {
        pdb::LeafFriendFcn type_info;
        if (!type_info.Initialize(&local_parser))
          return false;
        break;
      }
      case cci::LF_STMEMBER: {
        pdb::LeafSTMember type_info;
        if (!type_info.Initialize(&local_parser))
          return false;
        break;
      }
      case cci::LF_METHOD: {
        pdb::LeafMethod type_info;
        if (!type_info.Initialize(&local_parser) ||
            !ProcessMethod(&type_info, functions)) {
          return false;
        }
        break;
      }
      case cci::LF_NESTTYPE: {
        pdb::LeafNestType type_info;
        if (!type_info.Initialize(&local_parser))
          return false;
        break;
      }
      case cci::LF_VFUNCTAB: {
        pdb::LeafVFuncTab type_info;
        if (!type_info.Initialize(&local_parser) ||
            !ProcessVFuncTab(&type_info, fields))
          return false;
        break;
      }
      case cci::LF_FRIENDCLS: {
        pdb::LeafFriendCls type_info;
        if (!type_info.Initialize(&local_parser))
          return false;
        break;
      }
      case cci::LF_ONEMETHOD: {
        pdb::LeafOneMethod type_info;
        if (!type_info.Initialize(&local_parser) ||
            !ProcessOneMethod(&type_info, functions)) {
          return false;
        }
        break;
      }
      case cci::LF_VFUNCOFF: {
        pdb::LeafVFuncOff type_info;
        if (!type_info.Initialize(&local_parser) ||
            !ProcessVFuncOff(&type_info, fields))
          return false;
        break;
      }
      case cci::LF_INDEX: {
        pdb::LeafIndex type_info;
        if (!type_info.Initialize(&local_parser))
          return false;
        // This is always the last record of the fieldlist.
        // TODO(manzagop): ask siggi@ if he thinks this optimization is wise.
        return ReadFieldlist(type_info.body().index, fields, functions);
      }
      default: {
        NOTREACHED();
        break;
      }
    }
    // The records are aligned to a 4 byte boundary.
    const size_t kRecordAlignment = 4;
    size_t align = local_reader.Position() % kRecordAlignment;
    if (align > 0)
      local_reader.Consume(kRecordAlignment - align);

    DCHECK_EQ(0U, local_reader.Position() % kRecordAlignment);
  }
  return true;
}

bool TypeCreator::ReadArglist(TypeId type_id,
                              FunctionType::Arguments* arglist) {
  DCHECK(arglist);
  DCHECK_EQ(GetLeafType(type_id), cci::LF_ARGLIST);

  if (!type_info_enum_.SeekRecord(type_id))
    return false;

  pdb::TypeInfoEnumerator::BinaryTypeRecordReader reader(
      type_info_enum_.CreateRecordReader());
  common::BinaryStreamParser parser(&reader);

  uint32_t num_args = 0;
  if (!parser.Read(&num_args))
    return false;

  while (arglist->size() < num_args) {
    uint32_t arg_type_id = 0;
    if (!parser.Read(&arg_type_id)) {
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
         GetLeafType(type_id) == cci::LF_STRUCTURE ||
         GetLeafType(type_id) == cci::LF_UNION);

  if (!type_info_enum_.SeekRecord(type_id))
    return nullptr;

  // Read the values from the PDB records.
  LeafPropertyField property = {};
  TypeId fieldlist_id = kNoTypeId;
  uint64_t size = 0;
  base::string16 name;
  base::string16 decorated_name;

  pdb::TypeInfoEnumerator::BinaryTypeRecordReader reader(
      type_info_enum_.CreateRecordReader());
  common::BinaryStreamParser parser(&reader);
  if (type_info_enum_.type() == cci::LF_CLASS ||
      type_info_enum_.type() == cci::LF_STRUCTURE) {
    pdb::LeafClass type_info;
    if (!type_info.Initialize(&parser)) {
      LOG(ERROR) << "Unable to read type info record.";
      return nullptr;
    }
    property = type_info.property();
    fieldlist_id = type_info.body().field;
    size = type_info.size();
    name = type_info.name();
    decorated_name = type_info.decorated_name();
  } else if (type_info_enum_.type() == cci::LF_UNION) {
    pdb::LeafUnion type_info;
    if (!type_info.Initialize(&parser)) {
      LOG(ERROR) << "Unable to read type info record.";
      return nullptr;
    }
    property = type_info.property();
    fieldlist_id = type_info.body().field;
    size = type_info.size();
    name = type_info.name();
    decorated_name = type_info.decorated_name();
  }

  // Set the correct UDT kind.
  UserDefinedType::UdtKind udt_kind = UserDefinedType::UDT_CLASS;
  switch (type_info_enum_.type()) {
    case cci::LF_CLASS: {
      udt_kind = UserDefinedType::UDT_CLASS;
      break;
    }
    case cci::LF_STRUCTURE: {
      udt_kind = UserDefinedType::UDT_STRUCT;
      break;
    }
    case cci::LF_UNION: {
      udt_kind = UserDefinedType::UDT_UNION;
      break;
    }
  }

  if (property.fwdref) {
    // Find the type index of the UDT.
    auto real_class_id = udt_map_.find(decorated_name);
    if (real_class_id == udt_map_.end()) {
      // This is a forward reference without real UDT record.
      UserDefinedTypePtr udt =
          new UserDefinedType(name, decorated_name, size, udt_kind);
      udt->SetIsForwardDeclaration();
      if (!repository_->AddTypeWithId(udt, type_id))
        return nullptr;
      return udt;
    }

    // Cache redirection to the real UDT.
    if (!CacheUserDefinedTypeForwardDeclaration(type_id, real_class_id->second))
      return nullptr;

    // Force parsing of the UDT.
    return FindOrCreateSpecificType(real_class_id->second,
                                    type_info_enum_.type());
  } else {
    // Create UDT of the class and find its fieldlist.
    UserDefinedTypePtr udt =
        new UserDefinedType(name, decorated_name, size, udt_kind);
    if (!repository_->AddTypeWithId(udt, type_id))
      return nullptr;

    UserDefinedType::Fields fieldlist;
    UserDefinedType::Functions functionlist;
    if (!ReadFieldlist(fieldlist_id, &fieldlist, &functionlist))
      return false;

    udt->Finalize(&fieldlist, &functionlist);
    return udt;
  }
}

TypePtr TypeCreator::CreateArrayType(TypeId type_id) {
  DCHECK_EQ(GetLeafType(type_id), cci::LF_ARRAY);

  if (!type_info_enum_.SeekRecord(type_id))
    return nullptr;

  pdb::TypeInfoEnumerator::BinaryTypeRecordReader reader(
      type_info_enum_.CreateRecordReader());
  common::BinaryStreamParser parser(&reader);
  pdb::LeafArray type_info;
  if (!type_info.Initialize(&parser)) {
    LOG(ERROR) << "Unable to read type info record.";
    return nullptr;
  }

  ArrayTypePtr array_type = new ArrayType(type_info.size());
  if (!repository_->AddTypeWithId(array_type, type_id))
    return nullptr;

  // Find the types in the repository.
  Type::Flags flags = kNoTypeFlags;
  TypeId index_id = type_info.body().idxtype;
  TypeId elem_id = type_info.body().elemtype;
  TypePtr index_type = FindOrCreateIndexingType(index_id);
  TypePtr elem_type = FindOrCreateOptionallyModifiedType(elem_id, &flags);
  if (index_type == nullptr || elem_type == nullptr)
    return nullptr;

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

  pdb::TypeInfoEnumerator::BinaryTypeRecordReader reader(
      type_info_enum_.CreateRecordReader());
  common::BinaryStreamParser parser(&reader);
  if (type_info_enum_.type() == cci::LF_PROCEDURE) {
    // Load the procedure record.
    pdb::LeafProcedure type_info;
    if (!type_info.Initialize(&parser)) {
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
    if (!type_info.Initialize(&parser)) {
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
    return nullptr;

  Type::Flags flags = kNoTypeFlags;
  TypePtr return_type =
      FindOrCreateOptionallyModifiedType(return_type_id, &flags);
  if (return_type == nullptr)
    return nullptr;

  // If this is a member function parse the containing class.
  if (containing_class_id != kNoTypeId &&
      containing_class_id != cci::T_NOTYPE) {
    TypePtr class_type = FindOrCreateStructuredType(containing_class_id);
    if (class_type == nullptr)
      return nullptr;

    containing_class_id = class_type->type_id();
  }

  // Parse the argument list.
  FunctionType::Arguments arglist;
  if (!ReadArglist(arglist_id, &arglist))
    return nullptr;

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

  pdb::TypeInfoEnumerator::BinaryTypeRecordReader reader(
      type_info_enum_.CreateRecordReader());
  common::BinaryStreamParser parser(&reader);
  pdb::LeafBitfield type_info;
  if (!type_info.Initialize(&parser)) {
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

TypeCreator::TypeCreator(TypeRepository* repository, pdb::PdbStream* stream)
    : type_info_enum_(stream), repository_(repository) {
  DCHECK(repository);
  DCHECK(stream);
}

TypeCreator::~TypeCreator() {
}

bool TypeCreator::ProcessBClass(pdb::LeafBClass* bclass,
                                UserDefinedType::Fields* fields) {
  DCHECK(bclass);
  DCHECK(fields);

  // Ensure the base class' type is created.
  TypeId bclass_id = bclass->body().index;
  TypePtr bclass_type = FindOrCreateInheritableType(bclass_id);
  if (bclass_type == nullptr)
    return false;

  fields->push_back(new UserDefinedType::BaseClassField(
      bclass->offset(), bclass_type->type_id(), repository_));

  return true;
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

  fields->push_back(new UserDefinedType::MemberField(
      member->name(), member->offset(), flags, bit_pos, bit_len,
      member_type->type_id(), repository_));
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

  pdb::TypeInfoEnumerator::BinaryTypeRecordReader reader(
      type_info_enum_.CreateRecordReader());
  common::BinaryStreamParser parser(&reader);

  uint16_t count = method->body().count;
  while (count > 0) {
    pdb::MethodListRecord method_record;
    if (!method_record.Initialize(&parser)) {
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

bool TypeCreator::ProcessVFunc(
    TypeId id, ptrdiff_t offset, UserDefinedType::Fields* fields) {
  DCHECK(fields);

  // Virtual function pointer fields have as type a pointer type to a virtual
  // table shape.
  TypePtr type = FindOrCreateSpecificType(id, cci::LF_POINTER);
  if (type == nullptr)
    return false;

  // Validate the pointer type's content type is a vtable shape.
  PointerTypePtr ptr_type;
  if (!type->CastTo(&ptr_type))
    return false;
  DCHECK(ptr_type);
  TypePtr content_type = ptr_type->GetContentType();
  DCHECK(content_type);
  // TODO(manzagop): update once virtual tables have their own type.
  if (content_type->kind() != Type::WILDCARD_TYPE_KIND)
    return false;

  fields->push_back(
      new UserDefinedType::VfptrField(offset, type->type_id(), repository_));

  return true;
}

bool TypeCreator::ProcessVFuncOff(pdb::LeafVFuncOff* vfunc,
                                  UserDefinedType::Fields* fields) {
  DCHECK(vfunc);
  DCHECK(fields);
  return ProcessVFunc(vfunc->body().type, vfunc->body().offset, fields);
}

bool TypeCreator::ProcessVFuncTab(pdb::LeafVFuncTab* vfunc,
                                  UserDefinedType::Fields* fields) {
  DCHECK(vfunc);
  DCHECK(fields);
  return ProcessVFunc(vfunc->body().type, 0, fields);
}

base::string16 TypeCreator::BasicTypeName(size_t type) {
  switch (type) {
// Just return the name of the type.
#define SPECIAL_TYPE_NAME(record_type, type_name, size) \
  case cci::record_type: return L#type_name;
    SPECIAL_TYPE_NAME_CASE_TABLE(SPECIAL_TYPE_NAME)
#undef SPECIAL_TYPE_NAME
  }
  return L"unknown_basic_type";
}

size_t TypeCreator::BasicTypeSize(size_t type) {
  switch (type) {
// Just return the size of the type.
#define SPECIAL_TYPE_NAME(record_type, type_name, size) \
  case cci::record_type: return size;
    SPECIAL_TYPE_NAME_CASE_TABLE(SPECIAL_TYPE_NAME)
#undef SPECIAL_TYPE_NAME
  }
  return 0;
}

base::string16 TypeCreator::LeafTypeName(size_t leaf_type) {
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
    case cci::LF_UNION:
    case cci::LF_ARRAY:
    case cci::LF_POINTER:
    case cci::LF_PROCEDURE:
    case cci::LF_MFUNCTION:
      return true;
  }
  return false;
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
    return static_cast<uint16_t>(type_id);

  auto it = types_map_.find(type_id);
  if (it == types_map_.end()) {
    LOG(ERROR) << "Couldn't find record with type index " << type_id
               << " in the types map.";
    return kNoLeafType;
  } else {
    return it->second;
  }
}

bool TypeCreator::CacheUserDefinedTypeForwardDeclaration(TypeId fwd_id,
                                                         TypeId class_id) {
  return fwd_reference_map_.insert(std::make_pair(fwd_id, class_id)).second;
}

TypeId TypeCreator::LookupConcreteClassForForwardDeclaration(TypeId type_id) {
  auto redir = fwd_reference_map_.find(type_id);
  if (redir != fwd_reference_map_.end()) {
    return redir->second;
  } else {
    return kNoTypeId;
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
  TypeId concrete_type_id = LookupConcreteClassForForwardDeclaration(type_id);
  if (concrete_type_id != kNoTypeId)
    return repository_->GetType(concrete_type_id);

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
    if (type->kind() == Type::BASIC_TYPE_KIND || type->GetName() == L"LF_ENUM")
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
    case cci::LF_STRUCTURE:
    case cci::LF_UNION: {
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
  size_t unexpected_duplicate_types = 0;

  while (!type_info_enum_.EndOfStream()) {
    if (!type_info_enum_.NextTypeInfoRecord())
      return false;

    types_map_.insert(
        std::make_pair(type_info_enum_.type_id(), type_info_enum_.type()));

    // We remember ids of the types that we will later descend into.
    if (IsImportantType(type_info_enum_.type()))
      records_to_process_.push_back(type_info_enum_.type_id());

    pdb::TypeInfoEnumerator::BinaryTypeRecordReader reader(
        type_info_enum_.CreateRecordReader());
    common::BinaryStreamParser parser(&reader);
    if (type_info_enum_.type() == cci::LF_CLASS ||
        type_info_enum_.type() == cci::LF_STRUCTURE) {
      pdb::LeafClass type_info;
      if (!type_info.Initialize(&parser)) {
        LOG(ERROR) << "Unable to read type info record.";
        return false;
      }

      // Populate the decorated name to type index map. Note that this
      // overwrites any preceding record of the same name, which can occur for
      // 2 reasons:
      //   - the unnamed nested structures get assigned the name <unnamed-tag>
      //   - we've observed UDTs that are identical up to extra LF_NESTTYPE
      //     (which do not make it to our type representation).
      // TODO(manzagop): investigate more and consider folding duplicate types.
      if (!type_info.property().fwdref) {
        if (type_info.name().find(L'<') != 0 &&
            udt_map_.find(type_info.decorated_name()) != udt_map_.end()) {
          VLOG(1) << "Encountered duplicate decorated name: "
                  << type_info.decorated_name();
          unexpected_duplicate_types++;
        }

        udt_map_[type_info.decorated_name()] = type_info_enum_.type_id();
      }
    }
  }

  if (unexpected_duplicate_types > 0) {
    LOG(INFO) << "Encountered " << unexpected_duplicate_types
              << " unexpected duplicate types.";
  }

  return type_info_enum_.ResetStream();
}

bool TypeCreator::CreateTypes() {
  if (!type_info_enum_.Init()) {
    LOG(ERROR) << "Unable to initialize type info stream enumerator.";
    return false;
  }

  const TypeId kSmallestUnreservedIndex = 0x1000;
  if (type_info_enum_.type_info_header().type_min < kSmallestUnreservedIndex) {
    LOG(ERROR) << "Degenerate stream with type indices in the reserved range.";
    return false;
  }

  // Create the map of forward declarations and populate the process queue.
  if (!PrepareData())
    return false;

  // Process every important type.
  for (TypeId type_id : records_to_process_) {
    if (FindOrCreateTypeImpl(type_id) == nullptr)
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

  // Get the type stream.
  tpi_stream_ = pdb_file.GetStream(pdb::kTpiStream);

  // Get the public symbol stream: it has a variable index, found in the Dbi
  // stream.
  scoped_refptr<pdb::PdbStream> dbi_stream_raw =
      pdb_file.GetStream(pdb::kDbiStream);
  pdb::DbiStream dbi_stream;
  if (dbi_stream_raw.get() == nullptr ||
      !dbi_stream.Read(dbi_stream_raw.get())) {
    LOG(ERROR) << "No Dbi stream.";
    return false;
  }

  // The dbi stream's header contains the index of the public symbol stream.
  uint32_t sym_stream_idx = dbi_stream.header().symbol_record_stream;
  if (sym_stream_idx != -1) {
    sym_stream_ = pdb_file.GetStream(sym_stream_idx);
    if (sym_stream_ == nullptr) {
      LOG(ERROR) << "Failed to get symbol record stream.";
      return false;
    }
  } else {
    // The PDB does not have a public symbol stream. This may happen.
    LOG(INFO) << "No symbol record stream.";
    return true;
  }

  // Get the PE image section information. The DbiDbgHeader contains the index
  // of a stream that contains this information as an array of
  // IMAGE_SECTION_HEADER.
  uint32_t img_hdr_stream_idx = dbi_stream.dbg_header().section_header;
  if (img_hdr_stream_idx == -1) {
    LOG(ERROR) << "No section header stream.";
    return false;
  }
  scoped_refptr<pdb::PdbStream> img_hdr_stream =
      pdb_file.GetStream(img_hdr_stream_idx);
  if (img_hdr_stream == nullptr) {
    LOG(ERROR) << "Failed to get image header stream.";
    return false;
  }
  size_t num_elements = img_hdr_stream->length() / sizeof(IMAGE_SECTION_HEADER);
  section_headers_.resize(num_elements);
  if (num_elements != 0 &&
      !img_hdr_stream->ReadBytesAt(0, num_elements, &section_headers_.at(0))) {
    LOG(ERROR) << "Failed to read the image header stream.";
    return false;
  }

  // The PDB may include OMAP information, used to represent a mapping from
  // an original PDB address space to a transformed one. The DbiDbgHeader
  // contains indices for two streams that contain this information as arrays of
  // OMAP structures. We retrieve only the mapping from the original space to
  // the transformed space.
  if (dbi_stream.dbg_header().omap_from_src >= 0) {
    if (!pdb::ReadOmapsFromPdbFile(pdb_file, nullptr, &omap_from_)) {
      LOG(ERROR) << "Failed to read the OMAP data.";
      return false;
    }
  }

  return true;
}

bool PdbCrawler::GetTypes(TypeRepository* types) {
  DCHECK(types);
  DCHECK(tpi_stream_);

  TypeCreator creator(types, tpi_stream_.get());

  return creator.CreateTypes();
}

bool PdbCrawler::GetVFTableRVAForSymbol(
    base::hash_set<RelativeAddress>* vftable_rvas,
    uint16_t symbol_length,
    uint16_t symbol_type,
    common::BinaryStreamReader* symbol_reader) {
  DCHECK(symbol_reader);
  DCHECK(vftable_rvas);

  // Not a vftable: skip to the next record.
  if (symbol_type != cci::S_PUB32)
    return true;

  // Read the symbol.
  cci::PubSym32 symbol = {};
  size_t to_read = offsetof(cci::PubSym32, name);
  common::BinaryStreamParser parser(symbol_reader);
  if (!parser.ReadBytes(to_read, &symbol)) {
    LOG(ERROR) << "Unable to read symbol.";
    return false;
  }
  std::string symbol_name;
  if (!parser.ReadString(&symbol_name)) {
    LOG(ERROR) << "Unable to read symbol name.";
    return false;
  }

  // Determine if the symbol is a vftable based on its name.
  // Note: pattern derived from LLVM's MicrosoftMangle.cpp (mangleCXXVFTable).
  if (!base::MatchPattern(symbol_name, "\\?\\?_7*@6B*@"))
    return true;  // Not a vftable.

  // Determine the vftable's RVA, then add it to the set.

  // Note: Segment indexing seems to be 1-based.
  DCHECK(symbol.seg > 0);  // 1-based.
  if (symbol.seg < 1U || symbol.seg > section_headers_.size()) {
    LOG(ERROR) << "Symbol's segment is invalid.";
    return false;
  }

  uint32_t vftable_rva =
      section_headers_[symbol.seg - 1].VirtualAddress + symbol.off;

  // Apply OMAP transformation if necessary.
  if (omap_from_.size() > 0) {
    core::RelativeAddress rva_omap = pdb::TranslateAddressViaOmap(
        omap_from_, core::RelativeAddress(vftable_rva));
    vftable_rva = rva_omap.value();
  }

  vftable_rvas->insert(static_cast<RelativeAddress>(vftable_rva));

  return true;
}

bool PdbCrawler::GetVFTableRVAs(base::hash_set<RelativeAddress>* vftable_rvas) {
  DCHECK(vftable_rvas);
  vftable_rvas->clear();

  if (!sym_stream_)
    return false;  // The PDB does not have public symbols.

  pdb::VisitSymbolsCallback symbol_cb =
      base::Bind(&PdbCrawler::GetVFTableRVAForSymbol, base::Unretained(this),
                 base::Unretained(vftable_rvas));

  return pdb::VisitSymbols(symbol_cb, 0, sym_stream_->length(), false,
                           sym_stream_.get());
}

}  // namespace refinery
