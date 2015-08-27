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

// This struct is used to store and pass around additional information that
// cannot be put straight in the type repository. Main two purposes are to
// propagate CV modifiers from children to parents and to store information from
// records that do not get translated to the type repository (e.g. LF_MODIFIER).
struct ExtraTypeProperties {
  // CV flags.
  Type::Flags flags;

  // If this type is a bitfield, this is the bit position.
  size_t bit_pos : 6;

  // If this type is a bitfield, this is the bit length.
  size_t bit_len : 6;

  // Type Id of the closest element on the way down in the type repository.
  TypeId type_id;
};

class TypeCreator {
 public:
  explicit TypeCreator(TypeRepository* repository);
  ~TypeCreator();

  // Crawls @p stream, creates all types and assigns names to pointers.
  bool CreateTypes(scoped_refptr<pdb::PdbStream> stream);

 private:
  // The following functions parse objects from the data stream.
  // @returns pointer to the created object or underlying if this type does not
  // get translated to the type repository.
  TypePtr ReadClass();
  TypePtr ReadPointer();
  TypePtr ReadArray();
  TypePtr ReadProcedure();
  TypePtr ReadMFunction();
  TypePtr ReadModifier();
  TypePtr ReadBitfield();

  // Assigns names to all pointer, array and function types that have been
  // created.
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
  bool ReadFieldlist(UserDefinedType::Fields* fields,
                     UserDefinedType::Functions* functions);

  // Parses arglist from the data stream and populates the given list of
  // argument types. At the same time it appends comma separated list of
  // (decorated) names of the argument types to the strings passed as pointers.
  // @param args pointer to the the argument list.
  // @returns true on success, false on failure.
  bool ReadArglist(FunctionType::Arguments* args);

  // Creates function type from the given parameters.
  // @param type_id type index of the function type.
  // @param call_type calling convention of the function.
  // @param return_type_id type of the return value.
  // @param containing_class_id type index of the containing class. kNoTypeId
  //        means that this function isn't a member function.
  // @param arglist_id type index of the argument list.
  TypePtr CreateFunctionType(TypeId type_id,
                             uint8_t call_type,
                             TypeId return_type_id,
                             TypeId containing_class_id,
                             TypeId arglist_id);

  // Parses type given by a type from the PDB type info stream.
  // @param type_id index of the type to create.
  // @returns pointer to the created object.
  TypePtr CreateType(TypeId type_id);

  // Creates a basic type object.
  // @param type_id type index of the basic type.
  // @returns pointer to the created object.
  TypePtr CreateBasicType(TypeId type_id);

  // The following functions return values of the record with the given type id.
  // In case the temporary record is missing we assume identity mapping and no
  // flags.

  // @returns CV flags of the record with @p type id.
  Type::Flags GetFlags(TypeId type_id);

  // @returns bit position of the record with @p type id.
  size_t GetBitPosition(TypeId type_id);

  // @returns bit length of the record with @p type id.
  size_t GetBitLength(TypeId type_id);

  // @returns type id of the first type record in the repository lying under
  // the record with @p type id.
  size_t GetUnderlyingTypeId(TypeId type_id);

  // Does a first pass through the stream making the map of type indices for
  // UDT and saves indices of all types that will get translated to the type
  // repo.
  // @returns true on success, false on failure.
  bool PrepareData();

  // Checks if type object exists and constructs one if it does not.
  // @param type_id type index of the type.
  // @returns pointer to the type object.
  TypePtr FindOrCreateType(TypeId type_id);

  // Saves additional type info in the temporary stash.
  // @param type_id type index of the type in PDB stream.
  // @param underlying_id type index of the underlying type in the repository.
  // @param flags type info flags.
  void SaveTypeInfo(TypeId type_id, TypeId underlying_id, Type::Flags flags);

  // Saves additional bitfield type info in the temporary stash.
  // @param type_id type index of the bitfield.
  // @param bit_pos_in the bit position of the field.
  // @param bit_len_in the bit length of the field.
  void SaveBitfieldInfo(TypeId type_id, size_t bit_pos_in, size_t bit_len_in);

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

  // Construct string of CV modifiers.
  // @param is_const true if type is const.
  // @param is_volatile true if type is volatile.
  // @returns the string of CV modifiers.
  static base::string16 GetCVMod(bool is_const, bool is_volatile);

  // Pulls CV_prmode out of basic type index.
  // @param type_id type index of a basic type.
  // @returns the CV_prmode field.
  static cci::CV_prmode TypeIndexToPrMode(TypeId type_id);

  // Creates Type::Flags from the individual bool values.
  // @param is_const true if type is const.
  // @param is_volatile true if type is volatile.
  // @returns type flags.
  static Type::Flags CreateTypeFlags(bool is_const, bool is_volatile);

  // Checks if a type is important.
  // @param type the type of this record.
  // @returns true if this record gets translated to the repository.
  static bool IsImportantType(uint32_t type);

  // Pointer to the type info repository.
  TypeRepository* repository_;

  // Type info enumerator used to transverse the stream.
  pdb::TypeInfoEnumerator type_info_enum_;

  // Direct access to the Pdb stream inside the type info enumerator.
  scoped_refptr<pdb::PdbStream> stream_;

  // Hash to store the additional type information. Indexed by the type index
  // from the PDB stream.
  base::hash_map<TypeId, ExtraTypeProperties> temp_stash_;

  // Hash to map forward references to the right UDT records. For each unique
  // decorated name of an UDT, it contains type index of the class definition.
  base::hash_map<base::string16, TypeId> udt_map;

  // Vector of records to process.
  std::vector<TypeId> records_to_process_;
};

TypePtr TypeCreator::ReadPointer() {
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
  Type::Flags flags =
      CreateTypeFlags(type_info.attr().isconst, type_info.attr().isvolatile);

  TypeId type_id = type_info_enum_.type_id();
  SaveTypeInfo(type_id, type_id, flags);
  if (!repository_->AddTypeWithId(created, type_id))
    return nullptr;

  // Try to find the object in the repository.
  TypeId pointee_id = type_info.body().utype;
  if (FindOrCreateType(pointee_id) == nullptr)
    return nullptr;

  // Setting the flags from the child node - this is needed because of
  // different semantics between PDB file and Type interface. In PDB pointer
  // has a const flag when it's const, while here pointer has a const flag if
  // it points to a const type.
  created->Finalize(GetFlags(pointee_id), GetUnderlyingTypeId(pointee_id));
  return created;
}

TypePtr TypeCreator::ReadModifier() {
  pdb::LeafModifier type_info;
  if (!type_info.Initialize(stream_.get())) {
    LOG(ERROR) << "Unable to read type info record.";
    return nullptr;
  }

  TypePtr underlying_type = FindOrCreateType(type_info.body().type);
  if (underlying_type == nullptr)
    return nullptr;

  SaveTypeInfo(type_info_enum_.type_id(), underlying_type->type_id(),
               CreateTypeFlags(type_info.attr().mod_const,
                               type_info.attr().mod_volatile));
  return underlying_type;
}

bool TypeCreator::ReadFieldlist(UserDefinedType::Fields* fields,
                                UserDefinedType::Functions* functions) {
  DCHECK(fields);
  DCHECK(functions);
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

bool TypeCreator::ReadArglist(FunctionType::Arguments* arglist) {
  DCHECK(arglist);

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

    if (FindOrCreateType(arg_type_id) == nullptr)
      return false;

    arglist->push_back(FunctionType::ArgumentType(
        GetFlags(arg_type_id), GetUnderlyingTypeId(arg_type_id)));
  }
  return true;
}

TypePtr TypeCreator::ReadClass() {
  pdb::LeafClass type_info;
  if (!type_info.Initialize(stream_.get())) {
    LOG(ERROR) << "Unable to read type info record.";
    return nullptr;
  }

  TypeId type_id = type_info_enum_.type_id();

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

    SaveTypeInfo(type_id, real_class_id->second, kNoTypeFlags);

    // Force parsing of the class.
    return FindOrCreateType(real_class_id->second);
  } else {
    // Create UDT of the class and find its fieldlist.
    UserDefinedTypePtr udt = new UserDefinedType(
        type_info.name(), type_info.decorated_name(), type_info.size());
    if (!repository_->AddTypeWithId(udt, type_id))
      return nullptr;

    UserDefinedType::Fields fieldlist;
    UserDefinedType::Functions functionlist;
    if (!type_info_enum_.SeekRecord(type_info.body().field) ||
        !ReadFieldlist(&fieldlist, &functionlist))
      return false;

    udt->Finalize(fieldlist, functionlist);
    return udt;
  }
}

TypePtr TypeCreator::ReadArray() {
  pdb::LeafArray type_info;
  if (!type_info.Initialize(stream_.get())) {
    LOG(ERROR) << "Unable to read type info record.";
    return nullptr;
  }

  // Save type information.
  TypeId type_id = type_info_enum_.type_id();
  ArrayTypePtr array_type = new ArrayType(type_info.size());

  if (!repository_->AddTypeWithId(array_type, type_id))
    return false;

  // Find the types in the repository.
  TypeId index_id = type_info.body().idxtype;
  TypeId elem_id = type_info.body().elemtype;
  TypePtr index_type = FindOrCreateType(index_id);
  TypePtr elem_type = FindOrCreateType(elem_id);
  if (index_type == nullptr || elem_type == nullptr)
    return false;

  size_t num_elements = 0;
  // TODO(mopler): Once we load everything test against the size not being zero.
  if (elem_type->size() != 0)
    num_elements = type_info.size() / elem_type->size();
  array_type->Finalize(GetFlags(elem_id), index_type->type_id(), num_elements,
                       elem_type->type_id());
  return array_type;
}

TypePtr TypeCreator::ReadProcedure() {
  pdb::LeafProcedure type_info;
  if (!type_info.Initialize(stream_.get())) {
    LOG(ERROR) << "Unable to read type info record.";
    return nullptr;
  }

  return CreateFunctionType(type_info_enum_.type_id(),
                            type_info.body().calltype, type_info.body().rvtype,
                            kNoTypeId, type_info.body().arglist);
}

TypePtr TypeCreator::ReadMFunction() {
  pdb::LeafMFunction type_info;
  if (!type_info.Initialize(stream_.get())) {
    LOG(ERROR) << "Unable to read type info record.";
    return nullptr;
  }

  return CreateFunctionType(type_info_enum_.type_id(),
                            type_info.body().calltype, type_info.body().rvtype,
                            type_info.body().classtype,
                            type_info.body().arglist);
}

TypePtr TypeCreator::CreateFunctionType(TypeId type_id,
                                        uint8_t call_type,
                                        TypeId return_type_id,
                                        TypeId containing_class_id,
                                        TypeId arglist_id) {
  FunctionType::CallConvention call_convention =
      static_cast<FunctionType::CallConvention>(call_type);
  FunctionTypePtr function_type = new FunctionType(call_convention);

  if (!repository_->AddTypeWithId(function_type, type_id))
    return false;

  FunctionType::Arguments arglist;

  if (FindOrCreateType(return_type_id) == nullptr)
    return false;

  // If this is a member function parse the containing class.
  if (containing_class_id != kNoTypeId &&
      FindOrCreateType(containing_class_id) == nullptr) {
    return false;
  }

  // Parse the argument list and finish the names.
  if (!type_info_enum_.SeekRecord(arglist_id) || !ReadArglist(&arglist))
    return false;

  function_type->Finalize(
      FunctionType::ArgumentType(GetFlags(return_type_id),
                                 GetUnderlyingTypeId(return_type_id)),
      arglist, GetUnderlyingTypeId(containing_class_id));
  return function_type;
}

TypePtr TypeCreator::ReadBitfield() {
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

  TypeId underlying_id = type_info.body().type;
  TypePtr underlying_type = FindOrCreateType(underlying_id);
  if (underlying_type == nullptr)
    return nullptr;

  SaveTypeInfo(type_info_enum_.type_id(), underlying_type->type_id(),
               GetFlags(underlying_id));
  SaveBitfieldInfo(type_info_enum_.type_id(), type_info.body().position,
                   type_info.body().length);
  return underlying_type;
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
  if (FindOrCreateType(member_id) == nullptr)
    return false;

  fields->push_back(UserDefinedType::Field(
      member->name(), member->offset(), GetFlags(member_id),
      GetBitPosition(member_id), GetBitLength(member_id),
      GetUnderlyingTypeId(member_id)));
  return true;
}

bool TypeCreator::ProcessOneMethod(pdb::LeafOneMethod* method,
                                   UserDefinedType::Functions* functions) {
  DCHECK(method);
  DCHECK(functions);

  // Parse the function type.
  TypeId function_id = method->body().index;
  if (FindOrCreateType(function_id) == nullptr)
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
    if (FindOrCreateType(function_id) == nullptr)
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
      return L"LeafUnknown";
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

Type::Flags TypeCreator::GetFlags(TypeId type_id) {
  auto it = temp_stash_.find(type_id);
  if (it == temp_stash_.end()) {
    return kNoTypeFlags;
  } else {
    return it->second.flags;
  }
}

size_t TypeCreator::GetBitPosition(TypeId type_id) {
  auto it = temp_stash_.find(type_id);
  if (it == temp_stash_.end()) {
    return 0;
  } else {
    return it->second.bit_pos;
  }
}

size_t TypeCreator::GetBitLength(TypeId type_id) {
  auto it = temp_stash_.find(type_id);
  if (it == temp_stash_.end()) {
    return 0;
  } else {
    return it->second.bit_len;
  }
}

size_t TypeCreator::GetUnderlyingTypeId(TypeId type_id) {
  auto it = temp_stash_.find(type_id);
  if (it == temp_stash_.end()) {
    return type_id;
  } else {
    return it->second.type_id;
  }
}

cci::CV_prmode TypeCreator::TypeIndexToPrMode(TypeId type_id) {
  return static_cast<cci::CV_prmode>(
      (type_id & cci::CV_PRIMITIVE_TYPE::CV_MMASK) >>
      cci::CV_PRIMITIVE_TYPE::CV_MSHIFT);
}

TypePtr TypeCreator::CreateBasicType(TypeId type_id) {
  // Check if we are dealing with pointer.
  cci::CV_prmode prmode = TypeIndexToPrMode(type_id);
  if (prmode == cci::CV_TM_DIRECT) {
    BasicTypePtr basic_type =
        new BasicType(BasicTypeName(type_id), BasicTypeSize(type_id));

    // Save type and additional info.
    if (!repository_->AddTypeWithId(basic_type, type_id))
      return nullptr;
    return basic_type;
  } else {
    TypeId basic_index = type_id & (cci::CV_PRIMITIVE_TYPE::CV_TMASK |
                                    cci::CV_PRIMITIVE_TYPE::CV_SMASK);
    if (FindOrCreateType(basic_index) == nullptr)
      return nullptr;

    // Get pointer size.
    size_t size = 0;
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
    PointerTypePtr basic_type =
        new PointerType(size, PointerType::PTR_MODE_PTR);
    basic_type->Finalize(kNoTypeFlags, basic_index);

    if (!repository_->AddTypeWithId(basic_type, type_id))
      return nullptr;
    return basic_type;
  }
}

void TypeCreator::SaveTypeInfo(TypeId type_id,
                               TypeId underlying_id,
                               Type::Flags flags) {
  ExtraTypeProperties& prop = temp_stash_[type_id];
  prop.type_id = underlying_id;
  prop.flags = flags;
  prop.bit_pos = 0;
  prop.bit_len = 0;
}

void TypeCreator::SaveBitfieldInfo(TypeId type_id,
                                   size_t bit_pos,
                                   size_t bit_len) {
  ExtraTypeProperties& prop = temp_stash_[type_id];
  prop.bit_pos = bit_pos;
  prop.bit_len = bit_len;
}

TypePtr TypeCreator::FindOrCreateType(TypeId type_id) {
  TypePtr type = repository_->GetType(GetUnderlyingTypeId(type_id));
  if (type != nullptr)
    return type;

  // We need to create new type object.
  // Check if it is a regular type index.
  if (type_id >= type_info_enum_.type_info_header().type_min) {
    return CreateType(type_id);
  } else {
    // If it is a basic type, construct it.
    return CreateBasicType(type_id);
  }
}

TypePtr TypeCreator::CreateType(TypeId type_id) {
  if (!type_info_enum_.SeekRecord(type_id))
    return false;

  switch (type_info_enum_.type()) {
    case cci::LF_CLASS:
    case cci::LF_STRUCTURE: {
      return ReadClass();
    }
    case cci::LF_POINTER: {
      return ReadPointer();
    }
    case cci::LF_ARRAY: {
      return ReadArray();
    }
    case cci::LF_PROCEDURE: {
      return ReadProcedure();
    }
    case cci::LF_MFUNCTION: {
      return ReadMFunction();
    }
    case cci::LF_MODIFIER: {
      return ReadModifier();
    }
    case cci::LF_BITFIELD: {
      return ReadBitfield();
    }
    default: {
      // Default behavior is to create wildcard objects.
      // TODO(mopler): Parse everything and delete this stub.
      base::string16 name = LeafTypeName(type_info_enum_.type());
      TypePtr wildcard_type = new WildcardType(name, name, 0);
      if (!repository_->AddTypeWithId(wildcard_type, type_id))
        return nullptr;
      return wildcard_type;
    }
  }
}

bool TypeCreator::PrepareData() {
  while (!type_info_enum_.EndOfStream()) {
    if (!type_info_enum_.NextTypeInfoRecord())
      return false;

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
    if (FindOrCreateType(type_id) == nullptr)
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
