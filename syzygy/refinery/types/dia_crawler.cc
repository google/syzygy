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

#include "syzygy/refinery/types/dia_crawler.h"

#include <unordered_map>

#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/win/scoped_bstr.h"
#include "syzygy/pe/dia_util.h"
#include "syzygy/refinery/types/type_namer.h"
#include "syzygy/refinery/types/type_repository.h"

namespace refinery {

namespace {

bool GetSymFlags(IDiaSymbol* symbol, Type::Flags* flags) {
  DCHECK(symbol); DCHECK(flags);
  *flags = 0;

  bool is_const = false;
  bool is_volatile = false;
  if (!pe::GetSymQualifiers(symbol, &is_const, &is_volatile))
    return false;

  if (is_const)
    *flags |= UserDefinedType::FLAG_CONST;
  if (is_volatile)
    *flags |= UserDefinedType::FLAG_VOLATILE;

  return true;
}

bool GetSymSize(IDiaSymbol* symbol, size_t* size) {
  DCHECK(symbol); DCHECK(size);

  ULONGLONG length = 0;
  HRESULT hr = symbol->get_length(&length);
  if (hr != S_OK)
    return false;

  *size = static_cast<size_t>(length);
  return true;
}

bool GetSymBitPos(IDiaSymbol* symbol, size_t* bit_position) {
  DCHECK(symbol); DCHECK(bit_position);

  DWORD temp = 0;
  HRESULT hr = symbol->get_bitPosition(&temp);
  if (hr != S_OK)
    return false;

  *bit_position = static_cast<size_t>(temp);
  return true;
}

bool GetSymArrayIndexType(IDiaSymbol* symbol,
                          base::win::ScopedComPtr<IDiaSymbol>* type) {
  DCHECK(symbol);
  DCHECK(type);
  base::win::ScopedComPtr<IDiaSymbol> tmp;
  HRESULT hr = symbol->get_arrayIndexType(tmp.Receive());
  if (hr != S_OK)
    return false;

  *type = tmp;
  return true;
}

bool GetSymIndexId(IDiaSymbol* symbol, DWORD* index_id) {
  DCHECK(symbol); DCHECK(index_id);
  DWORD tmp = 0;
  HRESULT hr = symbol->get_symIndexId(&tmp);
  if (!SUCCEEDED(hr))
    return false;
  *index_id = tmp;
  return true;
}

bool GetSymPtrMode(IDiaSymbol* symbol, PointerType::Mode* is_reference) {
  DCHECK(symbol);
  DCHECK(is_reference);
  BOOL is_ref;
  HRESULT hr = symbol->get_reference(&is_ref);
  if (hr != S_OK)
    return false;
  *is_reference = PointerType::PTR_MODE_PTR;
  if (is_ref)
    *is_reference = PointerType::PTR_MODE_REF;
  return true;
}

bool GetSymCallingConvention(IDiaSymbol* symbol,
                             FunctionType::CallConvention* call_convention) {
  DCHECK(symbol);
  DCHECK(call_convention);
  DWORD tmp = 0;
  HRESULT hr = symbol->get_callingConvention(&tmp);
  if (!SUCCEEDED(hr))
    return false;
  *call_convention = static_cast<FunctionType::CallConvention>(tmp);
  return true;
}

bool GetSymUdtKind(IDiaSymbol* symbol, UserDefinedType::UdtKind* udt_kind) {
  DCHECK(symbol);
  DCHECK(udt_kind);
  DWORD cci_udt_kind;
  HRESULT hr = symbol->get_udtKind(&cci_udt_kind);
  if (hr != S_OK)
    return false;

  switch (cci_udt_kind) {
    case UdtStruct: {
      *udt_kind = UserDefinedType::UDT_STRUCT;
      break;
    }
    case UdtClass: {
      *udt_kind = UserDefinedType::UDT_CLASS;
      break;
    }
    case UdtUnion: {
      *udt_kind = UserDefinedType::UDT_UNION;
      break;
    }
    case UdtInterface: {
      NOTREACHED() << "Stumbled upon interface UDT kind which we don't expect.";
    }
  }

  return true;
}

class TypeCreator {
 public:
  explicit TypeCreator(TypeRepository* repository);

  // Crawls @p global, creates all types and assigns names to pointers.
  bool CreateTypes(IDiaSymbol* global);

 private:
  bool CreateTypesOfKind(enum SymTagEnum kind, IDiaSymbol* global);
  bool CreateGlobalDataTypes(IDiaSymbol* global);

  // Finds or creates the type corresponding to @p symbol.
  // The type will be registered by a unique name in @p existing_types_.
  TypePtr FindOrCreateType(IDiaSymbol* symbol);

  TypePtr CreateType(IDiaSymbol* symbol);
  TypePtr CreateUDT(IDiaSymbol* symbol);
  TypePtr CreateEnum(IDiaSymbol* symbol);
  TypePtr CreateFunctionType(IDiaSymbol* symbol);
  TypePtr CreateBaseType(IDiaSymbol* symbol);
  TypePtr CreatePointerType(IDiaSymbol* symbol);
  TypePtr CreateTypedefType(IDiaSymbol* symbol);
  TypePtr CreateArrayType(IDiaSymbol* symbol);

  TypePtr CreateGlobalType(IDiaSymbol* symbol,
                           const base::string16& name,
                           uint64_t rva);

  bool FinalizeUDT(IDiaSymbol* symbol, UserDefinedTypePtr udt);
  bool FinalizePointer(IDiaSymbol* symbol, PointerTypePtr ptr);
  bool FinalizeArray(IDiaSymbol* symbol, ArrayTypePtr type);
  bool FinalizeFunction(IDiaSymbol* symbol, FunctionTypePtr type);
  bool FinalizeType(IDiaSymbol* symbol, TypePtr type);

  struct CreatedType {
    CreatedType() : type_id(kNoTypeId), is_finalized(false) {
    }

    TypeId type_id;
    bool is_finalized;
  };
  typedef std::unordered_map<DWORD, CreatedType> CreatedTypeMap;

  // Maps from DIA symbol index ID to the created TypeId. Also keeps a flag
  // that's set when a type is finalized, as DIA has a nasty habit of
  // enumerating the same type multiple times.
  CreatedTypeMap created_types_;
  TypeRepository* repository_;
};

TypeCreator::TypeCreator(TypeRepository* repository)
    : repository_(repository) {
  DCHECK(repository);
}

bool TypeCreator::CreateTypesOfKind(enum SymTagEnum kind, IDiaSymbol* global) {
  base::win::ScopedComPtr<IDiaEnumSymbols> matching_types;
  HRESULT hr = global->findChildren(kind,
                                    nullptr,
                                    nsNone,
                                    matching_types.Receive());
  if (!SUCCEEDED(hr))
    return false;

  // The function get_Count from DIA has either a bug or is really badly
  // implemented thus taking forever to finish. Therefore we simply load next
  // symbol until reaching the end.
  base::win::ScopedComPtr<IDiaSymbol> symbol;
  ULONG received = 0;
  hr = matching_types->Next(1, symbol.Receive(), &received);

  while (hr == S_OK) {
    scoped_refptr<Type> type = FindOrCreateType(symbol.get());
    if (!type)
      return false;

    if (!FinalizeType(symbol.get(), type))
      return false;

    symbol.Release();
    received = 0;
    hr = matching_types->Next(1, symbol.Receive(), &received);
  }

  if (!SUCCEEDED(hr))
    return false;

  return true;
}

bool TypeCreator::CreateGlobalDataTypes(IDiaSymbol* global) {
  base::win::ScopedComPtr<IDiaEnumSymbols> matching_types;
  HRESULT hr = global->findChildren(SymTagData, nullptr, nsNone,
                                    matching_types.Receive());
  if (!SUCCEEDED(hr))
    return false;

  ULONG received = 0;
  while (true) {
    base::win::ScopedComPtr<IDiaSymbol> symbol;
    hr = matching_types->Next(1, symbol.Receive(), &received);
    if (hr != S_OK)
      break;

    // Filter here for symbols that have all the required properties.
    LocationType location_type = LocIsNull;
    DataKind data_kind = DataIsUnknown;
    if (!pe::GetLocationType(symbol.get(), &location_type))
      return false;
    if (location_type != LocIsStatic)
      continue;

    if (!pe::GetDataKind(symbol.get(), &data_kind))
      return false;

    switch (data_kind) {
      case DataIsUnknown:
      case DataIsLocal:
      case DataIsParam:
      case DataIsObjectPtr:
      case DataIsMember:
      case DataIsStaticMember:
      case DataIsConstant:
        continue;

      case DataIsStaticLocal:
      case DataIsFileStatic:
      case DataIsGlobal:
        // This data should have an RVA.
        break;
    }

    base::string16 name;
    if (!pe::GetSymName(symbol.get(), &name))
      return false;

    DWORD rva = 0;
    HRESULT hr = symbol->get_relativeVirtualAddress(&rva);
    if (hr != S_OK) {
      // This condition occurs for precisely two symbols that we've noticed.
      if (name == L"__safe_se_handler_count" ||
          name == L"__safe_se_handler_table") {
        continue;
      }

      // Make sure to err out for other cases for now.
      // TODO(siggi): Revisit this once the reason for this anomaly is
      //     understood.
      LOG(ERROR) << "Symbol " << name << " has no RVA!";
      return false;
    }

    // See whether the type has been created.
    DWORD index_id = 0;
    if (!GetSymIndexId(symbol.get(), &index_id))
      return false;

    auto it = created_types_.find(index_id);
    if (it != created_types_.end())
      continue;

    // Ok, we need to create it.
    TypePtr created = CreateGlobalType(symbol.get(), name, rva);
    DCHECK(created);
    CreatedType& entry = created_types_[index_id];
    entry.type_id = repository_->AddType(created);
    entry.is_finalized = false;

    if (!FinalizeType(symbol.get(), created))
      return false;
  }

  if (!SUCCEEDED(hr))
    return false;

  return true;
}

bool TypeCreator::FinalizeType(IDiaSymbol* symbol, TypePtr type) {
  // See whether this type needs finalizing.
  DWORD index_id = 0;
  if (!GetSymIndexId(symbol, &index_id))
    return false;

  DCHECK_EQ(type->type_id(), created_types_[index_id].type_id);
  if (created_types_[index_id].is_finalized) {
    // This is a re-visit of the same type. DIA has a nasty habit of doing
    // this, e.g. yielding the same type multiple times in an iteration.
    return true;
  }

  created_types_[index_id].is_finalized = true;

  switch (type->kind()) {
    case Type::USER_DEFINED_TYPE_KIND: {
      UserDefinedTypePtr udt;
      if (!type->CastTo(&udt))
        return false;

      return FinalizeUDT(symbol, udt);
    }

    case Type::POINTER_TYPE_KIND: {
      PointerTypePtr ptr;
      if (!type->CastTo(&ptr))
        return false;

      return FinalizePointer(symbol, ptr);
    }

    case Type::ARRAY_TYPE_KIND: {
      ArrayTypePtr array;
      if (!type->CastTo(&array))
        return false;

      return FinalizeArray(symbol, array);
    }

    case Type::FUNCTION_TYPE_KIND: {
      FunctionTypePtr function;
      if (!type->CastTo(&function))
        return false;

      return FinalizeFunction(symbol, function);
    }

    default:
      return true;
  }
}

bool TypeCreator::CreateTypes(IDiaSymbol* global) {
  if (!CreateTypesOfKind(SymTagUDT, global) ||
      !CreateTypesOfKind(SymTagEnum, global) ||
      !CreateTypesOfKind(SymTagTypedef, global) ||
      !CreateTypesOfKind(SymTagPointerType, global) ||
      !CreateTypesOfKind(SymTagArrayType, global) ||
      !CreateTypesOfKind(SymTagFunctionType, global) ||
      !CreateGlobalDataTypes(global)) {
    return false;
  }

  return true;
}

TypePtr TypeCreator::FindOrCreateType(IDiaSymbol* symbol) {
  DCHECK(symbol);

  DWORD index_id = 0;
  if (!GetSymIndexId(symbol, &index_id))
    return false;

  auto it = created_types_.find(index_id);
  if (it != created_types_.end())
    return repository_->GetType(it->second.type_id);

  // Note that this will recurse on pointer types, but the recursion should
  // terminate on a basic type or a UDT at some point - assuming the type
  // graph is sane.
  // TODO(siggi): It'd be better never to recurse, and this can be avoided for
  //    pointers by doing two-phase construction on them as for UDTs. To assign
  //    unique, human-readable names to pointers requires another pass yet.
  TypePtr created = CreateType(symbol);
  DCHECK(created);
  CreatedType& entry = created_types_[index_id];
  entry.type_id = repository_->AddType(created);
  entry.is_finalized = false;

  // Pointers to base types will not get enumerated by DIA and therefore need to
  // be finalized manually. We do so here.
  if (created->kind() == Type::POINTER_TYPE_KIND) {
    base::win::ScopedComPtr<IDiaSymbol> contained_type_sym;
    if (!pe::GetSymType(symbol, &contained_type_sym))
      return nullptr;
    enum SymTagEnum contained_sym_tag = SymTagNull;
    if (!pe::GetSymTag(contained_type_sym.get(), &contained_sym_tag))
      return nullptr;
    if (contained_sym_tag == SymTagBaseType) {
      if (!FinalizeType(symbol, created))
        return nullptr;
    }
  }

  return created;
}

TypePtr TypeCreator::CreateType(IDiaSymbol* symbol) {
  DCHECK(symbol);

  enum SymTagEnum sym_tag = SymTagNull;
  if (!pe::GetSymTag(symbol, &sym_tag))
    return nullptr;

  switch (sym_tag) {
    case SymTagUDT:
      return CreateUDT(symbol);
    case SymTagEnum:
      return CreateEnum(symbol);
    case SymTagBaseType:
      return CreateBaseType(symbol);
    case SymTagFunctionType:
      return CreateFunctionType(symbol);
    case SymTagPointerType:
      return CreatePointerType(symbol);
    case SymTagTypedef:
      return CreateTypedefType(symbol);
    case SymTagArrayType:
      return CreateArrayType(symbol);
    case SymTagVTableShape:
      return new WildcardType(L"VTableShape", 0);
    case SymTagVTable:
      return new WildcardType(L"VTable", 0);
    default:
      return nullptr;
  }
}

TypePtr TypeCreator::CreateUDT(IDiaSymbol* symbol) {
  DCHECK(symbol);
  DCHECK(pe::IsSymTag(symbol, SymTagUDT));

  base::string16 name;
  size_t size = 0;
  UserDefinedType::UdtKind udt_kind;
  if (!pe::GetSymName(symbol, &name) || !GetSymSize(symbol, &size) ||
      !GetSymUdtKind(symbol, &udt_kind)) {
    return nullptr;
  }

  return new UserDefinedType(name, size, udt_kind);
}

TypePtr TypeCreator::CreateEnum(IDiaSymbol* symbol) {
  DCHECK(symbol);
  DCHECK(pe::IsSymTag(symbol, SymTagEnum));

  base::string16 name;
  size_t size = 0;
  if (!pe::GetSymName(symbol, &name) || !GetSymSize(symbol, &size))
    return nullptr;

  // TODO(siggi): Implement an enum type.
  return new WildcardType(name, size);
}

bool TypeCreator::FinalizeUDT(IDiaSymbol* symbol, UserDefinedTypePtr udt) {
  DCHECK(symbol);
  DCHECK(udt);
  DCHECK(pe::IsSymTag(symbol, SymTagUDT));

  // Enumerate the fields and add them.
  base::win::ScopedComPtr<IDiaEnumSymbols> enum_children;
  HRESULT hr = symbol->findChildren(
      SymTagNull, NULL, nsNone, enum_children.Receive());
  if (!SUCCEEDED(hr))
    return false;

  LONG count = 0;
  hr = enum_children->get_Count(&count);
  if (!SUCCEEDED(hr))
    return false;

  UserDefinedType::Fields fields;
  UserDefinedType::Functions functions;
  for (LONG i = 0; i < count; ++i) {
    base::win::ScopedComPtr<IDiaSymbol> field_sym;
    hr = enum_children->Item(i, field_sym.Receive());
    if (!SUCCEEDED(hr))
      return false;

    enum SymTagEnum sym_tag = SymTagNull;
    if (!pe::GetSymTag(field_sym.get(), &sym_tag))
      return false;

    // We only care about data and functions.
    if (sym_tag == SymTagData) {
      // TODO(siggi): Also process VTables?
      DataKind data_kind = DataIsUnknown;
      if (!pe::GetDataKind(field_sym.get(), &data_kind))
        return false;
      // We only care about member data.
      if (data_kind != DataIsMember)
        continue;

      // The location udt and the symbol udt are a little conflated in the case
      // of bitfields. For bitfieds, the bit length and bit offset of the udt
      // are stored against the data symbol, and not its udt.
      LocationType loc_type = LocIsNull;
      if (!pe::GetLocationType(field_sym.get(), &loc_type))
        return false;
      DCHECK(loc_type == LocIsThisRel || loc_type == LocIsBitField);

      base::win::ScopedComPtr<IDiaSymbol> field_type_sym;
      base::string16 field_name;
      ptrdiff_t field_offset = 0;
      size_t field_size = 0;
      Type::Flags field_flags = 0;
      if (!pe::GetSymType(field_sym.get(), &field_type_sym) ||
          !pe::GetSymName(field_sym.get(), &field_name) ||
          !pe::GetSymOffset(field_sym.get(), &field_offset) ||
          !GetSymSize(field_type_sym.get(), &field_size) ||
          !GetSymFlags(field_type_sym.get(), &field_flags)) {
        return false;
      }

      TypePtr field_type;
      field_type = FindOrCreateType(field_type_sym.get());
      size_t bit_length = 0;
      size_t bit_pos = 0;
      if (loc_type == LocIsBitField) {
        // For bitfields we need the bit size and length.
        if (!GetSymSize(field_sym.get(), &bit_length) ||
            !GetSymBitPos(field_sym.get(), &bit_pos)) {
          return false;
        }
      } else if (loc_type != LocIsThisRel) {
        NOTREACHED() << "Impossible location udt!";
      }

      fields.push_back(new UserDefinedType::MemberField(
          field_name, field_offset, field_flags, bit_pos, bit_length,
          field_type->type_id(), repository_));
    } else if (sym_tag == SymTagFunction) {
      base::win::ScopedComPtr<IDiaSymbol> function_type_sym;
      base::string16 function_name;

      if (!pe::GetSymType(field_sym.get(), &function_type_sym) ||
          !pe::GetSymName(field_sym.get(), &function_name)) {
        return false;
      }

      TypePtr function_type;
      function_type = FindOrCreateType(function_type_sym.get());
      if (!function_type)
        return false;

      functions.push_back(
          UserDefinedType::Function(function_name, function_type->type_id()));
    }
  }

  DCHECK_EQ(0UL, udt->fields().size());
  DCHECK_EQ(0UL, udt->functions().size());
  udt->Finalize(&fields, &functions);
  return true;
}

bool TypeCreator::FinalizePointer(IDiaSymbol* symbol, PointerTypePtr ptr) {
  DCHECK(symbol);
  DCHECK(ptr);
  DCHECK(pe::IsSymTag(symbol, SymTagPointerType));

  base::win::ScopedComPtr<IDiaSymbol> contained_type_sym;
  if (!pe::GetSymType(symbol, &contained_type_sym))
    return false;

  Type::Flags flags = 0;
  if (!GetSymFlags(contained_type_sym.get(), &flags))
    return false;

  TypePtr contained_type = FindOrCreateType(contained_type_sym.get());
  if (!contained_type)
    return false;

  ptr->Finalize(flags, contained_type->type_id());
  return true;
}

bool TypeCreator::FinalizeArray(IDiaSymbol* symbol, ArrayTypePtr array) {
  DCHECK(symbol);
  DCHECK(array);
  DCHECK(pe::IsSymTag(symbol, SymTagArrayType));

  base::win::ScopedComPtr<IDiaSymbol> index_type_sym;
  if (!GetSymArrayIndexType(symbol, &index_type_sym))
    return false;

  size_t element_count = 0;
  if (!pe::GetSymCount(symbol, &element_count))
    return false;

  base::win::ScopedComPtr<IDiaSymbol> element_type_sym;
  if (!pe::GetSymType(symbol, &element_type_sym))
    return false;

  Type::Flags flags = 0;
  if (!GetSymFlags(element_type_sym.get(), &flags))
    return false;

  TypePtr index_type = FindOrCreateType(index_type_sym.get());
  if (!index_type)
    return false;
  TypePtr element_type = FindOrCreateType(element_type_sym.get());
  if (!element_type)
    return false;

  array->Finalize(flags, index_type->type_id(), element_count,
                  element_type->type_id());
  return true;
}

bool TypeCreator::FinalizeFunction(IDiaSymbol* symbol,
                                   FunctionTypePtr function) {
  DCHECK(symbol);
  DCHECK(function);
  DCHECK(pe::IsSymTag(symbol, SymTagFunctionType));

  // Determine the return type.
  base::win::ScopedComPtr<IDiaSymbol> return_type_sym;
  if (!pe::GetSymType(symbol, &return_type_sym))
    return false;

  Type::Flags return_flags = 0;
  if (!GetSymFlags(return_type_sym.get(), &return_flags))
    return false;

  TypePtr return_type = FindOrCreateType(return_type_sym.get());
  if (!return_type)
    return false;

  // Determine the containing class, if any.
  TypeId containing_class_id = kNoTypeId;
  base::win::ScopedComPtr<IDiaSymbol> parent_type_sym;
  if (!pe::GetSymClassParent(symbol, &parent_type_sym))
    return false;
  if (parent_type_sym.get() != nullptr) {
    TypePtr parent_type = FindOrCreateType(parent_type_sym.get());
    if (!parent_type)
      return false;
    containing_class_id = parent_type->type_id();
  }

  // Process arguments.
  base::win::ScopedComPtr<IDiaEnumSymbols> argument_types;
  HRESULT hr = symbol->findChildren(SymTagFunctionArgType, nullptr, nsNone,
                                    argument_types.Receive());
  if (!SUCCEEDED(hr))
    return false;

  base::win::ScopedComPtr<IDiaSymbol> arg_sym;
  ULONG received = 0;
  hr = argument_types->Next(1, arg_sym.Receive(), &received);

  FunctionType::Arguments args;
  while (hr == S_OK) {
    base::win::ScopedComPtr<IDiaSymbol> arg_type_sym;
    if (!pe::GetSymType(arg_sym.get(), &arg_type_sym))
      return false;

    TypePtr arg_type = FindOrCreateType(arg_type_sym.get());
    if (!arg_type)
      return false;

    Type::Flags arg_flags = 0;
    if (!GetSymFlags(arg_type_sym.get(), &arg_flags))
      return false;

    args.push_back(FunctionType::ArgumentType(arg_flags, arg_type->type_id()));

    arg_sym.Release();
    received = 0;
    hr = argument_types->Next(1, arg_sym.Receive(), &received);
  }

  if (!SUCCEEDED(hr))
    return false;

  function->Finalize(
      FunctionType::ArgumentType(return_flags, return_type->type_id()), args,
      containing_class_id);
  return true;
}

TypePtr TypeCreator::CreateBaseType(IDiaSymbol* symbol) {
  // Note that the void base type has zero size.
  DCHECK(symbol);
  DCHECK(pe::IsSymTag(symbol, SymTagBaseType));

  base::string16 base_type_name;
  size_t size = 0;
  if (!GetSymBaseTypeName(symbol, &base_type_name) ||
      !GetSymSize(symbol, &size)) {
    return nullptr;
  }

  return new BasicType(base_type_name, size);
}

TypePtr TypeCreator::CreateFunctionType(IDiaSymbol* symbol) {
  DCHECK(symbol);
  DCHECK(pe::IsSymTag(symbol, SymTagFunctionType));

  FunctionType::CallConvention call_convention;

  if (!GetSymCallingConvention(symbol, &call_convention))
    return nullptr;

  return new FunctionType(call_convention);
}

TypePtr TypeCreator::CreatePointerType(IDiaSymbol* symbol) {
  // Note that the void base type has zero size.
  DCHECK(symbol);
  DCHECK(pe::IsSymTag(symbol, SymTagPointerType));

  size_t size = 0;
  PointerType::Mode ptr_mode = PointerType::PTR_MODE_PTR;
  if (!GetSymSize(symbol, &size) || !GetSymPtrMode(symbol, &ptr_mode))
    return nullptr;

  return new PointerType(size, ptr_mode);
}

TypePtr TypeCreator::CreateTypedefType(IDiaSymbol* symbol) {
  DCHECK(symbol);
  DCHECK(pe::IsSymTag(symbol, SymTagTypedef));

  base::string16 name;
  if (!pe::GetSymName(symbol, &name))
    return nullptr;

  // TODO(siggi): Implement a typedef type.
  return new WildcardType(name, 0);
}

TypePtr TypeCreator::CreateArrayType(IDiaSymbol* symbol) {
  DCHECK(symbol);
  DCHECK(pe::IsSymTag(symbol, SymTagArrayType));

  size_t size = 0;
  if (!GetSymSize(symbol, &size)) {
    return nullptr;
  }

  return new ArrayType(size);
}

TypePtr TypeCreator::CreateGlobalType(IDiaSymbol* symbol,
                                      const base::string16& name,
                                      uint64_t rva) {
  DCHECK(symbol);
  DCHECK(pe::IsSymTag(symbol, SymTagData));

  base::win::ScopedComPtr<IDiaSymbol> global_type;
  if (!pe::GetSymType(symbol, &global_type))
    return nullptr;

  TypePtr type = FindOrCreateType(global_type.get());
  if (!type)
    return false;

  return new GlobalType(name, rva, type->type_id(), type->size());
}

}  // namespace

DiaCrawler::DiaCrawler() {
}

DiaCrawler::~DiaCrawler() {
}

bool DiaCrawler::InitializeForFile(const base::FilePath& path) {
  base::win::ScopedComPtr<IDiaDataSource> source;
  if (!pe::CreateDiaSource(source.Receive()))
    return false;

  base::win::ScopedComPtr<IDiaSession> session;
  if (!pe::CreateDiaSession(path, source.get(), session.Receive()))
    return false;

  return InitializeForSession(source, session);
}

bool DiaCrawler::InitializeForSession(
    base::win::ScopedComPtr<IDiaDataSource> source,
    base::win::ScopedComPtr<IDiaSession> session) {
  DCHECK(source.get()); DCHECK(session.get());

  HRESULT hr = session->get_globalScope(global_.Receive());
  if (!SUCCEEDED(hr) || !global_)
    return false;

  source_ = source;
  session_ = session;

  return true;
}

bool DiaCrawler::GetTypes(TypeRepository* types) {
  DCHECK(types); DCHECK(global_);

  // For each type in the PDB:
  //   Create a unique name for the type.
  //   Find or create the type by its unique name.
  //   Finalize the type, e.g.
  //     For each relevant "child" of the type.
  //       Create a unique name for the child.
  //       Find or create the child by its unique name.
  TypeCreator creator(types);

  return creator.CreateTypes(global_.get());
}

bool DiaCrawler::GetVFTableRVAs(base::hash_set<RelativeAddress>* vftable_rvas) {
  DCHECK(vftable_rvas); DCHECK(global_);
  vftable_rvas->clear();

  // VFTables are represented as public symbols. Note: we search through all
  // public symbols as we match on the undecorated name, not on the name.
  base::win::ScopedComPtr<IDiaEnumSymbols> public_symbols;
  HRESULT hr = global_->findChildren(SymTagPublicSymbol, nullptr, nsNone,
                                     public_symbols.Receive());
  if (!SUCCEEDED(hr))
    return false;

  // Note: the function get_Count from DIA has either a bug or is really badly
  // implemented thus taking forever to finish. Therefore we simply load next
  // symbol until reaching the end. Unfortunately, this also means we don't use
  // it for reserving the container's size.
  base::win::ScopedComPtr<IDiaSymbol> symbol;
  ULONG received = 0;
  hr = public_symbols->Next(1, symbol.Receive(), &received);

  while (hr == S_OK) {
    base::string16 undecorated_name;
    if (!pe::GetSymUndecoratedName(symbol.get(), &undecorated_name))
      return false;  // Public symbols are expected to have names.

    // Vftable names should look like:
    //     const std::Foo::`vftable'
    //     const testing::Foo::`vftable'{for `testing::Foo'}
    if (undecorated_name.find(L"::`vftable'") != base::string16::npos) {
      LocationType location_type = LocIsNull;
      if (!pe::GetLocationType(symbol.get(), &location_type))
        return false;
      if (location_type != LocIsStatic) {
        LOG(ERROR) << "Unexpected vftable location type: " << location_type;
        return false;
      }

      DWORD rva = 0U;
      HRESULT hr = symbol->get_relativeVirtualAddress(&rva);
      if (hr != S_OK) {
        LOG(ERROR) << "Unable to get vftable's RVA: " << common::LogHr(hr)
                   << ".";
        return false;
      }

      vftable_rvas->insert(static_cast<RelativeAddress>(rva));
    }

    symbol.Release();
    received = 0;
    hr = public_symbols->Next(1, symbol.Receive(), &received);
  }

  if (!SUCCEEDED(hr))
    return false;

  return true;
}

}  // namespace refinery
