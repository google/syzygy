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

#include <hash_map>

#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/win/scoped_bstr.h"
#include "syzygy/pe/dia_util.h"
#include "syzygy/refinery/types/type_repository.h"

namespace refinery {

namespace {

bool GetSymBaseTypeName(IDiaSymbol* symbol, base::string16* type_name) {
  DWORD base_type = 0;
  HRESULT hr = symbol->get_baseType(&base_type);
  if (hr != S_OK)
    return false;

  ULONGLONG length = 0;
  hr = symbol->get_length(&length);
  if (hr != S_OK)
    return false;

  // TODO(siggi): What to do for these basic type names?
  //     One idea is to standardize on stdint.h types?
  switch (base_type) {
    case btNoType:
      *type_name = L"btNoType";
      break;
    case btVoid:
      *type_name = L"void";
      break;
    case btChar:
      *type_name = L"char";
      break;
    case btWChar:
      *type_name = L"wchar_t";
      break;
    case btInt:
    case btLong: {
      switch (length) {
        case 1:
          *type_name = L"int8_t";
          break;
        case 2:
          *type_name = L"int16_t";
          break;
        case 4:
          *type_name = L"int32_t";
          break;
        case 8:
          *type_name = L"int64_t";
          break;

        default:
          return false;
      }
      break;
    }
    case btUInt:
    case btULong: {
      switch (length) {
        case 1:
          *type_name = L"uint8_t";
          break;
        case 2:
          *type_name = L"uint16_t";
          break;
        case 4:
          *type_name = L"uint32_t";
          break;
        case 8:
          *type_name = L"uint64_t";
          break;

        default:
          return false;
      }
      break;
    }

    case btFloat:
      *type_name = L"float";
      break;
    case btBCD:
      *type_name = L"BCD";
      break;
    case btBool:
      *type_name = L"bool";
      break;
    case btCurrency:
      *type_name = L"Currency";
      break;
    case btDate:
      *type_name = L"Date";
      break;
    case btVariant:
      *type_name = L"Variant";
      break;
    case btComplex:
      *type_name = L"Complex";
      break;
    case btBit:
      *type_name = L"Bit";
      break;
    case btBSTR:
      *type_name = L"BSTR";
      break;
    case btHresult:
      *type_name = L"HRESULT";
      break;
    default:
      return false;
  }

  return true;
}

bool GetSymFlags(IDiaSymbol* symbol, Type::Flags* flags) {
  DCHECK(symbol); DCHECK(flags);
  *flags = 0;
  BOOL is_const = FALSE;
  HRESULT hr = symbol->get_constType(&is_const);
  if (hr != S_OK)
    return false;

  BOOL is_volatile = FALSE;
  hr = symbol->get_volatileType(&is_volatile);
  if (hr != S_OK)
    return false;

  if (is_const)
    *flags |= UserDefinedType::FLAG_CONST;
  if (is_volatile)
    *flags |= UserDefinedType::FLAG_VOLATILE;

  return true;
}

bool GetSymLocType(IDiaSymbol* symbol, uint32_t* loc_type) {
  DCHECK(symbol); DCHECK(loc_type);

  DWORD temp = 0;
  HRESULT hr = symbol->get_locationType(&temp);
  if (hr != S_OK)
    return false;

  *loc_type = static_cast<uint32_t>(temp);
  return true;
}

bool GetSymName(IDiaSymbol* symbol, base::string16* name) {
  DCHECK(symbol); DCHECK(name);
  base::win::ScopedBstr tmp;
  HRESULT hr = symbol->get_name(tmp.Receive());
  if (hr != S_OK)
    return false;

  *name = tmp ? tmp : L"";
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

bool GetSymOffset(IDiaSymbol* symbol, ptrdiff_t* offset) {
  DCHECK(symbol); DCHECK(offset);

  LONG tmp = 0;
  HRESULT hr = symbol->get_offset(&tmp);
  if (hr != S_OK)
    return false;

  *offset = static_cast<ptrdiff_t>(tmp);
  return true;
}

bool GetSymDataKind(IDiaSymbol* symbol, DataKind* data_kind) {
  DCHECK(symbol); DCHECK(data_kind);

  DWORD tmp = 0;
  HRESULT hr = symbol->get_dataKind(&tmp);
  if (hr != S_OK)
    return false;

  *data_kind = static_cast<DataKind>(tmp);
  return true;
}

bool GetSymType(IDiaSymbol* symbol,
                base::win::ScopedComPtr<IDiaSymbol>* type) {
  DCHECK(symbol); DCHECK(type);
  base::win::ScopedComPtr<IDiaSymbol> tmp;
  HRESULT hr = symbol->get_type(tmp.Receive());
  if (hr != S_OK)
    return false;

  *type = tmp;
  return true;
}

bool GetSymClassParent(IDiaSymbol* symbol,
                       base::win::ScopedComPtr<IDiaSymbol>* type) {
  DCHECK(symbol);
  DCHECK(type);
  base::win::ScopedComPtr<IDiaSymbol> tmp;
  HRESULT hr = symbol->get_classParent(tmp.Receive());
  if (hr != S_OK)
    return false;

  *type = tmp;
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

bool GetSymCount(IDiaSymbol* symbol, size_t* count) {
  DCHECK(symbol);
  DCHECK(count);
  DWORD tmp = 0;
  HRESULT hr = symbol->get_count(&tmp);
  if (!SUCCEEDED(hr))
    return false;
  *count = tmp;
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

  // Assigns names to all pointer, array and function types that have been
  // created.
  bool AssignTypeNames();
  bool EnsureTypeName(TypePtr type);
  bool AssignPointerName(PointerTypePtr ptr);
  bool AssignArrayName(ArrayTypePtr array);
  bool AssignFunctionName(FunctionTypePtr function);

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
  typedef base::hash_map<DWORD, CreatedType> CreatedTypeMap;

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

bool TypeCreator::CreateTypesOfKind(enum SymTagEnum kind,
                                    IDiaSymbol* global) {
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
      !CreateTypesOfKind(SymTagFunctionType, global)) {
    return false;
  }

  return AssignTypeNames();
}

bool TypeCreator::AssignTypeNames() {
  for (auto type : *repository_) {
    if (!EnsureTypeName(type))
      return false;
  }

  return true;
}

bool TypeCreator::EnsureTypeName(TypePtr type) {
  if (type->kind() == Type::POINTER_TYPE_KIND && type->name().empty()) {
    PointerTypePtr ptr;
    if (!type->CastTo(&ptr))
      return false;

    if (!AssignPointerName(ptr))
      return false;
  } else if (type->kind() == Type::ARRAY_TYPE_KIND && type->name().empty()) {
    ArrayTypePtr array;
    if (!type->CastTo(&array))
      return false;

    if (!AssignArrayName(array))
      return false;
  } else if (type->kind() == Type::FUNCTION_TYPE_KIND && type->name().empty()) {
    FunctionTypePtr function;
    if (!type->CastTo(&function))
      return false;

    if (!AssignFunctionName(function))
      return false;
  }
  DCHECK_NE(L"", type->name());
  return true;
}

bool TypeCreator::AssignArrayName(ArrayTypePtr array) {
  TypePtr element_type = array->GetElementType();
  base::string16 name;
  if (element_type) {
    if (!EnsureTypeName(element_type))
      return false;
    name = element_type->name();
  }

  if (array->is_const())
    name.append(L" const");
  if (array->is_volatile())
    name.append(L" volatile");
  base::StringAppendF(&name, L"[%d]", array->num_elements());

  array->SetName(name);
  return true;
}

bool TypeCreator::AssignPointerName(PointerTypePtr ptr) {
  TypePtr content_type = ptr->GetContentType();
  base::string16 name;
  if (content_type) {
    if (!EnsureTypeName(content_type))
      return false;
    name = content_type->name();
  }

  if (ptr->is_const())
    name.append(L" const");
  if (ptr->is_volatile())
    name.append(L" volatile");

  if (ptr->ptr_mode() == PointerType::PTR_MODE_PTR) {
    name.append(L"*");
  } else {
    name.append(L"&");
  }

  ptr->SetName(name);
  return true;
}

bool TypeCreator::AssignFunctionName(FunctionTypePtr function) {
  TypePtr return_type = function->GetReturnType();
  base::string16 name;
  if (return_type) {
    if (!EnsureTypeName(return_type))
      return false;
    name = return_type->name();
  }

  name.append(L" (");

  TypePtr class_type = function->GetContainingClassType();
  if (class_type) {
    if (!EnsureTypeName(class_type))
      return false;
    name.append(class_type->name() + L"::)(");
  }

  // Get the argument types names.
  std::vector<base::string16> arg_names;
  for (size_t i = 0; i < function->argument_types().size(); ++i) {
    TypePtr arg_type = function->GetArgumentType(i);
    if (arg_type) {
      if (!EnsureTypeName(arg_type))
        return false;

      // Append the names, if the argument type is T_NOTYPE then this is a
      // C-style variadic function like printf and we append "..." instead.
      if (arg_type->name() == L"btNoType") {
        arg_names.push_back(L"...");
      } else {
        const FunctionType::ArgumentType& arg = function->argument_types()[i];
        base::string16 arg_name = arg_type->name();
        if (arg.is_const())
          arg_name.append(L" const");
        if (arg.is_volatile())
          arg_name.append(L" volatile");

        arg_names.push_back(arg_name);
      }
    }
  }

  name.append(base::JoinString(arg_names, L", "));
  name.append(L")");

  function->SetName(name);
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
  if (!GetSymName(symbol, &name) || !GetSymSize(symbol, &size) ||
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
  if (!GetSymName(symbol, &name) || !GetSymSize(symbol, &size))
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
      if (!GetSymDataKind(field_sym.get(), &data_kind))
        return false;
      // We only care about member data.
      if (data_kind != DataIsMember)
        continue;

      // The location udt and the symbol udt are a little conflated in the case
      // of bitfields. For bitfieds, the bit length and bit offset of the udt
      // are stored against the data symbol, and not its udt.
      uint32_t loc_type = LocIsNull;
      if (!GetSymLocType(field_sym.get(), &loc_type))
        return false;
      DCHECK(loc_type == LocIsThisRel || loc_type == LocIsBitField);

      base::win::ScopedComPtr<IDiaSymbol> field_type_sym;
      base::string16 field_name;
      ptrdiff_t field_offset = 0;
      size_t field_size = 0;
      Type::Flags field_flags = 0;
      if (!GetSymType(field_sym.get(), &field_type_sym) ||
          !GetSymName(field_sym.get(), &field_name) ||
          !GetSymOffset(field_sym.get(), &field_offset) ||
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

      fields.push_back(UserDefinedType::Field(field_name, field_offset,
                                              field_flags, bit_pos, bit_length,
                                              field_type->type_id()));
    } else if (sym_tag == SymTagFunction) {
      base::win::ScopedComPtr<IDiaSymbol> function_type_sym;
      base::string16 function_name;

      if (!GetSymType(field_sym.get(), &function_type_sym) ||
          !GetSymName(field_sym.get(), &function_name)) {
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
  udt->Finalize(fields, functions);
  return true;
}

bool TypeCreator::FinalizePointer(IDiaSymbol* symbol, PointerTypePtr ptr) {
  DCHECK(symbol);
  DCHECK(ptr);
  DCHECK(pe::IsSymTag(symbol, SymTagPointerType));

  base::win::ScopedComPtr<IDiaSymbol> contained_type_sym;
  if (!GetSymType(symbol, &contained_type_sym))
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
  if (!GetSymCount(symbol, &element_count))
    return false;

  base::win::ScopedComPtr<IDiaSymbol> element_type_sym;
  if (!GetSymType(symbol, &element_type_sym))
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

  base::win::ScopedComPtr<IDiaSymbol> return_type_sym;
  if (!GetSymType(symbol, &return_type_sym))
    return false;

  Type::Flags return_flags = 0;
  if (!GetSymFlags(return_type_sym.get(), &return_flags))
    return false;

  TypePtr return_type = FindOrCreateType(return_type_sym.get());
  if (!return_type)
    return false;

  TypeId containing_class_id = kNoTypeId;
  base::win::ScopedComPtr<IDiaSymbol> parent_type_sym;
  if (GetSymClassParent(symbol, &parent_type_sym)) {
    TypePtr parent_type = FindOrCreateType(parent_type_sym.get());
    if (!parent_type)
      return false;
    containing_class_id = parent_type->type_id();
  }

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
    if (!GetSymType(arg_sym.get(), &arg_type_sym))
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
  if (!GetSymName(symbol, &name))
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

}  // namespace refinery
