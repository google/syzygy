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

#include "base/win/scoped_bstr.h"
#include "syzygy/pe/dia_util.h"

namespace refinery {

namespace {

bool GetSymBaseTypeName(IDiaSymbol* symbol, base::string16* type_name) {
  DWORD base_type = 0;
  HRESULT hr = symbol->get_baseType(&base_type);
  if (hr != S_OK)
    return false;

  // TODO(siggi): What to do for these basic type names?
  //     One idea is to standardize on stdint.h types?
  switch (base_type) {
    case btNoType:
      *type_name = L"btNoType";
      break;
    case btVoid:
      *type_name = L"btVoid";
      break;
    case btChar:
      *type_name = L"btChar";
      break;
    case btWChar:
      *type_name = L"btWChar";
      break;
    case btInt:
      *type_name = L"btInt";
      break;
    case btUInt:
      *type_name = L"btUInt";
      break;
    case btFloat:
      *type_name = L"btFloat";
      break;
    case btBCD:
      *type_name = L"btBCD";
      break;
    case btBool:
      *type_name = L"btBool";
      break;
    case btLong:
      *type_name = L"btLong";
      break;
    case btULong:
      *type_name = L"btULong";
      break;
    case btCurrency:
      *type_name = L"btCurrency";
      break;
    case btDate:
      *type_name = L"btDate";
      break;
    case btVariant:
      *type_name = L"btVariant";
      break;
    case btComplex:
      *type_name = L"btComplex";
      break;
    case btBit:
      *type_name = L"btBit";
      break;
    case btBSTR:
      *type_name = L"btBSTR";
      break;
    case btHresult:
      *type_name = L"btHresult";
      break;
    default:
      return false;
  }

  return true;
}

bool GetSymTag(IDiaSymbol* symbol, uint32_t* sym_tag) {
  DCHECK(symbol); DCHECK(sym_tag);

  DWORD tmp = 0;
  HRESULT hr = symbol->get_symTag(&tmp);
  if (hr != S_OK)
    return false;

  *sym_tag = static_cast<uint32_t>(tmp);
  return true;
}

bool IsSymTag(IDiaSymbol* symbol, enum SymTagEnum sym_tag) {
  DCHECK(symbol);

  uint32_t tag = SymTagNull;
  if (!GetSymTag(symbol, &tag))
    return false;

  return static_cast<enum SymTagEnum>(tag) == sym_tag;
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

// Fwd.
bool CreateType(IDiaSymbol* symbol, TypePtr* type);
bool CreateBitFieldType(IDiaSymbol* symbol,
                        size_t bit_length,
                        size_t bit_pos,
                        TypePtr* field_type);

bool CreateUDT(IDiaSymbol* symbol, size_t size, TypePtr* type) {
  DCHECK(symbol); DCHECK(size); DCHECK(type);
  DCHECK(IsSymTag(symbol, SymTagUDT));

  base::string16 name;
  Type::Flags flags = 0;
  if (!GetSymName(symbol, &name) ||
      !GetSymFlags(symbol, &flags)) {
    return false;
  }

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
  for (LONG i = 0; i < count; ++i) {
    base::win::ScopedComPtr<IDiaSymbol> field_sym;
    hr = enum_children->Item(i, field_sym.Receive());
    if (!SUCCEEDED(hr))
      return false;

    uint32_t sym_tag = 0;
    DataKind data_kind = DataIsUnknown;
    if (!GetSymTag(field_sym.get(), &sym_tag) ||
        !GetSymDataKind(field_sym.get(), &data_kind)) {
      return false;
    }

    // TODO(siggi): Also process VTables?
    if (sym_tag != SymTagData || data_kind != DataIsMember) {
      // The "children" of a UDT also include static data, function members,
      // etc.
      continue;
    }

    // The location type and the symbol type are a little conflated in the case
    // of bitfields. For bitfieds, the bit length and bit offset of the type
    // are stored against the data symbol, and not its type.
    uint32_t loc_type = LocIsNull;
    if (!GetSymLocType(field_sym.get(), &loc_type))
      return false;
    DCHECK(loc_type == LocIsThisRel || loc_type == LocIsBitField);

    base::win::ScopedComPtr<IDiaSymbol> field_type_sym;
    base::string16 field_name;
    ptrdiff_t field_offset = 0;
    size_t field_size = 0;
    if (!GetSymType(field_sym.get(), &field_type_sym) ||
        !GetSymName(field_sym.get(), &field_name) ||
        !GetSymOffset(field_sym.get(), &field_offset) ||
        !GetSymSize(field_type_sym.get(), &field_size)) {
      return false;
    }

    TypePtr field_type;
    if (loc_type == LocIsThisRel) {
      if (!CreateType(field_type_sym.get(), &field_type))
        return false;
    } else if (loc_type == LocIsBitField) {
      // For bitfields we need the bit size and length.
      size_t bit_length = 0;
      size_t bit_pos = 0;
      if (!GetSymSize(field_sym.get(), &bit_length) ||
          !GetSymBitPos(field_sym.get(), &bit_pos)) {
        return false;
      }

      if (!CreateBitFieldType(field_type_sym.get(),
                              bit_length, bit_pos, &field_type)) {
        return false;
      }
    } else {
      NOTREACHED() << "Impossible location type!";
    }

    fields.push_back(UserDefinedType::Field(field_name,
                                            field_offset,
                                            field_type));
  }
  // TODO(siggi): Does the kind of the UDT make a difference?
  //   E.g. struct, class, union, enum - perhaps?
  UserDefinedTypePtr udt = new UserDefinedType(name, size, flags, fields);

  *type = udt;
  return true;
}

bool CreateBaseType(IDiaSymbol* symbol, size_t size, TypePtr* type) {
  // Note that the void base type has zero size.
  DCHECK(symbol); DCHECK(type);
  DCHECK(IsSymTag(symbol, SymTagBaseType));

  base::string16 base_type_name;
  Type::Flags flags = 0;
  if (!GetSymBaseTypeName(symbol, &base_type_name) ||
      !GetSymFlags(symbol, &flags)) {
    return false;
  }

  *type = new BasicType(base_type_name, size, flags);

  return true;
}

bool CreatePointerType(IDiaSymbol* symbol, size_t size, TypePtr* type) {
  DCHECK(symbol); DCHECK(size), DCHECK(type);
  DCHECK(IsSymTag(symbol, SymTagPointerType));

  base::win::ScopedComPtr<IDiaSymbol> ptr_type_sym;
  Type::Flags flags = 0;
  if (!GetSymType(symbol, &ptr_type_sym) ||
      !GetSymFlags(symbol, &flags)) {
    return false;
  }

  TypePtr ptr_type;
  if (!CreateType(ptr_type_sym.get(), &ptr_type))
    return false;

  // TODO(siggi): Will pointers ever need a name? Maybe build a name by
  //    concatenation to the ptr_type->name()?
  *type = new PointerType(L"", size, flags, ptr_type);
  return true;
}

bool CreateType(IDiaSymbol* symbol, TypePtr* type) {
  DCHECK(symbol); DCHECK(type);

  size_t size = 0;
  uint32_t sym_tag = SymTagNull;
  if (!GetSymSize(symbol, &size) ||
      !GetSymTag(symbol, &sym_tag)) {
    // TODO(siggi): Log?
    return false;
  }

  switch (sym_tag) {
    case SymTagUDT:
      return CreateUDT(symbol, size, type);
    case SymTagBaseType:
      return CreateBaseType(symbol, size, type);
    case SymTagPointerType:
      return CreatePointerType(symbol, size, type);

    default:
      return false;
  }
}

bool CreateBitFieldType(IDiaSymbol* symbol,
                        size_t bit_length,
                        size_t bit_pos,
                        TypePtr* type_ptr) {
  DCHECK(symbol); DCHECK(type_ptr); DCHECK(IsSymTag(symbol, SymTagBaseType));
  size_t size = 0;
  base::string16 name;
  Type::Flags flags = 0;
  if (!GetSymSize(symbol, &size) ||
      !GetSymBaseTypeName(symbol, &name) ||
      !GetSymFlags(symbol, &flags)) {
    // TODO(siggi): Log?
    return false;
  }

  *type_ptr = new BitfieldType(name, size, flags, bit_length, bit_pos);
  return true;
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

bool DiaCrawler::GetTypes(const base::string16& regexp,
                          std::vector<TypePtr>* types) {
  DCHECK(types); DCHECK(global_);

  base::win::ScopedComPtr<IDiaEnumSymbols> matching_types;
  HRESULT hr = global_->findChildren(SymTagUDT,
                                     regexp.c_str(),
                                     nsCaseInRegularExpression,
                                     matching_types.Receive());
  if (!SUCCEEDED(hr))
    return false;

  LONG count = 0;
  hr = matching_types->get_Count(&count);
  if (!SUCCEEDED(hr) || count == 0)
    return false;

  for (LONG i = 0; i < count; ++i) {
    base::win::ScopedComPtr<IDiaSymbol> symbol;

    ULONG received = 0;
    hr = matching_types->Next(1, symbol.Receive(), &received);
    if (!SUCCEEDED(hr))
      return false;

    scoped_refptr<Type> type;
    if (!CreateType(symbol.get(), &type))
      return false;

    types->push_back(type);
  }

  return true;
}

}  // namespace refinery
