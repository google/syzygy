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

#include "syzygy/refinery/types/type_namer.h"

#include <vector>

#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "syzygy/pe/dia_util.h"
#include "third_party/cci/files/cvinfo.h"

namespace refinery {

namespace {

namespace cci = Microsoft_Cci_Pdb;

base::string16 GetCVMod(bool is_const, bool is_volatile) {
  base::string16 suffix;
  if (is_const)
    suffix += L" const";
  if (is_volatile)
    suffix += L" volatile";
  return suffix;
}

void AppendPointerNameSuffix(bool is_const,
                             bool is_volatile,
                             bool is_ref,
                             base::string16* name) {
  DCHECK(name);

  name->append(GetCVMod(is_const, is_volatile));
  if (is_ref)
    name->append(L"&");
  else
    name->append(L"*");
}

void AppendArrayNameSuffix(bool is_const,
                           bool is_volatile,
                           size_t count,
                           base::string16* name) {
  DCHECK(name);
  name->append(GetCVMod(is_const, is_volatile));
  base::StringAppendF(name, L"[%d]", count);
}

}  // namespace

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

bool TypeNamer::GetName(ConstTypePtr type, base::string16* type_name) {
  return GetName(type, false, type_name);
}

bool TypeNamer::GetDecoratedName(ConstTypePtr type,
                                 base::string16* type_name) {
  return GetName(type, true, type_name);
}

bool TypeNamer::GetName(ConstTypePtr type,
                        bool decorated,
                        base::string16* type_name) {
  DCHECK(type);  DCHECK(type_name);
  type_name->clear();

  switch (type->kind()) {
    case Type::POINTER_TYPE_KIND: {
      ConstPointerTypePtr ptr;
      CHECK(type->CastTo(&ptr));
      return GetPointerName(ptr, decorated, type_name);
    }
    case Type::ARRAY_TYPE_KIND: {
      ConstArrayTypePtr array;
      CHECK(type->CastTo(&array));
      return GetArrayName(array, decorated, type_name);
    }
    case Type::FUNCTION_TYPE_KIND: {
      ConstFunctionTypePtr function;
      CHECK(type->CastTo(&function));
      return GetFunctionName(function, decorated, type_name);
    }
    case Type::USER_DEFINED_TYPE_KIND:
    case Type::BASIC_TYPE_KIND:
    case Type::GLOBAL_TYPE_KIND:
    case Type::WILDCARD_TYPE_KIND: {
      // These types should have their name set up.
      if (decorated)
        *type_name = type->GetDecoratedName();
      else
        *type_name = type->GetName();
      return true;
    }
    default:
      DCHECK(false);
      return false;
  }
}

bool TypeNamer::GetPointerName(ConstPointerTypePtr ptr,
                               bool decorated,
                               base::string16* type_name) {
  DCHECK(ptr);  DCHECK(type_name);
  type_name->clear();

  // Get the content type's name.
  ConstTypePtr content_type = ptr->GetContentType();
  if (!content_type)
    return false;
  if (!GetName(content_type, decorated, type_name))
    return false;

  // Append the suffix.
  bool is_ref = (ptr->ptr_mode() != PointerType::PTR_MODE_PTR);
  AppendPointerNameSuffix(ptr->is_const(), ptr->is_volatile(), is_ref,
                          type_name);

  return true;
}

bool TypeNamer::GetArrayName(ConstArrayTypePtr array,
                             bool decorated,
                             base::string16* type_name) {
  DCHECK(array);  DCHECK(type_name);
  type_name->clear();

  // Get the element type's name.
  ConstTypePtr element_type = array->GetElementType();
  if (!element_type)
    return false;
  if (!GetName(element_type, decorated, type_name))
    return false;

  // Append the suffix.
  AppendArrayNameSuffix(array->is_const(), array->is_volatile(),
                        array->num_elements(), type_name);
  return true;
}

bool TypeNamer::GetFunctionName(ConstFunctionTypePtr function,
                                bool decorated,
                                base::string16* type_name) {
  DCHECK(function);  DCHECK(type_name);
  type_name->clear();

  // Start with the return type.
  ConstTypePtr return_type = function->GetReturnType();
  if (!return_type)
    return false;
  if (!GetName(return_type, decorated, type_name))
    return false;

  // Append CV qualifiers.
  base::string16 suffix = GetCVMod(function->return_type().is_const(),
                                   function->return_type().is_volatile());
  suffix.append(L" (");
  type_name->append(suffix);

  // Continue with containing class.
  if (function->IsMemberFunction()) {
    ConstTypePtr class_type = function->GetContainingClassType();
    if (!class_type)
      return false;
    base::string16 class_name;
    if (!GetName(class_type, decorated, &class_name))
      return false;
    type_name->append(class_name + L"::)(");
  }

  // Get the argument types names.
  std::vector<base::string16> arg_names;
  for (size_t i = 0; i < function->argument_types().size(); ++i) {
    ConstTypePtr arg_type = function->GetArgumentType(i);
    if (!arg_type)
      return false;

    // Append the names, if the argument type is T_NOTYPE then this is a
    // C-style variadic function like printf and we append "..." instead.
    if (arg_type->type_id() == cci::T_NOTYPE) {
      arg_names.push_back(L"...");
    } else {
      arg_names.push_back(L"");

      if (!GetName(arg_type, decorated, &arg_names[i]))
        return false;

      const FunctionType::ArgumentType& arg = function->argument_types()[i];
      base::string16 CV_mods = GetCVMod(arg.is_const(), arg.is_volatile());

      arg_names[i].append(CV_mods);
    }
  }

  type_name->append(base::JoinString(arg_names, L", "));
  type_name->append(L")");

  return true;
}

bool DiaTypeNamer::GetTypeName(IDiaSymbol* type, base::string16* type_name) {
  DCHECK(type); DCHECK(type_name);

  enum SymTagEnum sym_tag_type = SymTagNull;
  if (!pe::GetSymTag(type, &sym_tag_type))
    return false;

  switch (sym_tag_type) {
    case SymTagUDT:
    case SymTagEnum:
    case SymTagTypedef:
    case SymTagData:
      return pe::GetSymName(type, type_name);
    case SymTagBaseType:
      return GetSymBaseTypeName(type, type_name);
    case SymTagPointerType:
      return GetPointerName(type, type_name);
    case SymTagArrayType:
      return GetArrayName(type, type_name);
    case SymTagFunctionType:
      return GetFunctionName(type, type_name);
    case SymTagVTableShape:
    case SymTagVTable:
    default:
      return false;
  }
}

bool DiaTypeNamer::GetPointerName(IDiaSymbol* type, base::string16* type_name) {
  DCHECK(type); DCHECK(type_name);
  DCHECK(pe::IsSymTag(type, SymTagPointerType));

  base::string16 name;

  // Get the content type's name.
  base::win::ScopedComPtr<IDiaSymbol> content_type;
  if (!pe::GetSymType(type, &content_type))
    return false;
  if (!GetTypeName(content_type.get(), &name))
    return false;

  // Append the suffix.
  bool is_const = false;
  bool is_volatile = false;
  if (!pe::GetSymQualifiers(content_type.get(), &is_const, &is_volatile))
    return false;
  BOOL is_ref;
  HRESULT hr = type->get_reference(&is_ref);
  if (hr != S_OK)
    return false;
  AppendPointerNameSuffix(is_const, is_volatile, is_ref == TRUE, &name);

  type_name->swap(name);
  return true;
}

bool DiaTypeNamer::GetArrayName(IDiaSymbol* type, base::string16* type_name) {
  DCHECK(type); DCHECK(type_name);
  DCHECK(pe::IsSymTag(type, SymTagArrayType));

  // Get the element type's name.
  base::win::ScopedComPtr<IDiaSymbol> element_type;
  if (!pe::GetSymType(type, &element_type))
    return false;
  base::string16 name;
  if (!GetTypeName(element_type.get(), &name))
    return false;

  // Determine the suffix.
  bool is_const = false;
  bool is_volatile = false;
  if (!pe::GetSymQualifiers(element_type.get(), &is_const, &is_volatile))
    return false;
  size_t element_count = 0;
  if (!pe::GetSymCount(type, &element_count))
    return false;
  AppendArrayNameSuffix(is_const, is_volatile, element_count, &name);

  // Set the name.
  type_name->swap(name);

  return true;
}

// TODO(manzagop): function type name should include function's CV qualifiers?
bool DiaTypeNamer::GetFunctionName(IDiaSymbol* type,
                                   base::string16* type_name) {
  DCHECK(type); DCHECK(type_name);
  DCHECK(pe::IsSymTag(type, SymTagFunctionType));

  // Start with the return type.
  base::win::ScopedComPtr<IDiaSymbol> return_type;
  if (!pe::GetSymType(type, &return_type))
    return false;
  base::string16 name;
  if (!GetTypeName(return_type.get(), &name))
    return false;

  bool is_const = false;
  bool is_volatile = false;
  if (!pe::GetSymQualifiers(return_type.get(), &is_const, &is_volatile))
    return false;
  name.append(GetCVMod(is_const, is_volatile));
  name.append(L" (");

  // Continue with containing class.
  base::win::ScopedComPtr<IDiaSymbol> parent_type_sym;
  if (!pe::GetSymClassParent(type, &parent_type_sym))
    return false;
  if (parent_type_sym.get() != nullptr) {
    base::string16 class_name;
    if (!GetTypeName(parent_type_sym.get(), &class_name))
      return false;
    name.append(class_name + L"::)(");
  }

  // Get the argument types names.
  size_t arg_count = 0;
  if (!pe::GetSymCount(type, &arg_count))
    return false;

  base::win::ScopedComPtr<IDiaEnumSymbols> argument_types;
  HRESULT hr = type->findChildren(SymTagFunctionArgType, nullptr, nsNone,
                                  argument_types.Receive());
  if (!SUCCEEDED(hr))
    return false;

  std::vector<base::string16> arg_names;
  base::win::ScopedComPtr<IDiaSymbol> arg_sym;
  ULONG received = 0;
  hr = argument_types->Next(1, arg_sym.Receive(), &received);
  while (hr == S_OK) {
    base::win::ScopedComPtr<IDiaSymbol> arg_type_sym;
    if (!pe::GetSymType(arg_sym.get(), &arg_type_sym))
      return false;

    // TODO(manzagop): look into how cci::T_NOTYPE fits in (C-style variadic
    // function).
    base::string16 arg_name;
    if (!GetTypeName(arg_type_sym.get(), &arg_name))
      return false;

    if (!pe::GetSymQualifiers(arg_type_sym.get(), &is_const, &is_volatile))
      return false;
    arg_name.append(GetCVMod(is_const, is_volatile));

    arg_names.push_back(arg_name);

    arg_sym.Release();
    received = 0;
    hr = argument_types->Next(1, arg_sym.Receive(), &received);
  }
  if (!SUCCEEDED(hr))
    return false;

  name.append(base::JoinString(arg_names, L", "));
  name.append(L")");

  type_name->swap(name);
  return true;
}

}  // namespace refinery
