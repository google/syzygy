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

TypeNamer::TypeNamer(bool set_decorated_name)
    : set_decorated_name_(set_decorated_name) {
}

TypeNamer::~TypeNamer() {
}

bool TypeNamer::EnsureTypeName(TypePtr type) const {
  if (!type->name().empty())
    return true;

  switch (type->kind()) {
    case Type::POINTER_TYPE_KIND: {
      PointerTypePtr ptr;
      if (!type->CastTo(&ptr))
        return false;
      if (!AssignPointerName(ptr))
        return false;
      break;
    }
    case Type::ARRAY_TYPE_KIND: {
      ArrayTypePtr array;
      if (!type->CastTo(&array))
        return false;
      if (!AssignArrayName(array))
        return false;
      break;
    }
    case Type::FUNCTION_TYPE_KIND: {
      FunctionTypePtr function;
      if (!type->CastTo(&function))
        return false;
      if (!AssignFunctionName(function))
        return false;
      break;
    }
    case Type::USER_DEFINED_TYPE_KIND:
    case Type::BASIC_TYPE_KIND: {
      // These types should have their name set up.
      break;
    }
  }

  DCHECK_NE(L"", type->name());
  if (set_decorated_name_ && type->kind() != Type::BASIC_TYPE_KIND) {
    DCHECK_NE(L"", type->decorated_name());
  }

  return true;
}

bool TypeNamer::GetTypeName(IDiaSymbol* type, base::string16* type_name) {
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

bool TypeNamer::AssignPointerName(PointerTypePtr ptr) const {
  base::string16 name;
  base::string16 decorated_name;

  // Get the content type's name.
  TypePtr content_type = ptr->GetContentType();
  if (!content_type)
    return false;
  if (!EnsureTypeName(content_type))
    return false;
  name = content_type->name();
  if (set_decorated_name_)
    decorated_name = content_type->decorated_name();

  // Determine the suffix.
  bool is_ref = (ptr->ptr_mode() != PointerType::PTR_MODE_PTR);
  base::string16 suffix;
  GetPointerNameSuffix(ptr->is_const(), ptr->is_volatile(), is_ref, &suffix);

  // Set the name.
  name.append(suffix);
  ptr->SetName(name);
  if (set_decorated_name_) {
    decorated_name.append(suffix);
    ptr->SetDecoratedName(decorated_name);
  }

  return true;
}

bool TypeNamer::AssignArrayName(ArrayTypePtr array) const {
  base::string16 name;
  base::string16 decorated_name;

  TypePtr element_type = array->GetElementType();
  if (!element_type)
    return false;
  if (!EnsureTypeName(element_type))
    return false;
  name = element_type->name();
  if (set_decorated_name_)
    decorated_name = element_type->decorated_name();

  base::string16 suffix = GetCVMod(array->is_const(), array->is_volatile());
  base::StringAppendF(&suffix, L"[%d]", array->num_elements());

  name.append(suffix);
  array->SetName(name);
  if (set_decorated_name_) {
    decorated_name.append(suffix);
    array->SetDecoratedName(decorated_name);
  }

  return true;
}

bool TypeNamer::AssignFunctionName(FunctionTypePtr function) const {
  TypePtr return_type = function->GetReturnType();
  base::string16 name;
  base::string16 decorated_name;
  if (!return_type)
    return false;
  if (!EnsureTypeName(return_type))
    return false;
  name = return_type->name();
  if (set_decorated_name_)
    decorated_name = return_type->decorated_name();

  name.append(L" (");
  if (set_decorated_name_)
    decorated_name.append(L" (");

  if (function->IsMemberFunction()) {
    TypePtr class_type = function->GetContainingClassType();
    if (!class_type)
      return false;
    if (!EnsureTypeName(class_type))
      return false;
    name.append(class_type->name() + L"::)(");
    if (set_decorated_name_)
      decorated_name.append(class_type->decorated_name() + L"::)(");
  }

  // Get the argument types names.
  std::vector<base::string16> arg_names;
  std::vector<base::string16> arg_decorated_names;
  for (size_t i = 0; i < function->argument_types().size(); ++i) {
    TypePtr arg_type = function->GetArgumentType(i);
    if (!arg_type)
      return false;
    if (!EnsureTypeName(arg_type))
      return false;

    // Append the names, if the argument type is T_NOTYPE then this is a
    // C-style variadic function like printf and we append "..." instead.
    if (arg_type->type_id() == cci::T_NOTYPE) {
      arg_names.push_back(L"...");
      if (set_decorated_name_)
        arg_decorated_names.push_back(L"...");
    } else {
      const FunctionType::ArgumentType& arg = function->argument_types()[i];
      base::string16 CV_mods = GetCVMod(arg.is_const(), arg.is_volatile());
      arg_names.push_back(arg_type->name() + CV_mods);
      if (set_decorated_name_)
        arg_decorated_names.push_back(arg_type->decorated_name() + CV_mods);
    }
  }

  name.append(base::JoinString(arg_names, L", "));
  name.append(L")");
  function->SetName(name);
  if (set_decorated_name_) {
    decorated_name.append(base::JoinString(arg_decorated_names, L", "));
    decorated_name.append(L")");
    function->SetDecoratedName(decorated_name);
  }

  return true;
}

void TypeNamer::GetPointerNameSuffix(bool is_const,
                                     bool is_volatile,
                                     bool is_ref,
                                     base::string16* suffix) {
  DCHECK(suffix);

  *suffix = GetCVMod(is_const, is_volatile);
  if (is_ref)
    suffix->append(L"&");
  else
    suffix->append(L"*");
}

bool TypeNamer::GetPointerName(IDiaSymbol* type, base::string16* type_name) {
  base::string16 name;

  // Get the content type's name.
  base::win::ScopedComPtr<IDiaSymbol> content_type;
  if (!pe::GetSymType(type, &content_type))
    return false;
  if (!GetTypeName(content_type.get(), &name))
    return false;

  // Determine the suffix.
  bool is_const = false;
  bool is_volatile = false;
  if (!pe::GetSymQualifiers(content_type.get(), &is_const, &is_volatile))
    return false;
  BOOL is_ref;
  HRESULT hr = type->get_reference(&is_ref);
  if (hr != S_OK)
    return false;

  base::string16 suffix;
  GetPointerNameSuffix(is_const, is_volatile, is_ref == TRUE, &suffix);

  // Set the name.
  name.append(suffix);

  type_name->swap(name);
  return true;
}

bool TypeNamer::GetArrayName(IDiaSymbol* type, base::string16* type_name) {
  // TODO(manzagop): implement.
  *type_name = base::ASCIIToUTF16("<array-type>");
  return true;
}

bool TypeNamer::GetFunctionName(IDiaSymbol* type, base::string16* type_name) {
  // TODO(manzagop): implement.
  *type_name = base::ASCIIToUTF16("<function-type>");
  return true;
}

}  // namespace refinery
