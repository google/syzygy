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

#include "syzygy/experimental/pdb_dumper/pdb_type_dump.h"

#include <algorithm>
#include <vector>

#include "base/logging.h"
#include "base/memory/ref_counted.h"
#include "syzygy/experimental/pdb_dumper/pdb_dump_util.h"
#include "syzygy/refinery/types/dia_crawler.h"
#include "syzygy/refinery/types/pdb_crawler.h"

namespace pdb {

namespace {

const char kUsage[] =
    "Usage: pdb_type_dump [options] <PDB file>...\n"
    "  Dumps information from type info stream in supplied PDB file as parsed\n"
    "  by PDB crawler.\n"
    "\n"
    "  Optional Options:\n"
    "    --dump-in-order if provided the types will be output ordered by\n"
    "       their type indices.\n"
    "    --dump-all-names if provided the names will be listed for all types\n"
    "       including function signatures which makes the output large.\n"
    "    --dump-with-dia if provided the types will be loaded with DIA.\n";

const char* GetTypeKindName(refinery::Type::TypeKind kind) {
  switch (kind) {
    case refinery::Type::USER_DEFINED_TYPE_KIND:
      return "USER_DEFINED_TYPE_KIND";
    case refinery::Type::BASIC_TYPE_KIND:
      return "BASIC_TYPE_KIND";
    case refinery::Type::POINTER_TYPE_KIND:
      return "POINTER_TYPE_KIND";
    case refinery::Type::FUNCTION_TYPE_KIND:
      return "FUNCTION_TYPE_KIND";
    case refinery::Type::ARRAY_TYPE_KIND:
      return "ARRAY_TYPE_KIND";
    case refinery::Type::WILDCARD_TYPE_KIND:
      return "WILDCARD_TYPE_KIND";
  }
  return "";
}

const char* GetUdtKindName(refinery::UserDefinedType::UdtKind kind) {
  switch (kind) {
    case refinery::UserDefinedType::UDT_CLASS:
      return "UDT_CLASS";
    case refinery::UserDefinedType::UDT_STRUCT:
      return "UDT_STRUCT";
    case refinery::UserDefinedType::UDT_UNION:
      return "UDT_UNION";
  }
  return "";
}

const char* GetCallConventionName(refinery::FunctionType::CallConvention call) {
  switch (call) {
    case refinery::FunctionType::CALL_NEAR_C:
      return "CALL_NEAR_C";
    case refinery::FunctionType::CALL_FAR_C:
      return "CALL_FAR_C";
    case refinery::FunctionType::CALL_NEAR_PASCAL:
      return "CALL_NEAR_PASCAL";
    case refinery::FunctionType::CALL_FAR_PASCAL:
      return "CALL_FAR_PASCAL";
    case refinery::FunctionType::CALL_NEAR_STDCALL:
      return "CALL_NEAR_STDCALL";
    case refinery::FunctionType::CALL_FAR_STDCALL:
      return "CALL_FAR_STDCALL";
    case refinery::FunctionType::CALL_THIS_CALL:
      return "CALL_THIS_CALL";
    case refinery::FunctionType::CALL_MIPS_CALL:
      return "CALL_MIPS_CALL";
    case refinery::FunctionType::CALL_GENERIC:
      return "CALL_GENERIC";
    case refinery::FunctionType::CALL_ALPHACALL:
      return "CALL_ALPHACALL";
    case refinery::FunctionType::CALL_PPCCALL:
      return "CALL_PPCCALL";
    case refinery::FunctionType::CALL_SHCALL:
      return "CALL_SHCALL";
    case refinery::FunctionType::CALL_ARMCALL:
      return "CALL_ARMCALL";
    case refinery::FunctionType::CALL_AM33CALL:
      return "CALL_AM33CALL";
    case refinery::FunctionType::CALL_TRICALL:
      return "CALL_TRICALL";
    case refinery::FunctionType::CALL_SH5CALL:
      return "CALL_SH5CALL";
    case refinery::FunctionType::CALL_M32RCALL:
      return "CALL_M32RCALL";
    case refinery::FunctionType::CALL_CLRCALL:
      return "CALL_CLRCALL";
  }
  return "";
}

}  // namespace

PdbTypeDumpApp::PdbTypeDumpApp()
    : application::AppImplBase("PDB Type Dumper"),
      dump_in_order_(false),
      dump_all_names_(false),
      dump_with_dia_(false) {
}

bool PdbTypeDumpApp::ParseCommandLine(const base::CommandLine* command_line) {
  DCHECK(command_line != nullptr);

  base::CommandLine::StringVector args = command_line->GetArgs();
  if (args.size() != 1U)
    return Usage("You must provide one input file.");

  pdb_path_ = base::FilePath(args[0]);
  dump_in_order_ = command_line->HasSwitch("dump-in-order");
  dump_all_names_ = command_line->HasSwitch("dump-all-names");
  dump_with_dia_ = command_line->HasSwitch("dump-with-dia");

  return true;
}

void PdbTypeDumpApp::DumpFlags(bool is_const,
                               bool is_volatile,
                               uint8_t indent_level) {
  if (is_const)
    DumpIndentedText(out(), indent_level, "is const.\n");
  if (is_volatile)
    DumpIndentedText(out(), indent_level, "is volatile.\n");
}

void PdbTypeDumpApp::DumpField(const refinery::UserDefinedType::Field& field,
                               uint8_t indent_level) {
  scoped_refptr<const refinery::UserDefinedType::MemberField> member;
  if (field.CastTo(&member)) {
    DumpMemberField(*member, indent_level);
    return;
  }

  DumpIndentedText(out(), indent_level, "Field (kind %d)\n", field.kind());
  DumpIndentedText(out(), indent_level + 1, "Offset: %d\n", field.offset());
  DumpIndentedText(out(), indent_level + 1, "Field type ID: %d\n",
                   field.type_id());
}

void PdbTypeDumpApp::DumpMemberField(
    const refinery::UserDefinedType::MemberField& member,
    uint8_t indent_level) {
  DumpIndentedText(out(), indent_level, "Member name: %S\n",
                   member.name().c_str());

  DumpIndentedText(out(), indent_level + 1, "Offset: %d\n", member.offset());
  DumpIndentedText(out(), indent_level + 1, "Properties:\n");
  DumpFlags(member.is_const(), member.is_volatile(), indent_level + 2);

  if (member.bit_len() != 0) {
    DumpIndentedText(out(), indent_level + 1, "Bit position: %d\n",
                     member.bit_pos());
    DumpIndentedText(out(), indent_level + 1, "Bit length: %d\n",
                     member.bit_len());
  }

  DumpIndentedText(out(), indent_level + 1, "Member type ID: %d\n",
                   member.type_id());
}

void PdbTypeDumpApp::DumpFunction(
    const refinery::UserDefinedType::Function& function,
    uint8_t indent_level) {
  DumpIndentedText(out(), indent_level, "Function name: %S\n",
                   function.name().c_str());
  DumpIndentedText(out(), indent_level + 1, "Function type ID: %d\n",
                   function.type_id());
}

void PdbTypeDumpApp::DumpArgument(refinery::FunctionType::ArgumentType argument,
                                  uint8_t indent_level) {
  DumpIndentedText(out(), indent_level, "Properties:\n");
  DumpFlags(argument.is_const(), argument.is_volatile(), indent_level + 1);
  DumpIndentedText(out(), indent_level, "Argument type ID: %d\n",
                   argument.type_id());
}

void PdbTypeDumpApp::DumpNames(refinery::TypePtr type, uint8_t indent_level) {
  DCHECK(type.get() != nullptr);

  DumpIndentedText(out(), indent_level, "Name: %S\n", type->GetName().c_str());
  DumpIndentedText(out(), indent_level, "Decorated name: %S\n",
                   type->GetDecoratedName().c_str());
}

void PdbTypeDumpApp::DumpBasicType(refinery::TypePtr type,
                                   uint8_t indent_level) {
  DCHECK(type.get() != nullptr);

  // Always print names of basic types.
  DumpNames(type, indent_level);
}

void PdbTypeDumpApp::DumpUserDefinedType(refinery::UserDefinedTypePtr type,
                                         uint8_t indent_level) {
  DCHECK(type.get() != nullptr);

  DumpIndentedText(out(), indent_level, "UDT kind: %s\n",
                   GetUdtKindName(type->udt_kind()));
  if (type->is_fwd_decl()) {
    DumpIndentedText(out(), indent_level,
                     "This is only forward declaration.\n");
  }

  DumpIndentedText(out(), indent_level, "%d member fields:\n",
                   type->fields().size());
  for (const auto& field : type->fields())
    DumpField(*field, indent_level + 1);

  DumpIndentedText(out(), indent_level, "%d member functions:\n",
                   type->functions().size());
  for (const auto& function : type->functions())
    DumpFunction(function, indent_level + 1);

  // Always print names of user defined types.
  DumpNames(type, indent_level);
}

void PdbTypeDumpApp::DumpArrayType(refinery::ArrayTypePtr type,
                                   uint8_t indent_level) {
  DCHECK(type.get() != nullptr);

  DumpIndentedText(out(), indent_level, "Properties:\n");
  DumpFlags(type->is_const(), type->is_volatile(), indent_level + 1);

  DumpIndentedText(out(), indent_level, "Number of elements: %d\n",
                   type->num_elements());
  DumpIndentedText(out(), indent_level, "Index type ID: %d\n",
                   type->index_type_id());
  DumpIndentedText(out(), indent_level, "Element type ID: %d\n",
                   type->element_type_id());

  if (dump_all_names_)
    DumpNames(type, indent_level);
}

void PdbTypeDumpApp::DumpPointerType(refinery::PointerTypePtr type,
                                     uint8_t indent_level) {
  DCHECK(type.get() != nullptr);

  DumpIndentedText(out(), indent_level, "Properties:\n");

  if (type->ptr_mode() == refinery::PointerType::PTR_MODE_REF)
    DumpIndentedText(out(), indent_level + 1, "is a reference.\n");

  DumpFlags(type->is_const(), type->is_volatile(), indent_level + 1);

  DumpIndentedText(out(), indent_level + 1, "Content type ID: %d\n",
                   type->content_type_id());

  if (dump_all_names_)
    DumpNames(type, indent_level);
}

void PdbTypeDumpApp::DumpFunctionType(refinery::FunctionTypePtr type,
                                      uint8_t indent_level) {
  DCHECK(type.get() != nullptr);

  DumpIndentedText(out(), indent_level, "Call convention: %s\n",
                   GetCallConventionName(type->call_convention()));

  if (type->IsMemberFunction()) {
    DumpIndentedText(out(), indent_level, "This is a member function.\n");
    DumpIndentedText(out(), indent_level + 1, "Containing class type ID: %d\n",
                     type->containing_class_id());
  }

  DumpIndentedText(out(), indent_level, "Return type:\n");
  DumpArgument(type->return_type(), indent_level + 1);

  DumpIndentedText(out(), indent_level, "%d arguments:\n",
                   type->argument_types().size());
  for (const auto& arg : type->argument_types())
    DumpArgument(arg, indent_level + 1);

  if (dump_all_names_)
    DumpNames(type, indent_level);
}

void PdbTypeDumpApp::DumpType(refinery::TypePtr type, uint8_t indent_level) {
  DCHECK(type.get() != nullptr);

  // Dump common properties.
  DumpIndentedText(out(), indent_level, "Type ID %d:\n", type->type_id());
  DumpIndentedText(out(), indent_level + 1, "Type kind: %s\n",
                   GetTypeKindName(type->kind()));
  DumpIndentedText(out(), indent_level + 1, "Size: %d\n", type->size());

  switch (type->kind()) {
    case refinery::Type::USER_DEFINED_TYPE_KIND: {
      refinery::UserDefinedTypePtr udt;
      type->CastTo(&udt);
      DumpUserDefinedType(udt, indent_level + 1);
      break;
    }
    case refinery::Type::ARRAY_TYPE_KIND: {
      refinery::ArrayTypePtr array_type;
      type->CastTo(&array_type);
      DumpArrayType(array_type, indent_level + 1);
      break;
    }
    case refinery::Type::POINTER_TYPE_KIND: {
      refinery::PointerTypePtr ptr_type;
      type->CastTo(&ptr_type);
      DumpPointerType(ptr_type, indent_level + 1);
      break;
    }
    case refinery::Type::FUNCTION_TYPE_KIND: {
      refinery::FunctionTypePtr fcn_type;
      type->CastTo(&fcn_type);
      DumpFunctionType(fcn_type, indent_level + 1);
      break;
    }
    case refinery::Type::BASIC_TYPE_KIND:
    case refinery::Type::WILDCARD_TYPE_KIND: {
      DumpBasicType(type, indent_level + 1);
      break;
    }
  }
}

int PdbTypeDumpApp::Run() {
  scoped_refptr<refinery::TypeRepository> repository =
      new refinery::TypeRepository();

  // Load the types.
  if (dump_with_dia_) {
    refinery::DiaCrawler crawler;
    if (!crawler.InitializeForFile(pdb_path_))
      return 1;

    if (!crawler.GetTypes(repository.get()))
      return 1;
  } else {
    refinery::PdbCrawler crawler;
    if (!crawler.InitializeForFile(pdb_path_))
      return 1;

    if (!crawler.GetTypes(repository.get()))
      return 1;
  }

  DumpIndentedText(out(), 0, "%d types parsed from the PDB stream:\n",
                   repository->size());

  if (dump_in_order_) {
    // We need to sort the repository.
    std::vector<refinery::TypePtr> ordered_repository(repository->begin(),
                                                      repository->end());
    std::sort(ordered_repository.begin(), ordered_repository.end(),
              [](const refinery::TypePtr& a, const refinery::TypePtr& b)
                  -> bool { return a->type_id() < b->type_id(); });

    for (refinery::TypePtr type : ordered_repository) {
      DumpType(type, 1);
    }
  } else {
    for (refinery::TypePtr type : *repository) {
      DumpType(type, 1);
    }
  }

  return 0;
}

bool PdbTypeDumpApp::Usage(const char* message) {
  ::fprintf(err(), "%s\n%s", message, kUsage);
  return false;
}

}  // namespace pdb
