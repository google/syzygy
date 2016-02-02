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

#ifndef SYZYGY_EXPERIMENTAL_PDB_DUMPER_PDB_TYPE_DUMP_H_
#define SYZYGY_EXPERIMENTAL_PDB_DUMPER_PDB_TYPE_DUMP_H_

#include "base/files/file_path.h"
#include "syzygy/application/application.h"
#include "syzygy/pdb/pdb_util.h"
#include "syzygy/refinery/types/type.h"
#include "syzygy/refinery/types/type_repository.h"

namespace pdb {

// The PdbTypeDump application dumps information from the type repository which
// gets created by PdbCrawler.
class PdbTypeDumpApp : public application::AppImplBase {
 public:
  PdbTypeDumpApp();

  // @name Application interface overrides.
  // @{
  bool ParseCommandLine(const base::CommandLine* command_line);
  int Run();
  // @}

 protected:
  // Prints @p message, followed by usage instructions.
  // @returns false.
  bool Usage(const char* message);

  // @name Dump information about @p type while using @p indent_level for
  // indentation.
  // @{
  void DumpType(refinery::TypePtr type, uint8_t indent_level);
  void DumpUserDefinedType(refinery::UserDefinedTypePtr type,
                           uint8_t indent_level);
  void DumpArrayType(refinery::ArrayTypePtr type, uint8_t indent_level);
  void DumpPointerType(refinery::PointerTypePtr type, uint8_t indent_level);
  void DumpFunctionType(refinery::FunctionTypePtr type, uint8_t indent_level);
  void DumpBasicType(refinery::TypePtr type, uint8_t indent_level);
  // @}

  // Dumps name and decorated name of @p type with @p indent_level.
  void DumpNames(refinery::TypePtr type, uint8_t ident_level);

  // Dumps information about @p field with @p indent_level.
  void DumpField(const refinery::UserDefinedType::Field& field,
                 uint8_t indent_level);
  void DumpMemberField(const refinery::UserDefinedType::MemberField& member,
                       uint8_t indent_level);

  // Dumps information about @p function with @p indent_level.
  void DumpFunction(const refinery::UserDefinedType::Function& function,
                    uint8_t indent_level);

  // Dumps information about @p argument with @p indent_level.
  void DumpArgument(refinery::FunctionType::ArgumentType argument,
                    uint8_t indent_level);

  // Dumps textual information whether type @p is_const or @p is_volatile with
  // @p indent_level.
  void DumpFlags(bool is_const, bool is_volatile, uint8_t indent_level);

  // The PDB file to dump.
  base::FilePath pdb_path_;

  // Iff true, the types will get dumped ordered by their type indices.
  bool dump_in_order_;

  // Iff true, all types will be printed with their names.
  bool dump_all_names_;

  // Iff true, DiaCrawler will be used for scraping the types.
  bool dump_with_dia_;
};

}  // namespace pdb

#endif  // SYZYGY_EXPERIMENTAL_PDB_DUMPER_PDB_TYPE_DUMP_H_
