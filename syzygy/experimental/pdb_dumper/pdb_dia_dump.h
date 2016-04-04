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

#ifndef SYZYGY_EXPERIMENTAL_PDB_DUMPER_PDB_DIA_DUMP_H_
#define SYZYGY_EXPERIMENTAL_PDB_DUMPER_PDB_DIA_DUMP_H_

#include <windows.h>  // NOLINT
#include <dia2.h>

#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include "base/containers/hash_tables.h"
#include "base/files/file_path.h"
#include "syzygy/application/application.h"
#include "syzygy/pdb/pdb_util.h"

namespace pdb {

// The PdbDiaDump application dumps information on DIA's representation of
// a PDB file.
class PdbDiaDumpApp : public application::AppImplBase {
 public:
  PdbDiaDumpApp();

  // @name Application interface overrides.
  // @{
  bool ParseCommandLine(const base::CommandLine* command_line);
  int Run();
  // @}

 protected:
  // Prints @p message, followed by usage instructions.
  // @returns false.
  bool Usage(const char* message);

  bool DumpSymbols(IDiaSession* session);
  bool DumpSymbol(uint8_t indent_level, IDiaSymbol* symbol);

  bool DumpAllFrameData(IDiaSession* session);
  bool DumpFrameData(uint8_t indent_level, IDiaFrameData* frame_data);

  base::FilePath pdb_path_;

  bool dump_symbol_data_;
  bool dump_frame_data_;

  // Tracks previously visited symbols on the path from the root to the current
  // symbol, for cycle detection during the the recursive traversal of the
  // symbol graph.
  std::unordered_set<uint32_t> visited_symbols_;
};

}  // namespace pdb

#endif  // SYZYGY_EXPERIMENTAL_PDB_DUMPER_PDB_DIA_DUMP_H_
