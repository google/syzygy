// Copyright 2012 Google Inc.
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
//
// This file allows to dump the content of the symbol record stream of a PDB.

#ifndef SYZYGY_PDB_PDB_DUMP_SYMBOLS_H_
#define SYZYGY_PDB_PDB_DUMP_SYMBOLS_H_

#include <vector>

#include "syzygy/common/application.h"
#include "syzygy/pdb/cvinfo_ext.h"

namespace pdb {

// Forward declarations.
class PdbStream;

// Typedefs used to store the content of the different PDB streams.
struct SymbolRecord {
  size_t start_position;
  uint16 len;
  uint16 type;
};
typedef std::vector<SymbolRecord> SymbolRecordVector;

// Dumps @p symbol_record_vector from @p stream to out.
void DumpSymbolRecord(FILE* out,
                      PdbStream* stream,
                      const SymbolRecordVector& sym_record_vector);

}  // namespace pdb

#endif  // SYZYGY_PDB_PDB_DUMP_SYMBOLS_H_
