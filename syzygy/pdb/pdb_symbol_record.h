// Copyright 2012 Google Inc. All Rights Reserved.
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
// This file allows reading the content of the symbol record table from a PDB
// stream.

#ifndef SYZYGY_PDB_PDB_SYMBOL_RECORD_H_
#define SYZYGY_PDB_PDB_SYMBOL_RECORD_H_

#include <vector>

#include "base/callback.h"
#include "syzygy/common/binary_stream.h"
#include "syzygy/pdb/pdb_data_types.h"
#include "syzygy/pdb/pdb_stream.h"

namespace pdb {

// Read a symbol record table from a Pdb stream.
// @param stream The stream containing the table.
// @param symbol_table_offset The start offset of the symbol record table.
// @param symbol_table_size The size of the symbol record table.
// @param symbol_vector The vector where the symbol records should be stored.
// @returns true on success, false otherwise.
bool ReadSymbolRecord(PdbStream* stream,
                      size_t symbol_table_offset,
                      size_t symbol_table_size,
                      SymbolRecordVector* symbol_vector);

// Defines a symbol visitor callback. This needs to return true on success
// (indicating that the symbol visitor should continue), and false on failure
// (indicating that it should terminate). The reader is positioned at the
// beginning of the symbol data, which is of the provided length, the type
// having already been read from the stream.
typedef base::Callback<bool(uint16_t /* symbol_length */,
                            uint16_t /* symbol_type */,
                            common::BinaryStreamReader* /* symbol_reader */)>
    VisitSymbolsCallback;

// Reads symbols from the given symbol stream until the end of the stream.
// @param callback The callback to be invoked for each symbol.
// @param symbol_table_offset The start offset of the symbol table to visit.
// @param symbol_table_size The size of the symbol record table.
// @param has_header If true then this will first parse the symbol stream
//     header and ensure it is of the expected type. If false it will assume
//     it is the expected type and start parsing symbols immediately.
// @param symbols The stream containing symbols to be visited. The stream
//     will be read starting from its current position, and will be advanced
//     past the symbols one by one.
// @returns true on success, false otherwise.
bool VisitSymbols(VisitSymbolsCallback callback,
                  size_t symbol_table_offset,
                  size_t symbol_table_size,
                  bool has_header,
                  PdbStream* symbols);

}  // namespace pdb

#endif  // SYZYGY_PDB_PDB_SYMBOL_RECORD_H_
