// Copyright 2014 Google Inc. All Rights Reserved.
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
// Declares a function to build a PDB file from a list of symbols.

#ifndef SYZYGY_EXPERIMENTAL_PDB_WRITER_SIMPLE_PDB_BUILDER_H_
#define SYZYGY_EXPERIMENTAL_PDB_WRITER_SIMPLE_PDB_BUILDER_H_

#include "syzygy/experimental/pdb_writer/symbol.h"
#include "syzygy/pe/pe_file.h"

namespace pdb {

// Forward declaration.
class PdbFile;

// Builds a PDB file from a list of symbols.
// @param pe_path the PE file for which a PDB is being generated.
// @param symbols the symbols to include in the PDB.
// @param pdb_file the generated PDB.
// @returns true in case of success, false otherwise.
bool BuildSimplePdb(const pe::PEFile& pe_file,
                    const SymbolVector& symbols,
                    PdbFile* pdb_file);

}  // namespace pdb

#endif  // SYZYGY_EXPERIMENTAL_PDB_WRITER_SIMPLE_PDB_BUILDER_H_
