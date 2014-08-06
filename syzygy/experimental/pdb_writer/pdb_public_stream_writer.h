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
// Declares a function to write the PDB public stream. The format of this
// stream is described at
// https://code.google.com/p/syzygy/wiki/PdbFileFormat#Public.

#ifndef SYZYGY_EXPERIMENTAL_PDB_WRITER_PDB_PUBLIC_STREAM_WRITER_H_
#define SYZYGY_EXPERIMENTAL_PDB_WRITER_PDB_PUBLIC_STREAM_WRITER_H_

#include "syzygy/experimental/pdb_writer/symbol.h"
#include "syzygy/experimental/pdb_writer/pdb_symbol_record_writer.h"

namespace pdb {

// Forward declaration.
class WritablePdbStream;

// Writes a PDB public stream.
// @param symbols the symbols defined in the PDB symbol record stream.
// @param symbol_offsets the offsets at which the symbols from |symbols| have
//     been written in the symbol record stream.
// @param stream the stream in which to write.
// @returns true in case of success, false otherwise.
bool WritePublicStream(const SymbolVector& symbols,
                       const SymbolOffsets& symbol_offsets,
                       WritablePdbStream* stream);

}  // namespace pdb

#endif  // SYZYGY_EXPERIMENTAL_PDB_WRITER_PDB_PUBLIC_STREAM_WRITER_H_
