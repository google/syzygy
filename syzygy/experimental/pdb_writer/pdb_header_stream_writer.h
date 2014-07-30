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

#ifndef SYZYGY_EXPERIMENTAL_PDB_WRITER_PDB_HEADER_STREAM_WRITER_H_
#define SYZYGY_EXPERIMENTAL_PDB_WRITER_PDB_HEADER_STREAM_WRITER_H_

#include "syzygy/pe/pdb_info.h"

namespace pdb {

// Forward declaration.
class WritablePdbStream;

// Writes a PDB header stream.
// @param pdb_info PDB info extracted from the PE for which the debug database
//     is being generated.
// @param names_stream_index index of the names stream in the generated PDB.
// @param stream the stream in which to write.
// @returns true in case of success, false otherwise.
bool WriteHeaderStream(const pe::PdbInfo& pdb_info,
                       size_t names_stream_index,
                       WritablePdbStream* stream);

}  // namespace pdb

#endif  // SYZYGY_EXPERIMENTAL_PDB_WRITER_PDB_HEADER_STREAM_WRITER_H_
