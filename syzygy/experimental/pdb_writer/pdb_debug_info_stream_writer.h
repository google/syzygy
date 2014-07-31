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

#ifndef SYZYGY_EXPERIMENTAL_PDB_WRITER_PDB_DEBUG_INFO_STREAM_WRITER_H_
#define SYZYGY_EXPERIMENTAL_PDB_WRITER_PDB_DEBUG_INFO_STREAM_WRITER_H_

#include "base/basictypes.h"

namespace pdb {

// Forward declaration.
class WritablePdbStream;

// Writes a debug info stream.
// @param age the age of the PDB, extracted from the PE file.
// @param symbol_record_stream_index index of the symbol record stream.
// @param public_stream_index index of the public stream.
// @param section_header_stream_index index of the section header stream.
// @param stream the stream in which to write.
// @returns true in case of success, false otherwise.
bool WriteDebugInfoStream(uint32 pdb_age,
                          size_t symbol_record_stream_index,
                          size_t public_stream_index,
                          size_t section_header_stream_index,
                          WritablePdbStream* stream);

}  // namespace pdb

#endif  // SYZYGY_EXPERIMENTAL_PDB_WRITER_PDB_DEBUG_INFO_STREAM_WRITER_H_
