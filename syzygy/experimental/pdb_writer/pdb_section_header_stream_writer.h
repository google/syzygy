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

#ifndef SYZYGY_EXPERIMENTAL_PDB_WRITER_PDB_SECTION_HEADER_STREAM_WRITER_H_
#define SYZYGY_EXPERIMENTAL_PDB_WRITER_PDB_SECTION_HEADER_STREAM_WRITER_H_

#include "syzygy/pe/pe_file.h"

namespace pdb {

// Forward declaration.
class WritablePdbStream;

// Writes a PDB section header stream. This stream contains the
// IMAGE_SECTION_HEADER structures extracted from the PE file for which a PDB
// is being generated.
// @param pe_file the PE file for which a PDB is being generated.
// @param stream the stream in which to write.
// @returns true in case of success, false otherwise.
bool WriteSectionHeaderStream(const pe::PEFile& pe_file,
                              WritablePdbStream* stream);

}  // namespace pdb

#endif  // SYZYGY_EXPERIMENTAL_PDB_WRITER_PDB_SECTION_HEADER_STREAM_WRITER_H_
