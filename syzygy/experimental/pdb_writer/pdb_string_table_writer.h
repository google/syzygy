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

#ifndef SYZYGY_EXPERIMENTAL_PDB_WRITER_PDB_STRING_TABLE_WRITER_H_
#define SYZYGY_EXPERIMENTAL_PDB_WRITER_PDB_STRING_TABLE_WRITER_H_

#include <string>
#include <vector>

namespace pdb {

typedef std::vector<std::string> StringTable;

// Forward declaration.
class WritablePdbStream;

// Writes a string table. A string table is found in the names stream and in the
// EC info header of the debug info stream of a PDB file.
// @param string_table the strings to write in the table.
// @param stream the stream in which to write the string table at the current
//     position.
// @returns true in case of success, false otherwise.
bool WriteStringTable(const StringTable& string_table,
                      pdb::WritablePdbStream* stream);

}  // namespace pdb

#endif  // SYZYGY_EXPERIMENTAL_PDB_WRITER_PDB_STRING_TABLE_WRITER_H_
