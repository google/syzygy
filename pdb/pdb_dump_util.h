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
// This file provide some utility functions to dump the content of a PDB.

#ifndef SYZYGY_PDB_PDB_DUMP_UTIL_H_
#define SYZYGY_PDB_PDB_DUMP_UTIL_H_

#include "base/file_util.h"

namespace pdb {

// Forward declare.
class PdbStream;

// Dump a block of unknown data to a specific output.
// @param out The output where the data should be dumped.
// @param stream The stream containing the data. It should be positionned at the
//     beginning of the data block.
// @param len The length of the data block.
// @returns true on success, false on error.
bool DumpUnknownBlock(FILE* out, PdbStream* stream, uint16 len);

}  // namespace pdb

#endif  // SYZYGY_PDB_PDB_DUMP_UTIL_H_
