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
// This file provide some utility functions to dump the content of a PDB.

#ifndef SYZYGY_EXPERIMENTAL_PDB_DUMPER_PDB_DUMP_UTIL_H_
#define SYZYGY_EXPERIMENTAL_PDB_DUMPER_PDB_DUMP_UTIL_H_

#include "base/files/file_util.h"
#include "syzygy/common/binary_stream.h"
#include "syzygy/pdb/pdb_decl.h"

namespace pdb {

// Dump a block of unknown data to a specific output.
// @param out The output where the data should be dumped.
// @param parser The parser for the data. It should be positioned at the
//     beginning of the data block.
// @param len The length of the data block.
// @param indent_level The level of indentation to use.
// @returns true on success, false on error.
bool DumpUnknownBlock(FILE* out,
                      common::BinaryStreamParser* parser,
                      uint16_t len,
                      uint8_t indent_level);

// Output the appropriate level of indentation.
// @param out The output where the tabs should be dumped.
// @param indent_level The number of tabs to put.
void DumpTabs(FILE* out, uint8_t indent_level);

// Output text with the appropriate level of indentation.
// @param out The output where the text should be dumped.
// @param text The text to dump.
// @param indent_level The number of tabs to put.
void DumpIndentedText(FILE* out, uint8_t indent_level, const char* format, ...);

}  // namespace pdb

#endif  // SYZYGY_EXPERIMENTAL_PDB_DUMPER_PDB_DUMP_UTIL_H_
