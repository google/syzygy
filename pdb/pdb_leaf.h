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
// This file provides some function to read and dump the different kind of
// leaves that we can encounter in a Pdb stream.

#ifndef SYZYGY_PDB_PDB_LEAF_H_
#define SYZYGY_PDB_PDB_LEAF_H_

#include "base/file_util.h"
#include "syzygy/pdb/pdb_data_types.h"

namespace pdb {

// Forward declare.
class PdbStream;

// Call the specific function to dump a kind of leaf.
// @param type_map The map containing all the type info records.
// @param type_value The type of the leaf.
// @param out The output where the data should be dumped.
// @param stream The stream containing the data. It should be positioned at the
//     beginning of the data block.
// @param len The length of the data.
// @param indent_level The level of indentation to use.
// @returns true on success, false on error.
bool DumpLeaf(const TypeInfoRecordMap& type_map,
              uint16 type_value,
              FILE* out,
              PdbStream* stream,
              uint16 len,
              uint8 indent_level);

// Returns the size of the struct associated with a numeric leaf type.
size_t NumericLeafSize(uint16 symbol_type);

// Returns the name associated with a numeric leaf type.
const char* NumericLeafName(uint16 leaf_type);

// Dump a numeric leaf.
// @param out The output where the data should be dumped.
// @param leaf_type The type of the numeric leaf.
// @param stream The stream containing the data. It should be positioned at the
//     beginning of the data block.
void DumpNumericLeaf(FILE* out, uint16 leaf_type, PdbStream* stream);

// Get the name and the size associated with a numeric leaf.
// @param leaf_type The type of the numeric leaf.
// @param leaf_size A pointer to the variable that will store the leaf size.
// Return The name of the leaf if it's a numeric one, NULL otherwise.
const char* GetNumericLeafNameAndSize(uint16 leaf_type, size_t* leaf_size);

// Hexdump the data of an undeciphered leaf.
// @param type_map The map containing all the type info records.
// @param out The output where the data should be dumped.
// @param stream The stream containing the data. It should be positioned at the
//     beginning of the data block.
// @param len The length of the data.
// @param indent_level The level of indentation to use.
// @returns true on success, false on error.
bool DumpUnknownLeaf(const TypeInfoRecordMap& type_map,
                     FILE* out,
                     PdbStream* stream,
                     uint16 len,
                     uint8 indent_level);

}  // namespace pdb

#endif  // SYZYGY_PDB_PDB_LEAF_H_
