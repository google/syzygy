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
// This file provides some function to read and dump the different kind of
// leaves that we can encounter in a Pdb stream.

#ifndef SYZYGY_EXPERIMENTAL_PDB_DUMPER_PDB_LEAF_H_
#define SYZYGY_EXPERIMENTAL_PDB_DUMPER_PDB_LEAF_H_

#include "base/files/file_util.h"
#include "syzygy/common/binary_stream.h"
#include "syzygy/pdb/pdb_data_types.h"
#include "syzygy/pdb/pdb_decl.h"

namespace pdb {

// Call the specific function to dump a kind of leaf.
// @param type_map The map containing all the type info records.
// @param type_value The type of the leaf.
// @param out The output where the data should be dumped.
// @param parser The parser for the data. It should be positioned at the
//     beginning of the data block.
// @param len The length of the data.
// @param indent_level The level of indentation to use.
// @returns true on success, false on error.
bool DumpLeaf(const TypeInfoRecordMap& type_map,
              uint16_t type_value,
              FILE* out,
              common::BinaryStreamParser* parser,
              size_t len,
              uint8_t indent_level);

// Returns the size of the struct associated with a numeric leaf type.
size_t NumericLeafSize(uint16_t symbol_type);

// Returns the name associated with a numeric leaf type.
const char* NumericLeafName(uint16_t leaf_type);

// Dump a numeric leaf.
// @param out The output where the data should be dumped.
// @param leaf_type The type of the numeric leaf.
// @param parser a parser over the data. It should be positioned at the
//     beginning of the data block.
void DumpNumericLeaf(FILE* out,
                     uint16_t leaf_type,
                     common::BinaryStreamParser* parser);

// Get the name and the size associated with a numeric leaf.
// @param leaf_type The type of the numeric leaf.
// @param leaf_size A pointer to the variable that will store the leaf size.
// Return The name of the leaf if it's a numeric one, NULL otherwise.
const char* GetNumericLeafNameAndSize(uint16_t leaf_type, size_t* leaf_size);

// Hexdump the data of an undeciphered leaf.
// @param type_map The map containing all the type info records.
// @param out The output where the data should be dumped.
// @param parser The parser for the data. It should be positioned at the
//     beginning of the data block.
// @param len The length of the data.
// @param indent_level The level of indentation to use.
// @returns true on success, false on error.
bool DumpUnknownLeaf(const TypeInfoRecordMap& type_map,
                     FILE* out,
                     common::BinaryStreamParser* parser,
                     uint16_t len,
                     uint8_t indent_level);

}  // namespace pdb

#endif  // SYZYGY_EXPERIMENTAL_PDB_DUMPER_PDB_LEAF_H_
