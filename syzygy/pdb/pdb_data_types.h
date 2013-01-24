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
// This file provide some data types used to store the content of the different
// PDB streams.

#ifndef SYZYGY_PDB_PDB_DATA_TYPES_H_
#define SYZYGY_PDB_PDB_DATA_TYPES_H_

#include <map>
#include <vector>

namespace pdb {

// Stores the basic information for a symbol record.
struct SymbolRecord {
  size_t start_position;
  uint16 len;
  uint16 type;
};
typedef std::vector<SymbolRecord> SymbolRecordVector;

// Stores the basic information for a type info record.
struct TypeInfoRecord {
  size_t start_position;
  uint16 len;
  uint16 type;
};
// Map with the type number as a key and the TypeInfoRecord as a value.
typedef std::map<uint32, TypeInfoRecord> TypeInfoRecordMap;

}  // namespace pdb

#endif  // SYZYGY_PDB_PDB_DATA_TYPES_H_
