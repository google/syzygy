// Copyright 2015 Google Inc. All Rights Reserved.
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
// This file allows reading the content of the type info stream of a PDB.

#ifndef SYZYGY_PDB_PDB_TYPE_INFO_STREAM_ENUM_H_
#define SYZYGY_PDB_PDB_TYPE_INFO_STREAM_ENUM_H_

#include <stdint.h>
#include "base/callback.h"
#include "syzygy/pdb/pdb_data.h"
#include "syzygy/pdb/pdb_data_types.h"

namespace pdb {

// Forward declarations.
class PdbStream;

// Simple type info stream enumerator which crawls through a type info stream.
class TypeInfoEnumerator {
 public:
  // Creates an uninitialized enumerator for @p stream.
  // @param stream a pointer to a heap allocated stream object. The enumerator
  //     does not take ownership of this pointer.
  explicit TypeInfoEnumerator(PdbStream* stream);

  // Reads the type info header and returns true on success. Needs to be called
  // first in order to initialize the class.
  // @param type_info_header pointer to TypeInfoHeader object which will be
  //     filled with the header info.
  // @returns true on success, false means bad header format.
  bool ReadTypeInfoHeader(TypeInfoHeader* type_info_header);

  // Moves to the next record in the type info stream. Expects stream position
  // at the beginning of a type info record.
  // @returns true on success, false on failure.
  bool NextTypeInfoRecord();

  // Checks if the end of stream was reached.
  // @returns true at the end of the stream, false otherwise.
  bool EndOfStream();

  // @name Accessors.
  // @{
  // @returns the starting position of current type record.
  size_t start_position() const { return start_position_; }

  // @returns the length of the current type record.
  uint16_t len() const { return len_; }

  // @returns the type of the current type record.
  uint16_t type() const { return type_; }

  // @returns the type ID of the current type record.
  uint32_t type_id() const { return type_id_; }
  // @}

 private:
  // Pointer to the PDB type info stream.
  scoped_refptr<PdbStream> stream_;

  // Starting position of the current type record in the stream.
  size_t start_position_;

  // Position of the end of data in the stream.
  size_t data_end_;

  // The length of the current type record.
  uint16_t len_;

  // The type of the current type record.
  uint16_t type_;

  // The type ID of the current type record.
  uint32_t type_id_;

  // The largest type ID according to header.
  uint32_t type_id_max_;

  // The smallest type ID according to header.
  uint32_t type_id_min_;
};

}  // namespace pdb

#endif  // SYZYGY_PDB_PDB_TYPE_INFO_STREAM_ENUM_H_
