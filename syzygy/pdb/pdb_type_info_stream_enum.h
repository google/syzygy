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
#include <memory>
#include <unordered_map>

#include "base/callback.h"
#include "base/memory/ref_counted.h"
#include "syzygy/pdb/pdb_byte_stream.h"
#include "syzygy/pdb/pdb_data.h"
#include "syzygy/pdb/pdb_data_types.h"
#include "syzygy/pdb/pdb_stream.h"
#include "syzygy/pdb/pdb_stream_reader.h"

namespace pdb {

// Simple type info stream enumerator which crawls through a type info stream.
class TypeInfoEnumerator {
 public:
  // Creates an uninitialized enumerator for type info stream.
  // @param stream the stream to parse.
  explicit TypeInfoEnumerator(PdbStream* stream);

  // Initializes the enumerator with given stream. Needs to be called before
  // any further work.
  // @returns true on success, false means bad header format.
  bool Init();

  // Moves to the next record in the type info stream. Expects stream position
  // at the beginning of a type info record.
  // @returns true on success, false on failure.
  bool NextTypeInfoRecord();

  // Moves position to the desired type id.
  // @param type index of the desired record.
  // @returns true on success, false on failure.
  bool SeekRecord(uint32_t type_id);

  // Checks if the end of stream was reached.
  // @returns true at the end of the stream, false otherwise.
  bool EndOfStream();

  // Resets stream to its beginning.
  // @returns true on success, false on failure.
  bool ResetStream();

  // @returns the data stream for the current type record. After calling
  // NextTypeInfoRecord the stream gets populated with the data of the next
  // type record.
  scoped_refptr<PdbStream> GetDataStream() const { return data_stream_; }

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

  // @returns the type info header of the type info stream.
  TypeInfoHeader type_info_header() const { return type_info_header_; }
  // @}

 private:
  bool EnsureTypeLocated(uint32_t type_id);
  // Adds the start position @p position for @p type_id, which must be a valid
  // type id, and must be one larger than the last added start position.
  bool AddStartPosition(uint32_t type_id, size_t position);
  bool FindStartPosition(uint32_t type_id, size_t* position);

  // Pointer to the PDB type info stream.
  scoped_refptr<PdbStream> stream_;

  // The reader used to parse out the locations of type records.
  PdbStreamReaderWithPosition reader_;

  // Header of the type info stream.
  TypeInfoHeader type_info_header_;

  // A vector with the positions of located records.
  std::vector<size_t> start_positions_;

  // The largest type index we already saved in the start_positions_ map. Every
  // time we seek beyond this record we simply load records one by one and save
  // their starting positions in the map.
  uint32_t largest_encountered_id_;

  // Stream containing data of the current type info record.
  scoped_refptr<PdbByteStream> data_stream_;

  // Starting position of the current type record in the stream.
  size_t start_position_;

  // Position of the end of data in the stream.
  size_t data_end_;

  // The largest type ID according to header.
  uint32_t type_id_max_;

  // The smallest type ID in the stream according to header.
  // This is typically 0x1000, as lower type id values are reserved for built
  // in types.
  uint32_t type_id_min_;

  // The length of the current type record.
  uint16_t len_;

  // The type of the current type record.
  uint16_t type_;

  // The type ID of the current type record.
  uint32_t type_id_;
};

}  // namespace pdb

#endif  // SYZYGY_PDB_PDB_TYPE_INFO_STREAM_ENUM_H_
