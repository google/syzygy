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
  class BinaryTypeRecordReader;

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

  // Creates and returns a class that implements common::BinaryStreamReader
  // over the current record.
  BinaryTypeRecordReader CreateRecordReader();

  // @name Accessors.
  // @{
  // @returns the starting position of current type record.
  // @note this is currently past the length and type fields of the record.
  size_t start_position() const {
    return current_record_.start + sizeof(current_record_.length) +
           sizeof(current_record_.type);
  }

  // @returns the length of the current type record.
  // @note this currently excludes the length and type fields, which are
  //     assumed to be consumed already.
  uint16_t len() const {
    return current_record_.length - sizeof(current_record_.type);
  }

  // @returns the type of the current type record.
  uint16_t type() const { return current_record_.type; }

  // @returns the type ID of the current type record.
  uint32_t type_id() const { return type_id_; }

  // @returns the type info header of the type info stream.
  TypeInfoHeader type_info_header() const { return type_info_header_; }
  // @}

 private:
  friend class BinaryTypeRecordReader;

  // Information about a specific type record.
  struct TypeRecordInfo {
    // The stream position of the first byte of the type record (which starts
    // with the record length).
    size_t start;
    // The type of the record.
    uint16_t type;
    // The length of the record, this is exclusive the length itself.
    uint16_t length;
  };

  // Ensure that the type with ID @p type_id has been located and stored
  // in @p located_records_.
  bool EnsureTypeLocated(uint32_t type_id);
  // Adds the start position @p position for @p type_id, which must be a valid
  // type id, and must be one larger than the last added start position.
  bool AddRecordInfo(uint32_t type_id, const TypeRecordInfo& record);
  bool FindRecordInfo(uint32_t type_id, TypeRecordInfo* record);

  // Pointer to the PDB type info stream.
  scoped_refptr<PdbStream> stream_;

  // The reader used to parse out the locations of type records.
  PdbStreamReaderWithPosition reader_;

  // Header of the type info stream.
  TypeInfoHeader type_info_header_;

  // A vector with the positions of located records.
  std::vector<TypeRecordInfo> located_records_;

  // The largest type index we already saved in @p located_records_.
  uint32_t largest_located_id_;

  // Position of the end of data in the stream.
  size_t data_end_;

  // The largest type ID according to header.
  uint32_t type_id_max_;

  // The smallest type ID in the stream according to header.
  // This is typically 0x1000, as lower type id values are reserved for built
  // in types.
  uint32_t type_id_min_;

  // The type ID of the current type record.
  uint32_t type_id_;

  // Details of the current type record.
  TypeRecordInfo current_record_;
};

class TypeInfoEnumerator::BinaryTypeRecordReader
    : public PdbStreamReaderWithPosition {
 private:
  friend class TypeInfoEnumerator;

  BinaryTypeRecordReader(size_t start_offset, size_t len, PdbStream* stream);
};

}  // namespace pdb

#endif  // SYZYGY_PDB_PDB_TYPE_INFO_STREAM_ENUM_H_
