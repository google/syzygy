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

#ifndef SYZYGY_PDB_PDB_STREAM_READER_H_
#define SYZYGY_PDB_PDB_STREAM_READER_H_

#include "syzygy/common/binary_stream.h"
#include "syzygy/pdb/pdb_stream.h"

namespace pdb {

// An adapter class that implements a BinaryStreamReader over a subset of
// a PdbStream.
class PdbStreamReaderWithPosition : public common::BinaryStreamReader {
 public:
  // Creates a reader over the entirety of @p stream.
  // @param stream the stream to read.
  explicit PdbStreamReaderWithPosition(PdbStream* stream);
  // Creates a reader over a sub-range of @p stream.
  // @param start_offset where to start reading in @p stream.
  // @param len the length, in bytes this reader will read.
  // @param stream the stream to read.
  // @pre @p start_offset + @p len <= stream->length().
  PdbStreamReaderWithPosition(size_t start_offset,
                              size_t len,
                              PdbStream* stream);

  // Creates an invalid reader, SetStream must be invoked before using this
  // instance.
  PdbStreamReaderWithPosition();

  // Set the stream this reader presents.
  // @param start_offset where to start reading in @p stream.
  // @param len the length, in bytes this reader will read.
  // @param stream the stream to read.
  // @pre @p start_offset + @p len <= stream->length().
  // @pre stream() == nullptr.
  void SetStream(size_t start_offset, size_t len, PdbStream* stream);

  // @name BinaryStreamReader implementation.
  // @pre stream() != nullptr.
  // @{
  bool Read(size_t len, void* out) override;
  size_t Position() const override;
  bool AtEnd() const override;
  // @}

  // Consumes the next @p len bytes.
  // @param len the number of bytes to consume.
  // @returns true on success, false on failure. On failure the stream position
  //     is unchanged.
  bool Consume(size_t len);

  // @name Accessors.
  // @{
  scoped_refptr<PdbStream> stream() const { return stream_; }
  // @}

 private:
  // The start offset into stream_.
  size_t start_offset_;

  // The length of this stream.
  size_t length_;

  // The read position within this stream, from 0 to length_.
  size_t pos_;

  // The PdbStream exposed on this reader.
  scoped_refptr<PdbStream> stream_;

  DISALLOW_ASSIGN(PdbStreamReaderWithPosition);
};

}  // namespace pdb

#endif  // SYZYGY_PDB_PDB_STREAM_READER_H_
