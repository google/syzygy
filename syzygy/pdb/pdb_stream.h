// Copyright 2011 Google Inc.
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

#ifndef SYZYGY_PDB_PDB_STREAM_H_
#define SYZYGY_PDB_PDB_STREAM_H_

#include <stdio.h>
#include <vector>
#include "base/basictypes.h"
#include "base/logging.h"

namespace pdb {

// This class represents a PDB stream. It has a stream-like interface that
// allows invoking successive reads through the stream and seeking.
class PdbStream {
 public:
  explicit PdbStream(size_t length);
  virtual ~PdbStream();

  // Reads @p count chunks of size sizeof(ItemType) into the destination buffer.
  // The caller is responsible for ensuring that the destination buffer has
  // enough space to receive the data.
  // @returns true on success.
  template <typename ItemType>
  bool Read(ItemType* dest, size_t count) {
    DCHECK(dest != NULL);

    size_t size = sizeof(ItemType) * count;
    size_t bytes_read = 0;
    return ReadBytes(dest, size, &bytes_read) && bytes_read == size;
  }

  // Reads @p count bytes of data into the destination buffer. The caller is
  // responsible for ensuring that the destination buffer has enough space to
  // receive the data. @p bytes_read will hold the number of bytes read.
  // @returns true on success.
  virtual bool ReadBytes(void* dest, size_t count, size_t* bytes_read) = 0;

  // Sets the current read position.
  bool Seek(size_t pos);

  // Gets the stream's length.
  size_t length() const { return length_; }

 protected:
  // Sets the stream's length.
  void set_length(size_t length) { length_ = length; }

  // Gets the stream's read position.
  size_t pos() const { return pos_; }

 private:
  // The length of the stream.
  size_t length_;

  // The read position within the stream.
  size_t pos_;

  DISALLOW_COPY_AND_ASSIGN(PdbStream);
};

}  // namespace pdb

#endif  // SYZYGY_PDB_PDB_STREAM_H_
