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
  explicit PdbStream(int length);
  virtual ~PdbStream();

  // Reads @p count chunks of size @p size into the destination buffer. The
  // caller is responsible for ensuring that the destination buffer has enough
  // space to receive the data.
  // @returns the number of chunks of size @p size read on success, 0 when the
  // end of the stream is reached, or -1 on error.
  template <typename ItemType>
  int Read(ItemType* dest, int count) {
    int size = sizeof(ItemType);
    int bytes_read = ReadBytes(dest, size * count);
    if (bytes_read == -1)
      return -1;

    DCHECK_EQ(0, bytes_read % size);
    return bytes_read / size;
  }

  // Sets the current read position.
  bool Seek(int pos);

  // Gets the stream's length.
  int length() const { return length_; }

 protected:
  // Reads @p count bytes of data into the destination buffer. The caller is
  // responsible for ensuring that the destination buffer has enough space to
  // receive the data. Returns the number of bytes read on success, 0 when the
  // end of the stream is reached, or -1 on error.
  virtual int ReadBytes(void* dest, int count) = 0;

  // Sets the stream's length.
  void set_length(int length) { length_ = length; }

  // Gets the stream's read position.
  int pos() const { return pos_; }

 private:
  // The length of the stream.
  int length_;

  // The read position within the stream.
  int pos_;

  DISALLOW_COPY_AND_ASSIGN(PdbStream);
};

}  // namespace pdb

#endif  // SYZYGY_PDB_PDB_STREAM_H_
