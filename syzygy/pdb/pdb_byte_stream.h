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

#ifndef SYZYGY_PDB_PDB_BYTE_STREAM_H_
#define SYZYGY_PDB_PDB_BYTE_STREAM_H_

#include "base/scoped_ptr.h"
#include "syzygy/pdb/pdb_stream.h"

namespace pdb {

// This class represents a PDB stream in memory.
class PdbByteStream : public PdbStream {
 public:
  PdbByteStream();
  ~PdbByteStream();

  // Initializes the stream from the contents of a byte array.
  bool Init(const uint8* data, size_t length);

  // Initializes the stream from the contents of another PdbStream.
  bool Init(PdbStream* stream);

  // Gets the stream's data pointer.
  uint8* data() { return data_.get(); }

 protected:
  // PdbStream implementation.
  size_t ReadBytes(void* dest, size_t count);

 private:
  // The stream's data.
  scoped_array<uint8> data_;

  DISALLOW_COPY_AND_ASSIGN(PdbByteStream);
};

}  // namespace pdb

#endif  // SYZYGY_PDB_PDB_BYTE_STREAM_H_
