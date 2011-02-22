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
#ifndef SYZYGY_PDB_PDB_FILE_STREAM_H_
#define SYZYGY_PDB_PDB_FILE_STREAM_H_

#include <stdio.h>
#include "base/basictypes.h"
#include "syzygy/pdb/pdb_stream.h"

namespace pdb {

// This class represents a PDB stream on disk.
class PdbFileStream : public PdbStream {
 public:
  PdbFileStream(FILE* file,
                size_t length,
                const uint32* pages,
                size_t page_size);
  ~PdbFileStream();

 protected:
  // PdbStream implementation.
  size_t ReadBytes(void* dest, size_t count);

  // Read @p count bytes from @p offset byte offset from page @p page_num and
  // store them in dest.
  bool ReadFromPage(void* dest, uint32 page_num, size_t offset, size_t count);

 private:
  // The handle to the open pdb file. The PdbFileStream does not own this
  // handle.
  FILE* file_;

  // The list of pages in the pdb file that this stream points to. This is a
  // pointer to an array that must exist for the lifetime of the PdbFileStream.
  const uint32* pages_;

  // The size of pages within the stream.
  size_t page_size_;

  DISALLOW_COPY_AND_ASSIGN(PdbFileStream);
};

}  // namespace pdb

#endif  // SYZYGY_PDB_PDB_FILE_STREAM_H_
