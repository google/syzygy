// Copyright 2012 Google Inc.
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
#include "base/memory/ref_counted.h"
#include "syzygy/pdb/pdb_stream.h"

namespace pdb {

// A reference counted FILE pointer object.
// NOTE: This is not thread safe for a variety of reasons.
class RefCountedFILE : public base::RefCounted<RefCountedFILE> {
 public:
  explicit RefCountedFILE(FILE* file) : file_(file) { }

  // @returns the file pointer being reference counted.
  FILE* file() { return file_; }

 private:
  friend base::RefCounted<RefCountedFILE>;

  // We disallow access to the destructor to enforce the use of reference
  // counting pointers.
  ~RefCountedFILE() {
    if (file_)
      ::fclose(file_);
  }

  FILE* file_;

  DISALLOW_COPY_AND_ASSIGN(RefCountedFILE);
};

// This class represents a PDB stream on disk.
class PdbFileStream : public PdbStream {
 public:
  // Constructor.
  // @param file the reference counted file housing this stream.
  // @param length the length of this stream.
  // @param pages the indices of the pages that make up this stream in the file.
  //     A copy is made of the data so the pointer need not remain valid
  //     beyond the constructor. The length of this array is implicit in the
  //     stream length and the page size.
  // @param page_size the size of the pages, in bytes.
  PdbFileStream(RefCountedFILE* file,
                size_t length,
                const uint32* pages,
                size_t page_size);

  // PdbStream implementation.
  bool ReadBytes(void* dest, size_t count, size_t* bytes_read);

 protected:
  // Protected to enforce reference counted pointers at compile time.
  virtual ~PdbFileStream();

  // Read @p count bytes from @p offset byte offset from page @p page_num and
  // store them in dest.
  bool ReadFromPage(void* dest, uint32 page_num, size_t offset, size_t count);

 private:
  // The handle to the open PDB file. This is reference counted so ownership so
  // that streams can outlive the PdbReader that created them.
  scoped_refptr<RefCountedFILE> file_;

  // The list of pages in the pdb PDB that make up this stream.
  std::vector<uint32> pages_;

  // The size of pages within the stream.
  size_t page_size_;

  DISALLOW_COPY_AND_ASSIGN(PdbFileStream);
};

}  // namespace pdb

#endif  // SYZYGY_PDB_PDB_FILE_STREAM_H_
