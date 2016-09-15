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

#ifndef SYZYGY_MSF_MSF_FILE_STREAM_H_
#define SYZYGY_MSF_MSF_FILE_STREAM_H_

#include <stdio.h>

#include "base/memory/ref_counted.h"
#include "syzygy/msf/msf_decl.h"
#include "syzygy/msf/msf_stream.h"

namespace msf {

// A reference counted FILE pointer object.
// NOTE: This is not thread safe for a variety of reasons.
class RefCountedFILE : public base::RefCounted<RefCountedFILE> {
 public:
  explicit RefCountedFILE(FILE* file) : file_(file) {}

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

namespace detail {

// This class represents an MSF stream on disk.
template <MsfFileType T>
class MsfFileStreamImpl : public MsfStreamImpl<T> {
 public:
  // Constructor.
  // @param file the reference counted file housing this stream.
  // @param length the length of this stream.
  // @param pages the indices of the pages that make up this stream in the file.
  //     A copy is made of the data so the pointer need not remain valid
  //     beyond the constructor. The length of this array is implicit in the
  //     stream length and the page size.
  // @param page_size the size of the pages, in bytes.
  MsfFileStreamImpl(RefCountedFILE* file,
                    uint32_t length,
                    const uint32_t* pages,
                    uint32_t page_size);

  // MsfStreamImpl implementation.
  bool ReadBytesAt(size_t pos, size_t count, void* dest) override;

 protected:
  // Protected to enforce reference counted pointers at compile time.
  virtual ~MsfFileStreamImpl();

  // Read @p count bytes from @p offset byte offset from page @p page_num and
  // store them in @p dest.
  bool ReadFromPage(void* dest, uint32_t page_num, size_t offset, size_t count);

 private:
  // The handle to the open MSF file. This is reference counted so ownership of
  // that streams can outlive the MsfReaderImpl that created them.
  scoped_refptr<RefCountedFILE> file_;

  // The list of pages in the msf MSF that make up this stream.
  std::vector<uint32_t> pages_;

  // The size of pages within the stream.
  size_t page_size_;

  DISALLOW_COPY_AND_ASSIGN(MsfFileStreamImpl);
};

}  // namespace detail

using MsfFileStream = detail::MsfFileStreamImpl<kGenericMsfFileType>;

}  // namespace msf

#include "syzygy/msf/msf_file_stream_impl.h"

#endif  // SYZYGY_MSF_MSF_FILE_STREAM_H_
