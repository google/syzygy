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
//
// Declares MsfFile, which is an in-memory representation of an MSF file.
// An MSF file consists of a collection of numbered MSF streams. The streams
// themselves obey certain formats and conventions but these are not enforced
// by this naive representation.

#ifndef SYZYGY_MSF_MSF_FILE_H_
#define SYZYGY_MSF_MSF_FILE_H_

#include <vector>

#include "base/memory/ref_counted.h"
#include "syzygy/msf/msf_decl.h"
#include "syzygy/msf/msf_stream.h"

namespace msf {
namespace detail {

// A simple representation of an MSF file as a collection of numbered streams.
// This object owns all of the streams referred to by it and maintains
// responsibility for cleaning them up on destruction.
template <MsfFileType T>
class MsfFileImpl {
 public:
  MsfFileImpl();
  virtual ~MsfFileImpl();

  // Clears all streams. After calling this the MsfFileImpl is in the same state
  // as after construction.
  void Clear();

  // Accesses the nth stream.
  // @param index the index of the nth stream.
  // @returns a pointer to the stream, NULL if it does not exist.
  scoped_refptr<MsfStreamImpl<T>> GetStream(uint32_t index) const;

  // Adds a new stream to this MSF file, returning the index of the newly
  // generated stream.
  // @param msf_stream a pointer to a heap allocated stream object This may be
  //     NULL, indicating that the nth stream exists but is empty.
  // @returns the index of the added stream.
  size_t AppendStream(MsfStreamImpl<T>* msf_stream);

  // Sets the nth stream. Overwrites an existing stream if there is one.
  // @param index the index of the stream. This must be >= 0, and must be
  //     a stream index that already exists.
  // @param msf_stream a pointer to the heap allocated stream to be placed at
  //     the given position. This may be NULL, which is equivalent to erasing
  //     the given stream.
  void ReplaceStream(uint32_t index, MsfStreamImpl<T>* msf_stream);

  // Sets the nth stream. Overwrites an existing stream if there is one.
  // @param index the index of the stream.
  // @param msf_stream a pointer to the heap allocated stream to be placed at
  //     the given position. This may be NULL, which is equivalent to erasing
  //     the given stream.
  void SetStream(uint32_t index, MsfStreamImpl<T>* msf_stream);

  // Returns the number of streams in the MSF file. There are streams with
  // IDs 0 through StreamCount() - 1.
  // @returns the number of streams in the MSF file.
  size_t StreamCount() const { return streams_.size(); }

 private:
  // The streams are implicitly numbered simply by their position in this
  // vector.
  std::vector<scoped_refptr<MsfStreamImpl<T>>> streams_;

  DISALLOW_COPY_AND_ASSIGN(MsfFileImpl);
};

}  // namespace detail

using MsfFile = detail::MsfFileImpl<kGenericMsfFileType>;

}  // namespace msf

#include "syzygy/msf/msf_file_impl.h"

#endif  // SYZYGY_MSF_MSF_FILE_H_
