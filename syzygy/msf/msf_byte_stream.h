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

#ifndef SYZYGY_MSF_MSF_BYTE_STREAM_H_
#define SYZYGY_MSF_MSF_BYTE_STREAM_H_

#include <vector>

#include "syzygy/msf/msf_decl.h"
#include "syzygy/msf/msf_stream.h"

namespace msf {
namespace detail {

// This class represents an MSF stream in memory.
template <MsfFileType T>
class MsfByteStreamImpl : public MsfStreamImpl<T> {
 public:
  MsfByteStreamImpl();

  // Initializes the stream from the contents of a byte array.
  bool Init(const uint8_t* data, uint32_t length);

  // Initializes the stream from the whole contents of another MsfStreamImpl.
  bool Init(MsfStreamImpl* stream);

  // Initializes the stream from the part of another MsfStreamImpl.
  bool Init(MsfStreamImpl* stream, uint32_t pos, uint32_t length);

  // @name MsfStreamImpl implementation.
  // @{
  bool ReadBytesAt(size_t pos, size_t count, void* dest) override;
  scoped_refptr<WritableMsfStreamImpl<T>> GetWritableStream() override;
  // @}

  // Gets the stream's data pointer.
  uint8_t* data() { return &data_[0]; }

 protected:
  // Our friend so it can access our internals.
  friend WritableMsfByteStreamImpl<T>;

  // This is protected to enforce use of reference counted pointers.
  virtual ~MsfByteStreamImpl();

  // The stream's data.
  std::vector<uint8_t> data_;

  // This is a bit of a hack, allowing us to enforce single
  // WritableMsfStreamImpl
  // semantics. This is most definitely *not* thread-safe.
  WritableMsfStreamImpl<T>* writable_msf_stream_;

  DISALLOW_COPY_AND_ASSIGN(MsfByteStreamImpl);
};

}  // namespace detail

using MsfByteStream = detail::MsfByteStreamImpl<kGenericMsfFileType>;

}  // namespace msf

#include "syzygy/msf/msf_byte_stream_impl.h"

#endif  // SYZYGY_MSF_MSF_BYTE_STREAM_H_
