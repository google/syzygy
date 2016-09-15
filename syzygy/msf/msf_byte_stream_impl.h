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
// Internal implementation details for msf_byte_stream.h. Not meant to be
// included directly.

#ifndef SYZYGY_MSF_MSF_BYTE_STREAM_IMPL_H_
#define SYZYGY_MSF_MSF_BYTE_STREAM_IMPL_H_

#include <algorithm>
#include <cstring>

#include "base/logging.h"
#include "base/memory/ref_counted.h"

namespace msf {
namespace detail {

// The writable half of an in-memory MSF stream. This is not in an anonymous
// namespace as it is forward declared in the header and is a friend of
// MsfByteStreamImpl, allowing access to the underlying storage vector. Once we
// hoist storage to another interface, this implementation can be entirely
// hidden.
template <MsfFileType T>
class WritableMsfByteStreamImpl : public WritableMsfStreamImpl<T> {
 public:
  // Constructor.
  // @param msf_byte_stream a pointer to the MSF byte stream whose data we
  //     wrap.
  explicit WritableMsfByteStreamImpl(MsfByteStreamImpl<T>* msf_byte_stream);

 protected:
  // This is protected to enforce use of reference counted pointers.
  virtual ~WritableMsfByteStreamImpl();

  // common::BufferWriter implementation.
  uint8_t* GrowBuffer(uint32_t size) override;

  // A reference counted pointer to the MsfByteStreamImpl we are wrapping.
  scoped_refptr<MsfByteStreamImpl<T>> msf_byte_stream_;
};

template <MsfFileType T>
MsfByteStreamImpl<T>::MsfByteStreamImpl()
    : MsfStreamImpl(0), writable_msf_stream_(NULL) {
}

template <MsfFileType T>
MsfByteStreamImpl<T>::~MsfByteStreamImpl() {
}

template <MsfFileType T>
bool MsfByteStreamImpl<T>::Init(const uint8_t* data, uint32_t length) {
  set_length(length);
  data_.resize(length);
  memcpy(this->data(), data, length);
  return true;
}

template <MsfFileType T>
bool MsfByteStreamImpl<T>::Init(MsfStreamImpl* stream) {
  DCHECK(stream != NULL);

  // Read the MSF stream.
  Init(stream, 0, stream->length());

  return true;
}

template <MsfFileType T>
bool MsfByteStreamImpl<T>::Init(MsfStreamImpl* stream,
                                uint32_t pos,
                                uint32_t length) {
  DCHECK(stream != NULL);

  // Init data members.
  set_length(length);
  data_.resize(length);

  if (data_.empty())
    return true;

  // Read the MSF stream.
  if (!stream->ReadBytesAt(pos, length, data())) {
    LOG(ERROR) << "Failed to read MSF stream.";
    return false;
  }

  return true;
}

template <MsfFileType T>
bool MsfByteStreamImpl<T>::ReadBytesAt(size_t pos, size_t count, void* dest) {
  DCHECK(dest != NULL);

  // Don't read beyond the end of the known stream length.
  if (count > length() - pos)
    return false;

  // Read the stream.
  ::memcpy(dest, data() + pos, count);

  return true;
}

template <MsfFileType T>
scoped_refptr<WritableMsfStreamImpl<T>>
MsfByteStreamImpl<T>::GetWritableStream() {
  // This is very not thread-safe! If we want this to be thread-safe, we'll
  // need to be using thread-safe reference counting, and a little smarts here
  // to ensure we're not mid-destructor on some other thread.
  if (writable_msf_stream_ == NULL)
    writable_msf_stream_ = new WritableMsfByteStreamImpl<T>(this);
  return scoped_refptr<WritableMsfStreamImpl<T>>(writable_msf_stream_);
}

template <MsfFileType T>
WritableMsfByteStreamImpl<T>::WritableMsfByteStreamImpl(
    MsfByteStreamImpl<T>* msf_byte_stream) {
  DCHECK(msf_byte_stream != NULL);
  msf_byte_stream_ = msf_byte_stream;

  // If the stream contains data, initialize the BufferWriter.
  if (msf_byte_stream_->length() > 0) {
    SetBuffer(msf_byte_stream_->data(), msf_byte_stream_->length());
  }
}

template <MsfFileType T>
WritableMsfByteStreamImpl<T>::~WritableMsfByteStreamImpl() {
  // Clear our parent's pointer to us.
  msf_byte_stream_->writable_msf_stream_ = NULL;
}

template <MsfFileType T>
uint8_t* WritableMsfByteStreamImpl<T>::GrowBuffer(uint32_t size) {
  DCHECK_GT(size, msf_byte_stream_->data_.size());
  // Resize the vector underlying the MsfByteStreamImpl, and notify the parent
  // MsfStreamImpl object of the new length.
  msf_byte_stream_->data_.resize(size);
  msf_byte_stream_->set_length(size);
  return msf_byte_stream_->data();
}

}  // namespace detail
}  // namespace msf

#endif  // SYZYGY_MSF_MSF_BYTE_STREAM_IMPL_H_
