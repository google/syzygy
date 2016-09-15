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

#ifndef SYZYGY_MSF_MSF_STREAM_H_
#define SYZYGY_MSF_MSF_STREAM_H_

#include "base/logging.h"
#include "base/memory/ref_counted.h"
#include "syzygy/common/buffer_writer.h"
#include "syzygy/msf/msf_decl.h"

namespace msf {
namespace detail {

// Forward declaration.
template <MsfFileType T>
class WritableMsfStreamImpl;

// This class represents an MSF stream. It has a stream-like interface that
// allows invoking successive reads through the stream and seeking.
template <MsfFileType T>
class MsfStreamImpl : public base::RefCounted<MsfStreamImpl<T>> {
 public:
  explicit MsfStreamImpl(uint32_t length);

  // Reads @p count bytes of data starting at @p pos into the destination
  // buffer. The caller is responsible for ensuring that the destination
  // buffer has enough space to receive the data.
  //
  // @param pos the position in the stream of the first byte to read.
  // @param dest the buffer to receive the data. May be modified on failure.
  // @param count the number of bytes to read.
  // @returns true if all @p count bytes are read, false otherwise.
  virtual bool ReadBytesAt(size_t pos, size_t count, void* dest) = 0;

  // Returns a pointer to a WritableMsfStreamImpl if the underlying object
  // supports this interface. If this returns non-NULL, it is up to the user to
  // ensure thread safety; each writer should be used exclusively of any other
  // writer, and no reader should be used while a writer is in use. Each of the
  // reader and writer maintains its own cursor, but their view of the data (and
  // its length) will remain in sync.
  //
  // NOTE: This function should act as a factory, with each call returning a
  //     heap allocated reference counted writer. However, since each
  //     WritableMsfStreamImpl is currently implemented using a BufferWriter,
  //     and the BufferWriter maintains its own state internally rather than a
  //     shared state, its possible that one writer causing a resize could
  //     invalidate the internal data pointer held by another writer. As a
  //     workaround, there is only a single writer allowed to be allocated
  //     right now.
  //
  // TODO(chrisha): Clean this up to return an interface, which can be wrapped
  //     in some common stream-writer functionality, reusing BufferWriter.
  //
  // @returns a pointer to a WritableMsfStreamImpl.
  virtual scoped_refptr<WritableMsfStreamImpl<T>> GetWritableStream() {
    return scoped_refptr<WritableMsfStreamImpl<T>>();
  }

  // Gets the stream's length.
  // @returns the total number of bytes in the stream.
  uint32_t length() const { return length_; }

 protected:
  friend base::RefCounted<MsfStreamImpl>;

  // Protected to enforce use of ref-counted pointers at compile time.
  virtual ~MsfStreamImpl();

  // Sets the stream's length.
  void set_length(uint32_t length) { length_ = length; }

 private:
  // The length of the stream.
  uint32_t length_;

  DISALLOW_COPY_AND_ASSIGN(MsfStreamImpl);
};

// Represents a writable MSF stream.
// TODO(chrisha): For now, this inherits from common::BufferWriter, but a far
//     cleaner approach would be to hoist a basic WritableStreamInterface, and
//     make BufferWriter accept a pointer to said interface. The same thing
//     could be done to the common::BufferParser/BufferReader and MsfStreamImpl
//     hierarchy.
template <MsfFileType T>
class WritableMsfStreamImpl : public base::RefCounted<WritableMsfStreamImpl<T>>,
                              public common::BufferWriter {
 public:
  // Constructor.
  WritableMsfStreamImpl() : common::BufferWriter(NULL, 0) {}

 protected:
  friend base::RefCounted<WritableMsfStreamImpl>;

  // Destructor. Protected to enforce use of ref-counted pointers at compile
  // time.
  virtual ~WritableMsfStreamImpl() {}

  // Forwarded from common::BufferWriter.
  virtual uint8_t* GrowBuffer(uint32_t size) = 0;
};

}  // namespace detail

using WritableMsfStream = detail::WritableMsfStreamImpl<kGenericMsfFileType>;
using MsfStream = detail::MsfStreamImpl<kGenericMsfFileType>;

}  // namespace msf

#include "syzygy/msf/msf_stream_impl.h"

#endif  // SYZYGY_MSF_MSF_STREAM_H_
