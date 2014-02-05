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

#ifndef SYZYGY_PDB_PDB_STREAM_H_
#define SYZYGY_PDB_PDB_STREAM_H_

#include <stdio.h>
#include <vector>

#include "base/basictypes.h"
#include "base/logging.h"
#include "base/memory/ref_counted.h"
#include "syzygy/common/buffer_writer.h"

namespace pdb {

// Forward declaration.
class WritablePdbStream;

// This class represents a PDB stream. It has a stream-like interface that
// allows invoking successive reads through the stream and seeking.
class PdbStream : public base::RefCounted<PdbStream> {
 public:
  explicit PdbStream(size_t length);

  // Reads @p count chunks of size sizeof(ItemType) into the destination buffer.
  // The caller is responsible for ensuring that the destination buffer has
  // enough space to receive the data. Returns the number of items successfully
  // read via @p items_read.
  //
  // @tparam ItemType the type of item to coerce the data to.
  // @param dest the destination array.
  // @param count the number of elements to read.
  // @param items_read pointer to receive the number of items successfully read.
  // @returns true on success.
  template <typename ItemType>
  bool Read(ItemType* dest, size_t count, size_t* items_read);

  // Reads @p count chunks of size sizeof(ItemType) into the destination buffer.
  // The caller is responsible for ensuring that the destination buffer has
  // enough space to receive the data.
  //
  // @tparam ItemType the type of item to coerce the data to.
  // @param dest the destination array.
  // @param count the number of elements to read.
  // @returns true on success.
  template <typename ItemType>
  bool Read(ItemType* dest, size_t count);

  // Reads @p count elements of size sizeof(ItemType) into the provided
  // vector of elements. Resizes @p dest to the number of elements that were
  // successfully read.
  //
  // @tparam ItemType the type of item to coerce the data to.
  // @param dest the destination vector.
  // @param count the number of elements to read.
  // @returns true if @p dest was populated with @p count elements, false
  //     otherwise. The number of elements actually read is indicated by the
  //     length of @p dest.
  template <typename ItemType>
  bool Read(std::vector<ItemType>* dest, size_t count);

  // Fills the provided vector with elements read from this stream. The bytes
  // remaining in the stream must be an even multiple of sizeof(ItemType).
  // Resizes @p dest to the number of elements read.
  //
  // @tparam ItemType the type of item to coerce the data to.
  // @param dest the destination vector.
  // @returns true if the remaining bytes in the stream were read into the
  //     provided vector, false otherwise. The number of elements actually read
  //     is indicated by the length of @p dest.
  template <typename ItemType>
  bool Read(std::vector<ItemType>* dest);

  // Reads @p count bytes of data into the destination buffer. The caller is
  // responsible for ensuring that the destination buffer has enough space to
  // receive the data. @p bytes_read will hold the number of bytes read. If
  // there was insufficient data but some bytes were read, returns false and
  // returns the number of bytes read via @p bytes_read.
  //
  // @param dest the buffer to receive the data.
  // @param count the number of bytes to read.
  // @param bytes_read pointer that will receive the number of bytes read.
  // @returns true if all @p count bytes are read, false otherwise.
  virtual bool ReadBytes(void* dest, size_t count, size_t* bytes_read) = 0;

  // Returns a pointer to a WritablePdbStream if the underlying object supports
  // this interface. If this returns non-NULL, it is up to the user to ensure
  // thread safety; each writer should be used exclusively of any other writer,
  // and no reader should be used while a writer is in use. Each of the reader
  // and writer maintains its own cursor, but their view of the data (and its
  // length) will remain in sync.
  //
  // NOTE: This function should act as a factory, with each call returning a
  //     heap allocated reference counted writer. However, since each
  //     WritablePdbStream is currently implemented using a BufferWriter, and
  //     the BufferWriter maintains its own state internally rather than a
  //     shared state, its possible that one writer causing a resize could
  //     invalidate the internal data pointer held by another writer. As a
  //     workaround, there is only a single writer allowed to be allocated
  //     right now.
  //
  // TODO(chrisha): Clean this up to return an interface, which can be wrapped
  //     in some common stream-writer functionality, reusing BufferWriter.
  //
  // @returns a pointer to a WritablePdbStream.
  virtual scoped_refptr<WritablePdbStream> GetWritablePdbStream() {
    return scoped_refptr<WritablePdbStream>();
  }

  // Sets the current read position.
  bool Seek(size_t pos);

  // Gets the stream's length.
  // @returns the total number of bytes in the stream.
  size_t length() const { return length_; }

  // Gets the stream's read position.
  // @returns the number of bytes already read.
  size_t pos() const { return pos_; }

  // Gets the number of bytes left to read in the stream.
  // @returns the number of bytes left.
  size_t bytes_left() const { return length_ - pos_; }

 protected:
  friend base::RefCounted<PdbStream>;

  // Protected to enforce use of ref-counted pointers at compile time.
  virtual ~PdbStream();

  // Sets the stream's length.
  void set_length(size_t length) { length_ = length; }

 private:
  // The length of the stream.
  size_t length_;

  // The read position within the stream.
  size_t pos_;

  DISALLOW_COPY_AND_ASSIGN(PdbStream);
};

// Represents a writable PDB stream.
// TODO(chrisha): For now, this inherits from common::BufferWriter, but a far
//     cleaner approach would be to hoist a basic WritableStreamInterface, and
//     make BufferWriter accept a pointer to said interface. The same thing
//     could be done to the common::BufferParser/BufferReader and PdbStream
//     hierarchy.
class WritablePdbStream : public base::RefCounted<WritablePdbStream>,
                          public common::BufferWriter {
 public:
  // Constructor.
  WritablePdbStream() : common::BufferWriter(NULL, 0) { }

 protected:
  friend base::RefCounted<WritablePdbStream>;

  // Destructor. Protected to enforce use of ref-counted pointers at compile
  // time.
  virtual ~WritablePdbStream() { }

  // Forwarded from common::BufferWriter.
  virtual uint8* GrowBuffer(size_t size) = 0;
};

template <typename ItemType>
bool PdbStream::Read(ItemType* dest, size_t count, size_t* items_read) {
  DCHECK(dest != NULL);
  DCHECK(items_read != NULL);

  size_t byte_size = sizeof(ItemType) * count;
  if (byte_size > bytes_left())
    return false;

  size_t bytes_read = 0;
  bool result = ReadBytes(dest, byte_size, &bytes_read);
  *items_read = bytes_read / sizeof(ItemType);
  return result && *items_read == count;
}

template <typename ItemType>
bool PdbStream::Read(ItemType* dest, size_t count) {
  DCHECK(dest != NULL);
  size_t items_read = 0;
  return Read(dest, count, &items_read) && items_read == count;
}

template <typename ItemType>
bool PdbStream::Read(std::vector<ItemType>* dest, size_t count) {
  DCHECK(dest != NULL);
  dest->clear();
  if (sizeof(ItemType) * count > bytes_left())
    return false;
  dest->resize(count);

  if (count == 0)
    return true;

  size_t items_read = 0;
  bool result = Read(&dest->at(0), count, &items_read);
  dest->resize(items_read);
  return result;
}

template <typename ItemType>
bool PdbStream::Read(std::vector<ItemType>* dest) {
  DCHECK(dest != NULL);
  dest->clear();
  if ((bytes_left() % sizeof(ItemType)) != 0)
    return false;
  return Read(dest, bytes_left() / sizeof(ItemType));
}

}  // namespace pdb

#endif  // SYZYGY_PDB_PDB_STREAM_H_
