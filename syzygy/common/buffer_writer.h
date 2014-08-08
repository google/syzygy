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
// Utility class for constructing a buffer of binary data. There are two
// implementations provided:
//
// 1. BufferWriter: for writing to fixed-size preallocated buffers; and,
// 2. VectorBufferWriter: for writing to growable std::vector<uint8>-backed
//                        buffers.
//
// Intended usage:
//
//   uint8 buffer[1024];
//   FixedBufferWriter writer(buffer, sizeof(buffer));
//   writer.WriteString(some_string);
//   writer.AlignUp(sizeof(uint32));
//   writer.Write(number_of_elements, array_of_uint32s);
//   writer.Write(some_complex_object);

#ifndef SYZYGY_COMMON_BUFFER_WRITER_H_
#define SYZYGY_COMMON_BUFFER_WRITER_H_

#include <vector>

#include "base/strings/string_piece.h"

namespace common {

// A helper class for creating buffers of binary data. This allows writing of
// arbitrary binary objects with helpers for controlling alignment, etc. This is
// a pure virtual base class, allowing this class to easily be extended for
// targeting other growable buffer types. Derived classes need only provide a
// constructor and implement the GrowBuffer function.
class BufferWriter {
 public:
  // Constructor.
  // @param buffer the initial destination buffer.
  // @param buffer_length the initial length of the buffer, in bytes.
  BufferWriter(void* buffer, size_t buffer_length);

  // @{
  // Simple accessors and mutators.
  size_t pos() const { return pos_; }
  void set_pos(size_t pos) { pos_ = pos; }
  size_t length() const { return buffer_length_; }
  // @}

  // Returns the remaining bytes in the buffer. If we're using an expandable
  // vector and this returns zero, the next write will cause the vector to
  // grow.
  // @returns the number of allocated bytes remaining.
  size_t RemainingBytes() const;

  // Advance the write position by @p bytes. This skips over the existing data.
  // @param bytes the number of bytes to skip.
  // @returns true if there was sufficient room for the seek, false otherwise.
  bool Consume(size_t bytes);

  // Advances the output position to the next multiple of @p bytes.
  // @param bytes the alignment, which must be a power of two.
  // @returns true if there was sufficient room for the align, false otherwise.
  bool Align(size_t bytes);

  // Determines if the current output position is aligned.
  // @param bytes the alignment to confirm, which must be a multiple of two.
  // @returns true if aligned, false otherwise.
  bool IsAligned(size_t bytes) const;

  // Writes the given data to the buffer, advancing the write pointer.
  // @param data_len the data length in bytes.
  // @param data the buffer of data to write.
  // @returns true if there was sufficient room for the write, false otherwise.
  bool Write(size_t data_len, const void* data);

  // Writes the given data to the buffer, advancing the write pointer. Writes
  // sizeof(T) * element_count bytes.
  // @param element_count the number of elements to write.
  // @param elements the array of elements to write.
  // @returns true if there was sufficient room for the write, false otherwise.
  template<typename T> bool Write(size_t element_count, const T* elements);

  // Writes the given data to the buffer, advancing the write pointer. Writes
  // sizeof(T) bytes.
  // @param element the element to write.
  // @returns true if there was sufficient room for the write, false otherwise.
  template<typename T> bool Write(const T& element);

  // @{
  // Writes the given zero terminated string to the buffer. Writes
  // (string.size() + 1) * sizeof(string[0]) bytes.
  // @param string the string to write.
  // @returns true if there was sufficient room for the write, false otherwise.
  bool WriteString(const base::StringPiece& string);
  bool WriteString(const base::StringPiece16& string);
  // @}

 protected:
  // This is intended to be called by the constructors of derived classes.
  // @param buffer the initial destination buffer.
  // @param buffer_length the initial length of the buffer, in bytes.
  void SetBuffer(uint8* buffer, size_t buffer_length);

  // This function is responsible for ensuring that the buffer has the expected
  // size. It should return a pointer to the buffer with sufficient size, or
  // return NULL if the resize is not possible. If the resize causes a
  // reallocation, this routine is also responsible for copying all data up to
  // and the current position pos_ into the new buffer. Upon success this is
  // also responsible for cleaning up the memory used by the old buffer if a
  // resize was required. Upon failure to resize the old buffer must be
  // maintained as the BufferWriter will keep a pointer to it.
  //
  // NOTE: Implementations of this function should be careful not to cause an
  //     O(N^2) algorithm. They should generally do something like vector
  //     and actually double the buffer size when a reallocation is needed.
  //     Further calls to GrowBuffer can simply return the same buffer as long
  //     as new_length < the actual allocated length.
  //
  // @param new_length the new buffer length requested.
  // @returns a pointer to the buffer of size at least @p new_length bytes on
  //     success, a NULL pointer on failure.
  virtual uint8* GrowBuffer(size_t new_length);

 private:
  // This handles overflow checking, determines if the buffer needs to be
  // grown, delegates to GrowBuffer, and updates internal structures as
  // necessary. Upon a successful call buffer_ points to a buffer of size at
  // least @p new_length, and buffer_length_ is set to @p new_length.
  // @param new_length  the new buffer length requested.
  // @returns true on success, false otherwise.
  bool EnsureCanWriteFromCurrentPosition(size_t new_length);

  uint8* buffer_;
  size_t buffer_length_;
  size_t pos_;
};

class VectorBufferWriter : public BufferWriter {
 public:
  // Constructor for writing to an expandable buffer based on a vector.
  // @param vector the vector to be written to. Writing will start at position
  //     zero, and once we've exceeded the current size of the vector writes
  //     will cause it to grow.
  explicit VectorBufferWriter(std::vector<uint8>* vector);

 protected:
  virtual uint8* GrowBuffer(size_t size);

  std::vector<uint8>* vector_;
};

template<typename T> bool BufferWriter::Write(size_t element_count,
                                              const T* elements) {
  return Write(element_count * sizeof(T),
               static_cast<const void*>(elements));
}

template<typename T> bool BufferWriter::Write(const T& element) {
  return Write(sizeof(T), static_cast<const void*>(&element));
}

}  // namespace common

#endif  // SYZYGY_COMMON_BUFFER_WRITER_H_
