// Copyright 2014 Google Inc. All Rights Reserved.
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
// A utility class for safe and easy parsing of binary buffers.

#ifndef SYZYGY_COMMON_BUFFER_PARSER_H_
#define SYZYGY_COMMON_BUFFER_PARSER_H_

#include "base/basictypes.h"

namespace common {

// A binary buffer parser
class BinaryBufferParser {
 public:
  BinaryBufferParser(const void* data, size_t data_len);

  // Accessors.
  const void* data() const { return data_; }
  size_t data_len() const { return data_len_; }

  // Check whether the buffer contains the range of data from @p pos to
  // @p pos + @p data_len.
  // @param pos the byte position of the start of the data range.
  // @param data_len the byte length of the data range.
  // @returns true iff the range of bytes from @p pos to @p pos + @p data_len.
  bool Contains(size_t pos, size_t data_len);

  // Retrieve a pointer into the buffer if the requested data is contained
  // in our buffer.
  // @param pos the position to get a pointer to.
  // @param data_len the amount of data expected behind @p pos.
  // @param data_ptr on success will contain a pointer to @p pos in data.
  // @returns true iff Contains(pos, data_len).
  bool GetAt(size_t pos, size_t data_len, const void** data_ptr);

  // Retrieve a typed pointer into the buffer if the requested data
  // is contained in our buffer.
  // @note Does not check @p pos for appropriate alignment.
  template <class DataType>
  bool GetAt(size_t pos, size_t data_len, const DataType** data_ptr) {
    return GetAt(pos, data_len, reinterpret_cast<const void**>(data_ptr));
  }

  // Retrieve a typed pointer into the buffer if the requested structure
  // fits into our buffer at position @pos.
  // @note Does not check @p pos for appropriate alignment.
  template <class DataType>
  bool GetAt(size_t pos, const DataType** data_ptr) {
    return GetAt(pos, sizeof(**data_ptr), data_ptr);
  }

  // Get a zero terminated string starting at the byte offset @p pos.
  // @param pos the byte offset where the string starts.
  // @param ptr on success returns the string pointer.
  // @param len on success returns the string character length.
  // @returns true on success, e.g. there's a zero termiator in the buffer
  //    after @p pos, or false on failure, when @p pos is outside the buffer
  //    or there is no zero terminator in the buffer after @p pos.
  // @note this function does not check @pos for appropriate alignment.
  bool GetStringAt(size_t pos, const char** ptr, size_t* len);
  bool GetStringAt(size_t pos, const wchar_t** ptr, size_t* len);

 protected:
  const int8* data_;
  size_t data_len_;
};

// A binary buffer reader allows reading sequentially from a binary buffer,
// as well as peeking at the current position without moving it.
class BinaryBufferReader {
 public:
  BinaryBufferReader(const void* data, size_t data_len);

  // Accessors.
  size_t pos() const { return pos_; }
  void set_pos(size_t pos) { pos_ = pos; }

  // Calculate the number of bytes remaining in the buffer.
  // @returns the number of bytes remaining in the buffer.
  size_t RemainingBytes() const;
  // Advance the read position by @p bytes.
  // @param bytes the number of bytes to advance the read position.
  // @returns true iff the new position is in our buffer.
  bool Consume(size_t bytes);

  // Align the read position to the next even multiple of @p bytes.
  // @param bytes the byte alignment, must be a power of two.
  // @returns true iff the new position is in our buffer.
  bool Align(size_t bytes);

  // Check whether the read position is aligned to bytes.
  // @param bytes the byte alignment to check, must be a power of two.
  // @returns true iff the current position is an integer multiple of @p bytes.
  bool IsAligned(size_t bytes);

  // Retrieve a pointer into our buffer, without moving the read position.
  bool Peek(size_t data_len, const void** data);
  template <class DataType>
  bool Peek(size_t data_len, const DataType** data_ptr) {
    return Peek(data_len, reinterpret_cast<const void**>(data_ptr));
  }
  template <class DataType>
  bool Peek(const DataType** data_ptr) {
    return Peek(sizeof(**data_ptr), data_ptr);
  }

  // Retrieve a pointer into our buffer and advance the read position.
  bool Read(size_t data_len, const void** data);
  template <class DataType>
  bool Read(size_t data_len, const DataType** data_ptr) {
    return Read(data_len, reinterpret_cast<const void**>(data_ptr));
  }
  template <class DataType>
  bool Read(const DataType** data_ptr) {
    return Read(sizeof(**data_ptr), data_ptr);
  }

  // Retrieve a zero-terminated string from our buffer without
  // advancing the read position.
  bool PeekString(const char** str, size_t* str_len);
  bool PeekString(const wchar_t** str, size_t* str_len);

  // Retrieve a zero-terminated string from our buffer and
  // advance the read position.
  bool ReadString(const char** str, size_t* str_len);
  bool ReadString(const wchar_t** str, size_t* str_len);

 private:
  // The buffer we read from.
  BinaryBufferParser parser_;
  // Current position.
  size_t pos_;
};

}  // namespace common

#endif  // SYZYGY_COMMON_BUFFER_PARSER_H_
