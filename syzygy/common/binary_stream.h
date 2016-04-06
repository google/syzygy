// Copyright 2016 Google Inc. All Rights Reserved.
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
// A utility class for safe and easy parsing of binary data streams.

#ifndef SYZYGY_COMMON_BINARY_STREAM_H_
#define SYZYGY_COMMON_BINARY_STREAM_H_

#include <stdint.h>
#include <string>

#include "base/macros.h"
#include "base/strings/string_piece.h"

namespace common {

// A binary stream reader yields a stream of bytes. The underlying
// implementation may be seekable, but this interface is forward-only.
// This is different from BinaryBufferParser et al, in that those classes
// yield pointers into an in-memory buffer, whereas this class always copies
// data to a caller-supplied buffer.
class BinaryStreamReader {
 public:
  // Read @p len bytes forward and return the read bytes in @p out.
  // @param len the number of bytes to read.
  // @param out a buffer for the read bytes, must be at least @p len bytes in
  //     size. On failure the contents of @p out are undefined.
  // @returns true iff @p len bytes were read, false otherwise.
  virtual bool Read(size_t len, void* out) = 0;
};

// This class implements a binary stream reader on an in-memory buffer.
class BinaryBufferStreamReader : public BinaryStreamReader {
 public:
  // Construct a binary stream reader on @p data of @p len bytes.
  // @param data the buffer to read.
  // @param len byte length of @p data.
  // @note the caller must ensure @p data outlives this instance.
  BinaryBufferStreamReader(const void* data, size_t len);

  // Construct a binary stream reader on @p data.
  // @param data the buffer to read.
  // @note the caller must ensure @p data outlives this instance.
  explicit BinaryBufferStreamReader(const base::StringPiece& data);

  // @name BinaryStreamReader implementation.
  bool Read(size_t len, void* out) override;

 private:
  bool IsValid();

  // Not owned.
  const uint8_t* data_;
  size_t bytes_remaining_;

  DISALLOW_COPY_AND_ASSIGN(BinaryBufferStreamReader);
};

// A binary stream reader allows parsing a binary stream forwards.
class BinaryStreamParser {
 public:
  // Constructs a parser on @p stream_reader.
  // @param stream_reader the reader to parse.
  // @note the caller must ensuer @p stream_reader outlives this instance.
  explicit BinaryStreamParser(BinaryStreamReader* stream_reader);

  // Read @p len bytes to @p out.
  // @param len the number of bytes to read.
  // @param out the buffer where @p len bytes will be written.
  // @returns true iff @p len bytes can be read, false otherwise.
  bool ReadBytes(size_t len, void* out) const;

  // Read sizeof(@p DataType) bytes into @p data.
  // @param data the read data on success, otherwise contains partial data.
  // @returns true iff @p data was successfully read.
  template <typename DataType>
  bool Read(DataType* data) const;

  // Read a zero-terminated string and advance the read position.
  // @param str returns the characters read, less the zero terminator.
  // @returns true if a zero terminating character is encountered.
  bool ReadString(std::string* str) const;
  bool ReadString(std::wstring* str) const;

 private:
  // Not owned.
  BinaryStreamReader* stream_reader_;

  DISALLOW_COPY_AND_ASSIGN(BinaryStreamParser);
};

template <typename DataType>
bool BinaryStreamParser::Read(DataType* data) const {
  return ReadBytes(sizeof(*data), data);
}

}  // namespace common

#endif  // SYZYGY_COMMON_BINARY_STREAM_H_
