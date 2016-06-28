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
#include <vector>

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

  // Get the current position of the stream.
  // @returns the current position of the stream.
  virtual size_t Position() const = 0;

  // Tests whether the stream is at end.
  // @returns true iff the stream is at the end.
  virtual bool AtEnd() const = 0;
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
  // @{
  bool Read(size_t len, void* out) override;
  size_t Position() const override;
  bool AtEnd() const override;
  // @}

 private:
  bool IsValid();
  size_t bytes_remaining() const { return len_ - pos_; }

  // Not owned.
  const uint8_t* data_;
  size_t pos_;
  size_t len_;

  DISALLOW_COPY_AND_ASSIGN(BinaryBufferStreamReader);
};

// This class implements a binary stream reader on a byte vector.
class BinaryVectorStreamReader : public BinaryStreamReader {
 public:
  explicit BinaryVectorStreamReader(std::vector<uint8_t>* data);

  // @name BinaryStreamReader implementation.
  // @{
  bool Read(size_t len, void* out) override;
  size_t Position() const override;
  bool AtEnd() const override;
  // @}

 private:
  size_t position_;
  std::vector<uint8_t>* data_;
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

  // Read @p elements of sizeof(@p DataType) bytes into the @p data vector.
  // @param elements the number of elements to read.
  // @param data the read data on success, otherwise contains partial data.
  // @returns true iff @p elements element were successfully read into
  // @p data.
  template <typename DataType>
  bool ReadMultiple(size_t elements, std::vector<DataType>* data) const;

  // Read a zero-terminated string and advance the read position.
  // @param str returns the characters read, less the zero terminator.
  // @returns true if a zero terminating character is encountered.
  bool ReadString(std::string* str) const;
  bool ReadString(std::wstring* str) const;

  // Consumes and discards a minimal number of bytes such that the position
  // of the underlying stream satisifies @p alignment.
  // @param alignment the required alignment.
  // @returns true iff @p alignment is achieved.
  bool AlignTo(size_t alignment) const;

  // Accessor to underlying stream.
  // @returns the underlying stream for the parser.
  BinaryStreamReader* stream_reader() const { return stream_reader_; }

 private:
  // Not owned.
  BinaryStreamReader* stream_reader_;

  DISALLOW_COPY_AND_ASSIGN(BinaryStreamParser);
};

template <typename DataType>
bool BinaryStreamParser::Read(DataType* data) const {
  return ReadBytes(sizeof(*data), data);
}

template <typename DataType>
bool BinaryStreamParser::ReadMultiple(size_t elements,
                                      std::vector<DataType>* data) const {
  DCHECK(data != nullptr);
  // Reserve for the new data to save on reallocs.
  data->reserve(data->size() + elements);
  for (size_t read = 0; read < elements; ++read) {
    DataType tmp = {};
    if (!Read(&tmp))
      return false;

    data->push_back(tmp);
  }

  return true;
}

}  // namespace common

#endif  // SYZYGY_COMMON_BINARY_STREAM_H_
