// Copyright 2015 Google Inc. All Rights Reserved.
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

// A utility class for reading minidumps.

#ifndef SYZYGY_MINIDUMP_MINIDUMP_H_
#define SYZYGY_MINIDUMP_MINIDUMP_H_

#include <windows.h>  // NOLINT
#include <dbghelp.h>

#include <string>
#include <vector>

#include "base/macros.h"
#include "base/files/file_path.h"
#include "base/files/scoped_file.h"

namespace minidump {

namespace internal {

// Provides the default header parsing for the TypedMinidumpStream class.
class DefaultHeaderParser {
 public:
  static size_t Parse(const MINIDUMP_MEMORY_LIST& header);
  static size_t Parse(const MINIDUMP_MODULE_LIST& header);
  static size_t Parse(const MINIDUMP_THREAD_LIST& header);
  static size_t Parse(const MINIDUMP_THREAD_EX_LIST& header);
};

}  // namespace internal

// fwd.
class Minidump;

template <typename HeaderType,
          typename ElementType,
          size_t (*ParseHeaderFunction)(const HeaderType& hdr) =
              internal::DefaultHeaderParser::Parse>
class TypedMinidumpStream;

template <typename ElementType>
class TypedMinidumpStreamIterator;

class Minidump {
 public:
  using TypedMemoryList =
      TypedMinidumpStream<MINIDUMP_MEMORY_LIST, MINIDUMP_MEMORY_DESCRIPTOR>;
  using TypedModuleList =
      TypedMinidumpStream<MINIDUMP_MODULE_LIST, MINIDUMP_MODULE>;
  using TypedThreadList =
      TypedMinidumpStream<MINIDUMP_THREAD_LIST, MINIDUMP_THREAD>;
  using TypedThreadExList =
      TypedMinidumpStream<MINIDUMP_THREAD_EX_LIST, MINIDUMP_THREAD_EX>;

  static const size_t kNoStreamId = static_cast<size_t>(-1);

  class Stream;

  Minidump();
  ~Minidump();

  TypedMemoryList GetMemoryList() const;
  TypedModuleList GetModuleList() const;
  TypedThreadList GetThreadList() const;
  TypedThreadExList GetThreadExList() const;

  // Opens the minidump file at @p path and verifies its header structure.
  // @param path the minidump file to open.
  // @return true on success, false on failure.
  bool Open(const base::FilePath& path);

  // Returns a stream for @p location.
  // @param location defines the offset and length of the returned stream.
  Stream GetStreamFor(const MINIDUMP_LOCATION_DESCRIPTOR& location) const;

  // Returns a stream for the file's @p stream_id.
  // @param stream_id the stream id to return, must be a valid stream id.
  Stream GetStream(size_t stream_id) const;

  // Find the next stream of type @p stream_type.
  // @param prev the previous stream of this type or nullptr.
  // @param stream_type the stream type to look for.
  // @returns a valid stream if one can be found, otherwise an invalid stream.
  Stream FindNextStream(const Stream* prev, size_t stream_type) const;

  // Accessors.
  const std::vector<MINIDUMP_DIRECTORY>& directory() const {
    return directory_;
  }

 private:
  friend class Stream;

  // @name Data accessors.
  // Reads file contents.
  // @param offset the file offset to read from.
  // @param data_size the amount of data to read.
  // @param data where to write the data, must be of size @p data_data size or
  //     larger.
  // @returns true on success, false on failure, including a short read.
  bool ReadBytes(size_t offset, size_t data_size, void* data) const;

  base::ScopedFILE file_;
  std::vector<MINIDUMP_DIRECTORY> directory_;

  DISALLOW_COPY_AND_ASSIGN(Minidump);
};

// A forward-only reading class that bounds reads to streams that make it safe
// and easy to parse minidump streams. Streams are lightweight objects that
// can be freely copied.
// Note that a stream has a current position and a remaining length, and no
// independent start position. It's therefore not possible to "rewind" a
// stream.
class Minidump::Stream {
 public:
  Stream();
  Stream(const Minidump* minidump, size_t offset, size_t length,
         size_t stream_id);

  bool IsValid() const { return minidump_ != nullptr; }

  // @name Functions that read and advance over the read data.
  // @{
  bool ReadAndAdvanceBytes(size_t data_len, void* data);
  bool ReadAndAdvanceBytes(size_t data_len, std::string* data);

  template <class DataType>
  bool ReadAndAdvanceElement(DataType* element);
  bool ReadAndAdvanceString(std::wstring* data);
  // @}

  // Accessors.
  size_t GetRemainingBytes() const { return remaining_length_; }
  size_t stream_id() const { return stream_id_; }
  const Minidump* minidump() const { return minidump_; }

 private:
  const Minidump* minidump_;

  size_t current_offset_;
  size_t remaining_length_;
  size_t stream_id_;
};

// A forward only-iterator for Minidump Streams that yields elements of a
// given, fixed type.
template <typename ElementType>
class TypedMinidumpStreamIterator {
 public:
  // Creates the invalid iterator, which is at end.
  TypedMinidumpStreamIterator() {}

  // Creates a new iterator on @p stream. This iterator will yield
  // @p stream.GetBytesRemaining() / sizeof(ElementType) elements.
  explicit TypedMinidumpStreamIterator(const minidump::Minidump::Stream& stream)
      : stream_(stream) {
    // Make sure the stream contains a range that covers whole elements.
    DCHECK(!stream_.IsValid() ||
           (stream.GetRemainingBytes() % sizeof(ElementType) == 0));
    if (stream_.IsValid() && !stream_.ReadAndAdvanceElement(&element_))
      stream_ = minidump::Minidump::Stream();
  }
  TypedMinidumpStreamIterator(const TypedMinidumpStreamIterator& o)
      : stream_(o.stream), element_(o.element_) {}

  void operator++() {
    if (stream_.IsValid() && !stream_.ReadAndAdvanceElement(&element_))
      stream_ = minidump::Minidump::Stream();
  }

  bool operator!=(const TypedMinidumpStreamIterator& o) const {
    // Two iterators with invalid streams are equal.
    if (!stream_.IsValid() && !o.stream_.IsValid())
      return false;

    if (stream_.IsValid() && o.stream_.IsValid()) {
      // It's not allowed to compare two valid streams from different
      // minidumps.
      DCHECK_EQ(stream_.minidump(), o.stream_.minidump());
    }

    return stream_.IsValid() != o.stream_.IsValid() ||
           stream_.GetRemainingBytes() != o.stream_.GetRemainingBytes();
  }

  const ElementType& operator*() const { return element_; }

 private:
  minidump::Minidump::Stream stream_;
  ElementType element_;
};

// A typed minidump stream allows reading a stream header and iterating over
// the elements of the stream.
template <typename HeaderType,
          typename ElementType,
          size_t (*ParseHeaderFunction)(const HeaderType& hdr)>
class TypedMinidumpStream {
 public:
  using Iterator = TypedMinidumpStreamIterator<ElementType>;

  // Initializes this instance to a stream of type @p stream_type in
  // @p minidump.
  TypedMinidumpStream(const Minidump& minidump, size_t stream_type);
  TypedMinidumpStream(const TypedMinidumpStream& other) = default;

  bool IsValid() const { return element_stream_.IsValid(); }

  const HeaderType& header() const {
    return *reinterpret_cast<const HeaderType*>(header_storage_);
  }

  Iterator begin() const { return Iterator(element_stream_); }
  Iterator end() const { return Iterator(); }

 private:
  // Initializes this instance to a stream of type @p stream_type in
  // @p minidump.
  // @returns true on success, false if the stream doesn't exist, is not
  //     unique, or the stream header can't be read.
  bool Initialize(const Minidump& minidump, size_t stream_type);

  // The stream we read elements from, this must be constrained to the
  // range elements occupy, e.g. positioned at the start of the first element
  // and span a multiple of sizeof(ElementType) bytes.
  Minidump::Stream element_stream_;

  // Some of the MINIDUMP_* headers declare a zero element array as placeholder
  // for the elements. Since such structures can't be directly instantiated,
  // we read them into a byte array instead.
  uint8_t header_storage_[sizeof(HeaderType)];
};

template <typename HeaderType,
          typename ElementType,
          size_t (*ParseHeaderFunction)(const HeaderType& hdr)>
TypedMinidumpStream<HeaderType, ElementType, ParseHeaderFunction>::
    TypedMinidumpStream(const Minidump& minidump, size_t stream_type) {
  memset(header_storage_, 0, sizeof(header_storage_));
  Initialize(minidump, stream_type);
}

template <typename HeaderType,
          typename ElementType,
          size_t (*ParseHeaderFunction)(const HeaderType& hdr)>
bool TypedMinidumpStream<HeaderType, ElementType, ParseHeaderFunction>::
    Initialize(const Minidump& minidump, size_t stream_type) {
  // Find the first stream of the requested type.
  Minidump::Stream stream = minidump.FindNextStream(nullptr, stream_type);
  if (!stream.IsValid())
    return false;

  // Make sure the stream is unique.
  if (minidump.FindNextStream(&stream, stream_type).IsValid())
    return false;

  // Read the header.
  if (!stream.ReadAndAdvanceBytes(sizeof(header_storage_), header_storage_))
    return false;

  size_t number_of_elements = ParseHeaderFunction(header());
  if (stream.GetRemainingBytes() != number_of_elements * sizeof(ElementType))
    return false;

  element_stream_ = stream;
  return true;
}

template <typename DataType>
bool Minidump::Stream::ReadAndAdvanceElement(DataType* element) {
  return ReadAndAdvanceBytes(sizeof(DataType), element);
}

}  // namespace minidump

#endif  // SYZYGY_MINIDUMP_MINIDUMP_H_
