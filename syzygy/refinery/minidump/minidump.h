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
//
// A utility class for reading minidumps.

#ifndef SYZYGY_REFINERY_MINIDUMP_MINIDUMP_H_
#define SYZYGY_REFINERY_MINIDUMP_MINIDUMP_H_

#include <windows.h>  // NOLINT
#include <dbghelp.h>

#include <vector>

#include "base/macros.h"
#include "base/files/file_path.h"
#include "base/files/scoped_file.h"

namespace refinery {

// fwd.
class Minidump;

class Minidump {
 public:
  static const size_t kNoStreamId = static_cast<size_t>(-1);

  class Stream;

  Minidump();
  ~Minidump();

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
// and easy to parse minidump streams.
class Minidump::Stream {
 public:
  Stream();
  Stream(const Minidump* minidump, size_t offset, size_t length,
         size_t stream_id);

  bool IsValid() const { return minidump_ != nullptr; }
  bool ReadBytes(size_t data_len, void* data);

  template <class DataType>
  bool ReadElement(DataType* element);

  size_t GetRemainingBytes() const { return remaining_length_; }
  size_t stream_id() const { return stream_id_; }

 private:
  const Minidump* minidump_;

  size_t current_offset_;
  size_t remaining_length_;
  size_t stream_id_;
};

template <typename DataType>
bool Minidump::Stream::ReadElement(DataType* element) {
  return ReadBytes(sizeof(DataType), element);
}

}  // namespace refinery

#endif  // SYZYGY_REFINERY_MINIDUMP_MINIDUMP_H_
