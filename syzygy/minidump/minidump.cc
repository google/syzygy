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

#include "syzygy/minidump/minidump.h"

#include "base/logging.h"
#include "base/files/file_util.h"

namespace minidump {

namespace internal {

size_t DefaultHeaderParser::Parse(const MINIDUMP_MEMORY_LIST& header) {
  return header.NumberOfMemoryRanges;
}

size_t DefaultHeaderParser::Parse(const MINIDUMP_MODULE_LIST& header) {
  return header.NumberOfModules;
}

size_t DefaultHeaderParser::Parse(const MINIDUMP_THREAD_LIST& header) {
  return header.NumberOfThreads;
}

size_t DefaultHeaderParser::Parse(const MINIDUMP_THREAD_EX_LIST& header) {
  return header.NumberOfThreads;
}

}  // namespace internal

Minidump::Minidump() {
}

Minidump::~Minidump() {
}

Minidump::TypedMemoryList Minidump::GetMemoryList() const {
  return TypedMemoryList(*this, MemoryListStream);
}

Minidump::TypedModuleList Minidump::GetModuleList() const {
  return TypedModuleList(*this, ModuleListStream);
}

Minidump::TypedThreadList Minidump::GetThreadList() const {
  return TypedThreadList(*this, ThreadListStream);
}

Minidump::TypedThreadExList Minidump::GetThreadExList() const {
  return TypedThreadExList(*this, ThreadExListStream);
}

bool Minidump::ReadDirectory() {
  // Read the header and validate the signature.
  MINIDUMP_HEADER header = {};
  if (!ReadBytes(0, sizeof(header), &header))
    return false;

  if (header.Signature != MINIDUMP_SIGNATURE || header.NumberOfStreams == 0) {
    return false;
  }

  directory_.resize(header.NumberOfStreams);
  if (!ReadBytes(header.StreamDirectoryRva,
                 header.NumberOfStreams * sizeof(directory_[0]),
                 &directory_.at(0))) {
    return false;
  }

  return true;
}

bool FileMinidump::Open(const base::FilePath& path) {
  file_.reset(base::OpenFile(path, "rb"));
  if (!file_)
    return false;

  return ReadDirectory();
}

Minidump::Stream Minidump::GetStreamFor(
    const MINIDUMP_LOCATION_DESCRIPTOR& location) const {
  return Stream(this, location.Rva, location.DataSize, kNoStreamId);
}

Minidump::Stream Minidump::GetStream(size_t stream_id) const {
  DCHECK_GT(directory_.size(), stream_id);
  const MINIDUMP_DIRECTORY& dir_entry = directory_[stream_id];

  return Stream(this, dir_entry.Location.Rva, dir_entry.Location.DataSize,
                stream_id);
}

Minidump::Stream Minidump::FindNextStream(const Stream* prev,
                                          size_t stream_type) const {
  size_t start = prev ? prev->stream_id() + 1 : 0;

  for (size_t id = start; id < directory_.size(); ++id) {
    if (directory_[id].StreamType == stream_type)
      return GetStream(id);
  }

  // Not found, return an invalid stream.
  return Stream();
}

bool FileMinidump::ReadBytes(size_t offset,
                             size_t data_size,
                             void* data) const {
  DCHECK_LE(offset, static_cast<size_t>(std::numeric_limits<long>::max()));
  if (fseek(file_.get(), static_cast<long>(offset), SEEK_SET) != 0)
    return false;

  if (fread(data, 1, data_size, file_.get()) != data_size)
    return false;

  return true;
}

BufferMinidump::BufferMinidump() : buf_(nullptr), buf_len_(0) {
}

bool BufferMinidump::Initialize(const uint8_t* buf, size_t buf_len) {
  DCHECK(buf);

  buf_ = buf;
  buf_len_ = buf_len;

  return ReadDirectory();
}

bool BufferMinidump::ReadBytes(size_t offset,
                               size_t data_size,
                               void* data) const {
  // Bounds check the request.
  if (offset >= buf_len_ || offset + data_size > buf_len_ ||
      offset + data_size < offset) {  // Test for overflow.
    return false;
  }

  ::memcpy(data, buf_ + offset, data_size);
  return true;
}

Minidump::Stream::Stream()
    : minidump_(nullptr),
      current_offset_(0),
      remaining_length_(0),
      stream_id_(0) {
}

Minidump::Stream::Stream(
    const Minidump* minidump, size_t offset, size_t length, size_t stream_id)
        : minidump_(minidump),
          current_offset_(offset),
          remaining_length_(length),
          stream_id_(stream_id) {
  DCHECK_NE(static_cast<Minidump*>(nullptr), minidump);
}

bool Minidump::Stream::ReadAndAdvanceBytes(size_t data_len, void* data) {
  return ReadBytes(data_len, data) && AdvanceBytes(data_len);
}

bool Minidump::Stream::ReadAndAdvanceBytes(size_t data_len, std::string* data) {
  DCHECK(minidump_ != nullptr);
  DCHECK(data != nullptr);

  data->resize(data_len);
  bool success = ReadAndAdvanceBytes(data_len, &data->at(0));
  if (!success)
    data->resize(0);

  return success;
}

bool Minidump::Stream::ReadAndAdvanceString(std::wstring* data) {
  DCHECK(minidump_ != nullptr);
  DCHECK(data != nullptr);

  ULONG32 size_bytes = 0U;
  if (!ReadAndAdvanceElement(&size_bytes))
    return false;

  // Increment to account for (consume) null-terminating character.
  size_bytes += sizeof(wchar_t);
  if (size_bytes % sizeof(wchar_t))
    return false;
  size_t num_characters = size_bytes / sizeof(wchar_t);

  std::wstring buffer;
  buffer.resize(num_characters);
  if (!ReadAndAdvanceBytes(size_bytes, &buffer.at(0)))
    return false;

  // Drop the extra null-terminating character.
  buffer.resize(num_characters - 1);
  buffer.swap(*data);
  return true;
}

bool Minidump::Stream::ReadBytes(size_t data_len, void* data) {
  DCHECK(minidump_ != nullptr);

  if (data_len > remaining_length_)
    return false;

  if (!minidump_->ReadBytes(current_offset_, data_len, data))
    return false;

  return true;
}

bool Minidump::Stream::AdvanceBytes(size_t data_len) {
  if (data_len > remaining_length_)
    return false;

  current_offset_ += data_len;
  remaining_length_ -= data_len;

  return true;
}

}  // namespace minidump
