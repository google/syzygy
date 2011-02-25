// Copyright 2011 Google Inc.
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
#include "syzygy/pdb/pdb_byte_stream.h"

#include "base/logging.h"

namespace pdb {

PdbByteStream::PdbByteStream() : PdbStream(0) {
}

PdbByteStream::~PdbByteStream() {
}

bool PdbByteStream::Init(const uint8* data, size_t length) {
  length_ = length;
  data_.reset(new uint8[length_]);
  if (data_.get() == NULL) {
    LOG(ERROR) << "Failed to allocate byte stream";
    return false;
  }

  memcpy(data_.get(), data, length_);
  return true;
}

bool PdbByteStream::Init(PdbStream* stream) {
  // Init data members.
  length_ = stream->length();
  data_.reset(new uint8[length_]);
  if (data_.get() == NULL) {
    LOG(ERROR) << "Failed to allocate byte stream";
    return false;
  }

  // Read the file stream.
  if (!stream->Seek(0)) {
    LOG(ERROR) << "Failed to seek in pdb file stream";
    return false;
  }
  if (stream->Read(data_.get(), length_) != length_) {
    LOG(ERROR) << "Failed to read pdb file stream";
    return false;
  }

  return true;
}

size_t PdbByteStream::ReadBytes(void* dest, size_t count) {
  // Return 0 once we've reached the end of the stream.
  if (pos_ == length_)
    return 0;

  // Don't read beyond the end of the known stream length.
  if (pos_ + count > length_)
    count = length_ - pos_;
  size_t bytes_read = count;

  // Read the stream.
  memcpy(dest, data_.get() + pos_, count);
  pos_ += count;

  return bytes_read;
}

}  // namespace pdb
