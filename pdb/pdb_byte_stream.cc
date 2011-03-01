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

#include <algorithm>
#include "base/logging.h"

namespace pdb {

PdbByteStream::PdbByteStream() : PdbStream(0) {
}

PdbByteStream::~PdbByteStream() {
}

bool PdbByteStream::Init(const uint8* data, int length) {
  set_length(length);
  data_.reset(new uint8[length]);
  if (data_.get() == NULL) {
    LOG(ERROR) << "Failed to allocate byte stream";
    return false;
  }

  memcpy(data_.get(), data, length);
  return true;
}

bool PdbByteStream::Init(PdbStream* stream) {
  // Init data members.
  set_length(stream->length());
  data_.reset(new uint8[length()]);
  if (data_.get() == NULL) {
    LOG(ERROR) << "Failed to allocate byte stream";
    return false;
  }

  // Read the file stream.
  if (!stream->Seek(0)) {
    LOG(ERROR) << "Failed to seek in pdb file stream";
    return false;
  }
  if (stream->Read(data_.get(), length()) != length()) {
    LOG(ERROR) << "Failed to read pdb file stream";
    return false;
  }

  return true;
}

int PdbByteStream::ReadBytes(void* dest, int count) {
  // Return 0 once we've reached the end of the stream.
  if (pos() == length())
    return 0;

  // Don't read beyond the end of the known stream length.
  count = std::min(count, length() - pos());

  // Read the stream.
  memcpy(dest, data_.get() + pos(), count);
  Seek(pos() + count);

  return count;
}

}  // namespace pdb
