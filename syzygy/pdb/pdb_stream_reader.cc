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
#include "syzygy/pdb/pdb_stream_reader.h"


namespace pdb {

PdbStreamReaderWithPosition::PdbStreamReaderWithPosition(PdbStream* stream)
    : start_offset_(0), pos_(0), length_(stream->length()), stream_(stream) {
  DCHECK_NE(static_cast<PdbStream*>(nullptr), stream_);
}

PdbStreamReaderWithPosition::PdbStreamReaderWithPosition(size_t start_offset,
                                                         size_t len,
                                                         PdbStream* stream)
    : start_offset_(start_offset), pos_(0), length_(len), stream_(stream) {
  DCHECK_NE(static_cast<PdbStream*>(nullptr), stream_);
  DCHECK_GE(stream_->length(), start_offset_ + length_);
  DCHECK_LE(start_offset_, start_offset_ + length_);
}

PdbStreamReaderWithPosition::PdbStreamReaderWithPosition()
    : start_offset_(0), pos_(0), length_(0), stream_(nullptr) {
}

void PdbStreamReaderWithPosition::SetStream(size_t start_offset,
                                            size_t len,
                                            PdbStream* stream) {
  DCHECK_EQ(static_cast<PdbStream*>(nullptr), stream_.get());
  DCHECK_NE(static_cast<PdbStream*>(nullptr), stream);
  DCHECK_GE(stream->length(), start_offset + len);

  start_offset_ = start_offset;
  length_ = len;
  stream_ = stream;
}

bool PdbStreamReaderWithPosition::Read(size_t len, void* out) {
  DCHECK(stream_);
  if (pos_ + len > length_)
    return false;

  if (!stream_->ReadBytesAt(start_offset_ + pos_, len, out))
    return false;

  pos_ += len;
  DCHECK_LE(pos_, length_);

  return true;
}

size_t PdbStreamReaderWithPosition::Position() const {
  DCHECK(stream_);
  return pos_;
}

bool PdbStreamReaderWithPosition::AtEnd() const {
  DCHECK(stream_);
  DCHECK_LE(pos_, length_);
  return pos_ == length_;
}

bool PdbStreamReaderWithPosition::Consume(size_t len) {
  DCHECK(stream_);
  if (pos_ + len > length_)
    return false;

  pos_ += len;
  DCHECK_LE(pos_, length_);

  return true;
}

}  // namespace pdb
