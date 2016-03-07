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

#include "syzygy/common/buffer_writer.h"

#include "base/logging.h"
#include "syzygy/common/align.h"

namespace common {

BufferWriter::BufferWriter(void* buffer, size_t buffer_length)
    : buffer_(reinterpret_cast<uint8_t*>(buffer)),
      buffer_length_(buffer_length),
      pos_(0) {
  if (buffer_length_ == 0) {
    buffer_ = NULL;
  } else {
    DCHECK(buffer_ != NULL);
  }
}

size_t BufferWriter::RemainingBytes() const {
  // Be careful with overflow.
  if (pos_ >= buffer_length_)
    return 0;
  return buffer_length_ - pos_;
}

bool BufferWriter::Consume(size_t bytes) {
  size_t new_pos = pos_ + bytes;
  if (!EnsureCanWriteFromCurrentPosition(new_pos))
    return false;
  pos_ = new_pos;
  return true;
}

bool BufferWriter::Align(size_t bytes) {
  DCHECK(IsPowerOfTwo(bytes));
  size_t new_pos = AlignUp(pos_, bytes);
  if (!EnsureCanWriteFromCurrentPosition(new_pos))
    return false;
  pos_ = new_pos;
  return true;
}

bool BufferWriter::IsAligned(size_t bytes) const {
  DCHECK(IsPowerOfTwo(bytes));
  return common::IsAligned(pos_, bytes);
}

bool BufferWriter::Write(size_t data_len, const void* data) {
  size_t new_pos = pos_ + data_len;
  if (!EnsureCanWriteFromCurrentPosition(new_pos))
    return false;
  ::memcpy(buffer_ + pos_, data, data_len);
  pos_ = new_pos;
  return true;
}

bool BufferWriter::WriteString(const base::StringPiece& string) {
  return Write(string.size() + 1, string.data());
}

bool BufferWriter::WriteString(const base::StringPiece16& string) {
  return Write(string.size() + 1, string.data());
}

bool BufferWriter::EnsureCanWriteFromCurrentPosition(size_t new_length) {
  // Does this overflow our position counter?
  if (new_length < pos_)
    return false;

  // Already room for it?
  if (new_length <= buffer_length_)
    return true;

  // Attempt to grow.
  uint8_t* new_buffer = GrowBuffer(new_length);
  if (new_buffer == NULL)
    return false;

  buffer_ = new_buffer;
  buffer_length_ = new_length;

  return true;
}

void BufferWriter::SetBuffer(uint8_t* buffer, size_t buffer_length) {
  buffer_length_ = buffer_length;
  if (buffer_length_ == 0) {
    buffer_ = NULL;
  } else {
    DCHECK(buffer != NULL);
    buffer_ = buffer;
  }
}

uint8_t* BufferWriter::GrowBuffer(size_t new_length) {
  // Growing a fixed sized buffer is impossible.
  return NULL;
}

VectorBufferWriter::VectorBufferWriter(std::vector<uint8_t>* vector)
    : BufferWriter(NULL, 0), vector_(vector) {
  DCHECK(vector != NULL);

  if (!vector_->empty())
    SetBuffer(&(*vector_)[0], vector_->size());
}

uint8_t* VectorBufferWriter::GrowBuffer(size_t new_length) {
  // NOTE: While this may appear to be O(N^2), it's actually not. vector is
  // smart enough to double the size of the allocation when a resize causes
  // a reallocation, so it is amortized O(N).
  vector_->resize(new_length);
  return &(*vector_)[0];
}

}  // namespace common
