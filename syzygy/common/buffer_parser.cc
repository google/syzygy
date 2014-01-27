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

#include "syzygy/common/buffer_parser.h"

#include "base/logging.h"

namespace common {

namespace {

template <class CharType>
bool GetStringAtImpl(BinaryBufferParser* parser, size_t pos,
    const CharType** ptr, size_t* len) {
  DCHECK(parser != NULL);
  const CharType* start = NULL;
  if (!parser->GetAt(pos, sizeof(*start), &start))
    return false;

  size_t num_chars = (parser->data_len() - pos) / sizeof(*start);
  for (size_t strlen = 0; strlen < num_chars; ++strlen) {
    if (start[strlen] == '\0') {
      *len = strlen;
      *ptr = start;
      return true;
    }
  }

  return false;
}

}  // namespace

BinaryBufferParser::BinaryBufferParser(const void* data, size_t data_len)
    : data_(reinterpret_cast<const int8*>(data)), data_len_(data_len) {
}

bool BinaryBufferParser::Contains(size_t pos, size_t data_len) {
  // Guard against overflow.
  if (pos < 0 || pos > data_len_)
    return false;
  if (data_len < 0 || data_len > data_len_)
    return false;

  // Make sure the range is fully contained in the buffer.
  if (pos + data_len > data_len_)
    return false;

  return true;
}

bool BinaryBufferParser::GetAt(size_t pos,
                               size_t data_len,
                               const void** data_ptr) {
  if (!Contains(pos, data_len))
    return false;

  *data_ptr = data_ + pos;
  return true;
}

bool BinaryBufferParser::GetStringAt(size_t pos, const char** ptr,
    size_t* len) {
  return GetStringAtImpl(this, pos, ptr, len);
}

bool BinaryBufferParser::GetStringAt(size_t pos, const wchar_t** ptr,
    size_t* len) {
  return GetStringAtImpl(this, pos, ptr, len);
}


BinaryBufferReader::BinaryBufferReader(const void* data, size_t data_len)
    : parser_(data, data_len), pos_(0) {
}

size_t BinaryBufferReader::RemainingBytes() const {
  DCHECK(pos_ <= parser_.data_len());
  return parser_.data_len() - pos_;
}

bool BinaryBufferReader::Consume(size_t bytes) {
  if (!parser_.Contains(pos_ + bytes, 0))
    return false;

  pos_ += bytes;
  return true;
}

bool BinaryBufferReader::Align(size_t bytes) {
  DCHECK((bytes & (bytes - 1)) == 0);
  size_t mask = bytes - 1;
  size_t offset = (bytes - (pos_ & mask)) & mask;
  if (offset == 0)
    return true;

  return Consume(offset);
}

bool BinaryBufferReader::IsAligned(size_t bytes) {
  DCHECK((bytes & (bytes - 1)) == 0);
  size_t mask = bytes - 1;
  size_t offset = (bytes - (pos_ & mask)) & mask;
  return offset == 0;
}

bool BinaryBufferReader::Peek(size_t data_len, const void** data) {
  return parser_.GetAt(pos_, data_len, data);
}

bool BinaryBufferReader::Read(size_t data_len, const void** data) {
  if (!Peek(data_len, data))
    return false;

  bool consumed = Consume(data_len);
  DCHECK(consumed == true);
  return true;
}

bool BinaryBufferReader::PeekString(const char** str, size_t* str_len) {
  return parser_.GetStringAt(pos_, str, str_len);
}

bool BinaryBufferReader::PeekString(const wchar_t** str, size_t* str_len) {
  return parser_.GetStringAt(pos_, str, str_len);
}

bool BinaryBufferReader::ReadString(const char** str, size_t* str_len) {
  size_t len = 0;
  if (!PeekString(str, &len))
    return false;

  bool consumed = Consume(len + 1);
  DCHECK(consumed == true);
  *str_len = len;
  return true;
}

bool BinaryBufferReader::ReadString(const wchar_t** str, size_t* str_len) {
  size_t len = 0;
  if (!PeekString(str, &len))
    return false;

  bool consumed = Consume((len + 1) * sizeof(**str));
  DCHECK(consumed == true);
  *str_len = len;
  return true;
}

}  // namespace common
