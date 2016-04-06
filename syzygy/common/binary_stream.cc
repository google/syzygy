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

#include "syzygy/common/binary_stream.h"

#include "base/logging.h"

namespace common {

namespace {

template <typename StringType>
bool ReadStringImpl(const BinaryStreamParser* reader, StringType* str) {
  DCHECK_NE(static_cast<StringType*>(nullptr), str);
  DCHECK_NE(static_cast<BinaryStreamParser*>(nullptr), reader);
  str->clear();

  while (true) {
    StringType::value_type chr;
    if (!reader->Read(&chr))
      return false;

    if (chr == '\0')
      return true;

    str->push_back(chr);
  }
}

}  // namespace

BinaryBufferStreamReader::BinaryBufferStreamReader(const void* data, size_t len)
    : data_(reinterpret_cast<const uint8_t*>(data)), bytes_remaining_(len) {
}

BinaryBufferStreamReader::BinaryBufferStreamReader(
    const base::StringPiece& data)
    : data_(reinterpret_cast<const uint8_t*>(data.data())),
      bytes_remaining_(data.length()) {
}

bool BinaryBufferStreamReader::Read(size_t len, void* out) {
  DCHECK(IsValid());

  if (bytes_remaining_ < len)
    return false;

  DCHECK_GE(bytes_remaining_, len);

  memcpy(out, data_, len);
  data_ += len;
  bytes_remaining_ -= len;

  return true;
}

bool BinaryBufferStreamReader::IsValid() {
  if (data_ == nullptr && bytes_remaining_ != 0)
    return false;

  return true;
}

BinaryStreamParser::BinaryStreamParser(BinaryStreamReader* stream_reader)
    : stream_reader_(stream_reader) {
}

bool BinaryStreamParser::ReadBytes(size_t len, void* out) const {
  DCHECK_NE(static_cast<void*>(nullptr), out);

  return stream_reader_->Read(len, out);
}

bool BinaryStreamParser::ReadString(std::string* str) const {
  return ReadStringImpl(this, str);
}

bool BinaryStreamParser::ReadString(std::wstring* str) const {
  return ReadStringImpl(this, str);
}

}  // namespace common
