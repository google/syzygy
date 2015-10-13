// Copyright 2011 Google Inc. All Rights Reserved.
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
// Internal implementation details for msf_stream.h. Not meant to be included
// directly.

#ifndef SYZYGY_MSF_MSF_STREAM_IMPL_H_
#define SYZYGY_MSF_MSF_STREAM_IMPL_H_

#include <vector>

#include "base/logging.h"
#include "syzygy/msf/msf_decl.h"

namespace msf {
namespace detail {

namespace {

const size_t kInvalidLength = 0xFFFFFFFF;

}  // namespace

template <MsfFileType T>
template <typename ItemType>
bool MsfStreamImpl<T>::Read(ItemType* dest, size_t count, size_t* items_read) {
  DCHECK(dest != NULL);
  DCHECK(items_read != NULL);

  size_t requested_bytes = sizeof(ItemType) * count;
  if (requested_bytes == 0) {
    *items_read = count;
    return true;
  }

  size_t seviceable_bytes = requested_bytes;
  if (requested_bytes > bytes_left()) {
    seviceable_bytes = bytes_left() - bytes_left() % sizeof(ItemType);
  }
  if (seviceable_bytes == 0) {
    *items_read = 0;
    return false;
  }

  size_t bytes_read = 0;
  bool result = ReadBytes(dest, seviceable_bytes, &bytes_read);
  *items_read = bytes_read / sizeof(ItemType);
  return result && *items_read == count;
}

template <MsfFileType T>
template <typename ItemType>
bool MsfStreamImpl<T>::Read(ItemType* dest, size_t count) {
  DCHECK(dest != NULL);
  size_t items_read = 0;
  return Read(dest, count, &items_read) && items_read == count;
}

template <MsfFileType T>
template <typename ItemType>
bool MsfStreamImpl<T>::Read(std::vector<ItemType>* dest, size_t count) {
  DCHECK(dest != NULL);
  dest->clear();
  if (sizeof(ItemType) * count > bytes_left())
    return false;
  dest->resize(count);

  if (count == 0)
    return true;

  size_t items_read = 0;
  bool result = Read(&dest->at(0), count, &items_read);
  dest->resize(items_read);
  return result;
}

template <MsfFileType T>
template <typename ItemType>
bool MsfStreamImpl<T>::Read(std::vector<ItemType>* dest) {
  DCHECK(dest != NULL);
  dest->clear();
  if ((bytes_left() % sizeof(ItemType)) != 0)
    return false;
  return Read(dest, bytes_left() / sizeof(ItemType));
}

template <MsfFileType T>
MsfStreamImpl<T>::MsfStreamImpl(size_t length)
    : length_(length == kInvalidLength ? 0 : length), pos_(0) {
}

template <MsfFileType T>
MsfStreamImpl<T>::~MsfStreamImpl() {
}

template <MsfFileType T>
bool MsfStreamImpl<T>::Seek(size_t pos) {
  if (pos > length_)
    return false;

  pos_ = pos;
  return true;
}

}  // namespace detail
}  // namespace msf

#endif  // SYZYGY_MSF_MSF_STREAM_IMPL_H_
