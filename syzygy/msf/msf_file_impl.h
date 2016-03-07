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
//
// Internal implementation details for msf_file.h. Not meant to be included
// directly.

#ifndef SYZYGY_MSF_MSF_FILE_IMPL_H_
#define SYZYGY_MSF_MSF_FILE_IMPL_H_

#include "base/logging.h"
#include "base/memory/ref_counted.h"
#include "syzygy/msf/msf_decl.h"

namespace msf {
namespace detail {

template <MsfFileType T>
MsfFileImpl<T>::MsfFileImpl() {
}

template <MsfFileType T>
MsfFileImpl<T>::~MsfFileImpl() {
  Clear();
}

template <MsfFileType T>
void MsfFileImpl<T>::Clear() {
  streams_.clear();
}

template <MsfFileType T>
scoped_refptr<MsfStreamImpl<T>> MsfFileImpl<T>::GetStream(
    uint32_t index) const {
  DCHECK_LT(index, streams_.size());
  return streams_[index];
}

template <MsfFileType T>
size_t MsfFileImpl<T>::AppendStream(MsfStreamImpl<T>* msf_stream) {
  size_t index = streams_.size();
  streams_.push_back(msf_stream);
  return index;
}

template <MsfFileType T>
void MsfFileImpl<T>::ReplaceStream(uint32_t index,
                                   MsfStreamImpl<T>* msf_stream) {
  DCHECK_LT(index, streams_.size());
  streams_[index] = msf_stream;
}

template <MsfFileType T>
void MsfFileImpl<T>::SetStream(uint32_t index, MsfStreamImpl<T>* msf_stream) {
  if (index >= streams_.size())
    streams_.resize(index + 1);

  streams_[index] = msf_stream;
}

}  // namespace detail
}  // namespace msf

#endif  // SYZYGY_MSF_MSF_FILE_IMPL_H_
