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
//
// Internal implementation of a size-limited quarantine. This file is not
// meant to be included directly.

#ifndef SYZYGY_AGENT_ASAN_QUARANTINES_SIZE_LIMITED_QUARANTINE_IMPL_H_
#define SYZYGY_AGENT_ASAN_QUARANTINES_SIZE_LIMITED_QUARANTINE_IMPL_H_

namespace agent {
namespace asan {
namespace quarantines {

template<typename OT, typename SFT>
bool SizeLimitedQuarantineImpl<OT, SFT>::Push(
    const Object& object) {
  SizeFunctor get_size;
  size_t size = get_size(object);
  if (max_object_size_ != 0 && size > max_object_size_)
    return false;
  if (max_quarantine_size_ != 0 && size > max_quarantine_size_)
    return false;
  if (!PushImpl(object))
    return false;
  size_ += size;
  ++count_;
  return true;
}

template<typename OT, typename SFT>
bool SizeLimitedQuarantineImpl<OT, SFT>::Pop(
    Object* object) {
  DCHECK_NE(static_cast<Object*>(NULL), object);
  if (max_quarantine_size_ == 0 || size_ <= max_quarantine_size_)
    return false;
  PopImpl(object);
  SizeFunctor get_size;
  size_t size = get_size(*object);
  DCHECK_LE(size, size_);
  size_ -= size;
  --count_;
  return true;
}

template<typename OT, typename SFT>
void SizeLimitedQuarantineImpl<OT, SFT>::Empty(
    ObjectVector* objects) {
  DCHECK_NE(static_cast<ObjectVector*>(NULL), objects);
  EmptyImpl(objects);
  size_ = 0;
  count_ = 0;
}

template<typename OT, typename SFT>
size_t SizeLimitedQuarantineImpl<OT, SFT>::GetCount() const {
  return count_;
}

}  // namespace quarantines
}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_QUARANTINES_SIZE_LIMITED_QUARANTINE_IMPL_H_
