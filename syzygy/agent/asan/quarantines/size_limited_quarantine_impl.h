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

#include <algorithm>

namespace agent {
namespace asan {
namespace quarantines {

template <typename OT, typename SFT>
PushResult SizeLimitedQuarantineImpl<OT, SFT>::Push(const Object& object) {
  PushResult result = {false, 0};
  size_t size = size_functor_(object);
  if (max_object_size_ != kUnboundedSize && size > max_object_size_)
    return result;

  // This will contain the size of quarantine after the implementation of push,
  // whether successful or not.
  size_t new_size = 0;
  {
    // Note that if a thread gets preempted here, the size/count will be wrong,
    // until the thread resumes (the size will eventually become consistent).
    ScopedQuarantineSizeCountLock size_count_lock(size_count_);
    new_size = size_count_.Increment(size, 1);
  }

  // This is the size of the quarantine before the call to PushImpl and is
  // needed to calculate the old color and infer potential transitions.
  size_t old_size = new_size - size;
  if (PushImpl(object)) {
    result.push_successful = true;
  } else {
    // Decrementing here is not guaranteed to give the same size as before the
    // increment, as the whole sequence is not atomic. Trimming might still be
    // required and will be signaled if need be.
    ScopedQuarantineSizeCountLock size_count_lock(size_count_);
    new_size = size_count_.Decrement(size, 1);
  }

  // Note that because GetQuarantineColor can return the wrong color (see note
  // in its implementation), this function might miss a transition to RED/BLACK
  // which would result in not signaling the asynchronous thread (under
  // signaling). This is a tradeoff for not having to lock the overbudget size.
  // As for the synchronous trimming, unless the wrong color is returned forever
  // (which would obviously be a bug), it will eventually be signaled when BLACK
  // is returned (regardless of transition).
  TrimColor new_color = GetQuarantineColor(new_size);
  TrimColor old_color = GetQuarantineColor(old_size);

  if (new_color == TrimColor::BLACK) {
    // If the current color is BLACK, always request synchronous trimming. As
    // stated above, this ensures that regardless of the transition, the
    // quarantine will eventually get trimmed (no "run away" situation should be
    // possible).
    result.trim_status |= TrimStatusBits::SYNC_TRIM_REQUIRED;
    if (old_color < TrimColor::RED) {
      // If going from GREEN/YELLOW to BLACK, also schedule asynchronous
      // trimming (this is by design to improve the performance).
      result.trim_status |= TrimStatusBits::ASYNC_TRIM_REQUIRED;
    }
  } else if (new_color == TrimColor::RED) {
    if (old_color < TrimColor::RED) {
      // If going from GREEN/YELLOW to RED, schedule asynchronous trimming.
      result.trim_status |= TrimStatusBits::ASYNC_TRIM_REQUIRED;
    }
  }
  return result;
}

template <typename OT, typename SFT>
PopResult SizeLimitedQuarantineImpl<OT, SFT>::Pop(Object* object) {
  DCHECK_NE(static_cast<Object*>(NULL), object);
  PopResult result = {false, TrimColor::GREEN};

  if (max_quarantine_size_ == kUnboundedSize)
    return result;

  {
    // Never pop if already in GREEN as this is the lowest bound.
    // Note that because GetQuarantineColor can return the wrong color (see note
    // in its implementation), this verification might not always be correct
    // which might cause either an over popping or an under popping. Either way,
    // that is acceptable as the extra or missing pop operations are not harmful
    // and the size will eventually get consistency.
    ScopedQuarantineSizeCountLock size_count_lock(size_count_);
    if (GetQuarantineColor(size_count_.size()) == TrimColor::GREEN)
      return result;
  }

  if (!PopImpl(object))
    return result;

  // Note that if a thread gets preempted here, the size/count will be wrong,
  // until the thread resumes.
  size_t size = size_functor_(*object);
  ScopedQuarantineSizeCountLock size_count_lock(size_count_);

  size_t new_size = size_count_.Decrement(size, 1);

  // Return success and the new quarantine color.
  result.pop_successful = true;
  // See note above about GetQuarantineColor potentially returning the wrong
  // color.
  result.trim_color = GetQuarantineColor(new_size);
  return result;
}

template<typename OT, typename SFT>
void SizeLimitedQuarantineImpl<OT, SFT>::Empty(
    ObjectVector* objects) {
  DCHECK_NE(static_cast<ObjectVector*>(NULL), objects);
  EmptyImpl(objects);

  // In order for the quarantine to remain long-term consistent we need to
  // remove a size and count consistent with the output of EmptyImpl. Simply
  // setting the size and count to zero could introduce inconsistency, as they
  // may not yet reflect the contributions of some of the elements returned by
  // EmptyImpl.
  size_t net_size = 0;
  for (size_t i = 0; i < objects->size(); ++i) {
    size_t size = size_functor_(objects->at(i));
    net_size += size;
  }

  ScopedQuarantineSizeCountLock size_count_lock(size_count_);
  size_count_.Decrement(net_size, objects->size());
}

template <typename OT, typename SFT>
size_t SizeLimitedQuarantineImpl<OT, SFT>::GetCountForTesting() {
  ScopedQuarantineSizeCountLock size_count_lock(size_count_);
  return size_count_.count();
}

template<typename OT, typename SFT>
size_t SizeLimitedQuarantineImpl<OT, SFT>::GetLockId(
    const Object& object) {
  return GetLockIdImpl(object);
}

template<typename OT, typename SFT>
void SizeLimitedQuarantineImpl<OT, SFT>::Lock(size_t id) {
  LockImpl(id);
}

template<typename OT, typename SFT>
void SizeLimitedQuarantineImpl<OT, SFT>::Unlock(size_t id) {
  UnlockImpl(id);
}

template <typename OT, typename SFT>
TrimColor SizeLimitedQuarantineImpl<OT, SFT>::GetQuarantineColor(
    size_t size) const {
  // The quarantine is allowed to go overbudget by |overbudget_size_|.
  // Furthermore, to enable hysteresis, 3 size limits are set that define 4
  // zones, each representing a color. These colors are as following:
  //   GREEN if the current size is lower than |max_quarantine_size_ -
  //     overbudget_size_|
  //   YELLOW if it's over GREEN but lower than |max_quarantine_size_|
  //   RED if it's over YELLOW but lower than
  //     |max_quarantine_size_ + overbudget_size_|
  //   BLACK if it's over |max_quarantine_size_ + overbudget_size_|
  //
  // YELLOW is basically the equivalent of the single limit that exists when the
  // deferred free thread is not enabled. A trim will always cross an entire
  // color. An async trim is triggered once the size crossed into the RED or
  // BLACK zone from either YELLOW or GREEN and will bring it back to GREEN.
  // Also, if it hits BLACK, then a sync trim is requested which will bring it
  // back to YELLOW. Synchronous and asynchronous trimming can therefore happen
  // simultanously. This is by design.

  if (max_quarantine_size_ == kUnboundedSize)
    return TrimColor::GREEN;

  // Note that this is racy by design, to avoid contention. If
  // |overbudget_size_| is modified before the end of the function, the wrong
  // color can be returned. Functions that call GetQuarantineColor must deal
  // with the consequences accordingly. But since |overbudget_size_| is only
  // modified when the thread is started or shutdown, this is seldom an issue.
  base::subtle::Atomic32 overbudget_size =
      base::subtle::NoBarrier_Load(&overbudget_size_);

  if (size <= max_quarantine_size_ - overbudget_size)
    return TrimColor::GREEN;

  if (size <= max_quarantine_size_)
    return TrimColor::YELLOW;

  if (size <= max_quarantine_size_ + overbudget_size)
    return TrimColor::RED;

  return TrimColor::BLACK;
}

template <typename OT, typename SFT>
size_t SizeLimitedQuarantineImpl<OT, SFT>::GetMaxSizeForColorForTesting(
    TrimColor color) const {
  // Note that this is racy by design, to avoid contention. If
  // |overbudget_size_| is modified before the end of the function, the wrong
  // size can be returned. Since this function is only used in testing, this is
  // not an issue.
  if (color == TrimColor::BLACK || max_quarantine_size_ == kUnboundedSize)
    return kUnboundedSize;

  switch (color) {
    case TrimColor::GREEN:
      return max_quarantine_size_ -
             base::subtle::NoBarrier_Load(&overbudget_size_);
    case TrimColor::YELLOW:
      return max_quarantine_size_;
    case TrimColor::RED:
      return max_quarantine_size_ +
             base::subtle::NoBarrier_Load(&overbudget_size_);
  }

  // Should never hit this.
  NOTREACHED();
  return kUnboundedSize;
}

template <typename OT, typename SFT>
void SizeLimitedQuarantineImpl<OT, SFT>::SetOverbudgetSize(
    size_t overbudget_size) {
  const size_t kMinBudgetSize = 1024;
  // |overbudget_size_ | cannot exceed half of |max_quarantine_size_| and must
  // be at least 1024 (1k), or 0 (which removes the hysteresis).
  size_t new_size = 0;
  if (overbudget_size > 0) {
    new_size = std::max(overbudget_size, kMinBudgetSize);
    new_size = std::min(new_size, max_quarantine_size_ / 2);
  }
  auto old_size =
      base::subtle::NoBarrier_AtomicExchange(&overbudget_size_, new_size);
  // This can only be called twice, once to set the size and a second time to
  // reset it to 0.
  DCHECK((old_size == 0) != (new_size == 0));
}

}  // namespace quarantines
}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_QUARANTINES_SIZE_LIMITED_QUARANTINE_IMPL_H_
