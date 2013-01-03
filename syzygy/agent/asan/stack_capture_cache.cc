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

#include "syzygy/agent/asan/stack_capture_cache.h"

#include <windows.h>  // NOLINT
#include <string.h>
#include <algorithm>

#include "base/logging.h"

namespace agent {
namespace asan {

void StackCapture::InitFromBuffer(const void* const* frames,
                                  size_t num_frames) {
  DCHECK(frames != NULL);
  DCHECK_LT(0U, num_frames);
  num_frames_ = std::min(num_frames, kMaxNumFrames);
  ::memcpy(frames_, frames, num_frames_ * sizeof(void*));
}

StackCaptureCache::StackCaptureCache() : current_page_(new CachePage(NULL)) {
  CHECK(current_page_ != NULL);
}

StackCaptureCache::~StackCaptureCache() {
  // Iterate through the list of linked pages, deleting the head of the list
  // as we go.
  while (current_page_ != NULL) {
    CachePage* page_to_delete = current_page_;
    current_page_ = current_page_->next_page;
    delete page_to_delete;
  }
}

const StackCapture* StackCaptureCache::SaveStackTrace(
    StackId stack_id, const void* const* frames, size_t num_frames) {
  DCHECK(frames != NULL);
  DCHECK(num_frames != 0);
  DCHECK(current_page_ != NULL);

  // TODO(rogerm): Track "compression ratio" achieved by caching.

  base::AutoLock auto_lock(lock_);

  // If the current page has been entirely consumed, allocate a new page
  // that links to the current page.
  if (current_page_->num_captures_used == kNumCapturesPerPage) {
    current_page_ = new CachePage(current_page_);
    CHECK(current_page_ != NULL);
  }

  // Find the next unused trace capture object.
  StackCapture* unused_trace =
      &current_page_->captures[current_page_->num_captures_used];

  // Attempt to insert it into the known stacks map.
  std::pair<StackMap::const_iterator, bool> result = known_stacks_.insert(
      std::make_pair(stack_id, unused_trace));

  // If the insertion was successful, then this capture has not already been
  // cached and we have to initialize the data.
  if (result.second) {
    unused_trace->InitFromBuffer(frames, num_frames);
    ++(current_page_->num_captures_used);
  }

  // Return the stack trace pointer that is now in the cache.
  return result.first->second;
}

}  // namespace asan
}  // namespace agent
