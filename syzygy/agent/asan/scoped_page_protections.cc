// Copyright 2015 Google Inc. All Rights Reserved.
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
// Declares a helper class for use in performing hot-patching operations.
// The class takes care of modifying page protections as the patcher works.

#include "syzygy/agent/asan/scoped_page_protections.h"

#include "base/logging.h"
#include "syzygy/agent/asan/constants.h"
#include "syzygy/common/align.h"
#include "syzygy/common/com_utils.h"

namespace agent {
namespace asan {

ScopedPageProtections::~ScopedPageProtections() {
  RestorePageProtections();
}

bool ScopedPageProtections::EnsureContainingPagesWritable(void* addr,
                                                          size_t size) {
  // Ensure the entire space of pages covered by the provided range is
  // writable.
  uint8_t* cursor = reinterpret_cast<uint8_t*>(addr);
  uint8_t* page_begin = common::AlignDown(cursor, GetPageSize());
  uint8_t* page_end = common::AlignUp(cursor + size, GetPageSize());
  while (page_begin < page_end) {
    if (!EnsurePageWritable(page_begin))
      return false;
    page_begin += GetPageSize();
  }

  return true;
}

bool ScopedPageProtections::RestorePageProtections() {
  // Grab the list of pages to unprotect.
  UnprotectedPages to_unprotect;
  unprotected_pages_.swap(to_unprotect);

  // Best-effort restore the old page protections, and remember pages for
  // which the effort failed.
  bool did_succeed = true;
  for (const auto& unprotected_page : to_unprotect) {
    DWORD old_prot = 0;
    if (!::VirtualProtect(unprotected_page.first, GetPageSize(),
                          unprotected_page.second, &old_prot)) {
      DWORD error = ::GetLastError();
      LOG(ERROR) << "VirtualProtect failed: " << common::LogWe(error);

      // Pages that failed to be unprotected are reinserted into the set of
      // pages being tracked.
      bool inserted = unprotected_pages_.insert(unprotected_page).second;
      DCHECK(inserted);

      did_succeed = false;
    }
  }

  return did_succeed;
}

bool ScopedPageProtections::EnsurePageWritable(void* page) {
  DCHECK(common::IsAligned(page, GetPageSize()));

  // Check whether we've already unprotected this page.
  if (unprotected_pages_.find(page) != unprotected_pages_.end())
    return true;

  // We didn't unprotect this yet, make the page writable.
  MEMORY_BASIC_INFORMATION memory_info{};
  if (!::VirtualQuery(page, &memory_info, sizeof(memory_info))) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "VirtualQuery failed: " << common::LogWe(error);
    return false;
  }

  // Preserve executable status while patching.
  DWORD is_executable = (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                         PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) &
                        memory_info.Protect;
  DWORD new_prot = PAGE_READWRITE;
  if (is_executable)
    new_prot = PAGE_EXECUTE_READWRITE;

  DWORD old_prot = 0;
  if (!::VirtualProtect(page, GetPageSize(), new_prot, &old_prot)) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "VirtualProtect failed: " << common::LogWe(error);
    return false;
  }

  // Make a note that we modified this page, as well as its original settings.
  bool inserted =
      unprotected_pages_.insert(std::make_pair(page, old_prot)).second;
  DCHECK(inserted);

  // Callback as a testing seam.
  if (!on_unprotect_.is_null())
    on_unprotect_.Run(page, old_prot);

  return true;
}

}  // namespace asan
}  // namespace agent
