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

#ifndef SYZYGY_AGENT_ASAN_SCOPED_PAGE_PROTECTIONS_H_
#define SYZYGY_AGENT_ASAN_SCOPED_PAGE_PROTECTIONS_H_

#include <windows.h>
#include <map>
#include "base/callback.h"
#include "base/macros.h"

namespace agent {
namespace asan {

// Helper class for managing page protections during hot-patching.
// Notice that modifying page protections is inherently racy. This class
// performs no locking. It's wise to call this function from under a lock
// that prevents concurrent patching on the same module, and the caller must
// guarantee that the underlying pages are not unloaded during patching.
class ScopedPageProtections {
 public:
  // Optional callback for testing. Notifies of pages whose protections have
  // just been removed.
  using OnUnprotectCallback = base::Callback<void(void* /* page */,
                                                  DWORD /* old_prot */)>;

  ScopedPageProtections() {}
  ~ScopedPageProtections();

  // Makes the page(s) containing @p size bytes starting at @p addr writable.
  // @param addr The address to be written.
  // @param size The number of bytes to be written.
  // @returns true on success, false otherwise.
  bool EnsureContainingPagesWritable(void* addr, size_t size);

  // Restores all page protections that have been modified. This is
  // automatically invoked on destruction. Specifically remembers pages for
  // which restoring protections failed. Repeated calls to this function
  // will try again for those pages.
  // @returns true on success, false otherwise.
  bool RestorePageProtections();

  // Allows settings a callback as a testing seam.
  void set_on_unprotect(OnUnprotectCallback on_unprotect) {
    on_unprotect_ = on_unprotect;
  }

 private:
  // Helper function for EnsureContainingPagesWritable.
  // @pre page Points to the beginning of a page.
  // @param page The address of the page to make writable.
  bool EnsurePageWritable(void* page);

  using UnprotectedPages = std::map<void*, DWORD>;

  // Stores the pages unprotected with their original settings.
  UnprotectedPages unprotected_pages_;

  // Optional callback.
  OnUnprotectCallback on_unprotect_;

  DISALLOW_COPY_AND_ASSIGN(ScopedPageProtections);
};

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_SCOPED_PAGE_PROTECTIONS_H_
