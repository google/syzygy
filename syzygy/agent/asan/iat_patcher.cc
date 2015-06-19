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

#include "syzygy/agent/asan/iat_patcher.h"

#include <vector>

#include "base/logging.h"
#include "base/win/iat_patch_function.h"
#include "base/win/pe_image.h"
#include "syzygy/common/align.h"
#include "syzygy/common/com_utils.h"

namespace agent {
namespace asan {

namespace {

// Assume 4K pages.
const size_t kPageSize = 4096;

bool UpdateImportThunk(volatile PIMAGE_THUNK_DATA iat,
                       FunctionPointer function) {
  // Writing to an IAT is inherently racy, as there may be other parties also
  // writing the same page at the same time. This gets ugly where multiple
  // parties mess with page protections, as VirtualProtect causes surprising
  // serialization. We therefore proceed with an abundance of caution, by
  // running inside an exception handler and using a compare-and-swap to
  // detect races on VM operations as well as on assignment.

  __try {
    DWORD old_fn = iat->u1.Function;
    DWORD new_fn = reinterpret_cast<DWORD>(function);
    DWORD prev_fn =
        ::InterlockedCompareExchange(&iat->u1.Function, new_fn, old_fn);
    // Check whether we collided on the assignment.
    if (prev_fn != old_fn)
      return false;
  } __except(EXCEPTION_EXECUTE_HANDLER) {
    // We took an exception, that goes down as failure.
    return false;
  }

  // All shiny!
  return true;
}

class IATPatchWorker {
 public:
  explicit IATPatchWorker(const IATPatchMap& patch);

  bool PatchImage(base::win::PEImage* image);

 private:
  static bool VisitImport(const base::win::PEImage &image, LPCSTR module,
                          DWORD ordinal, LPCSTR name, DWORD hint,
                          PIMAGE_THUNK_DATA iat, PVOID cookie);
  bool OnImport(const char* name, PIMAGE_THUNK_DATA iat);

  // Makes the page containing @p addr writable.
  bool EnsureContainingPageWritable(void* addr);
  // Restores all page protections modified.
  void RestorePageProtections();

  using UnprotectedPages = std::vector<std::pair<void*, DWORD>>;

  // Stores the pages unprotected with their original settings.
  // This is a vector as typically this'll be a single page, two at most in
  // practice.
  UnprotectedPages unprotected_pages_;
  const IATPatchMap& patch_;

  DISALLOW_COPY_AND_ASSIGN(IATPatchWorker);
};

IATPatchWorker::IATPatchWorker(const IATPatchMap& patch) : patch_(patch) {
}

bool IATPatchWorker::PatchImage(base::win::PEImage* image) {
  DCHECK_NE(static_cast<base::win::PEImage*>(nullptr), image);

  // The IAT patching takes place during enumeration.
  bool ret = image->EnumAllImports(&VisitImport, this);

  // Clean up whatever we soiled, success or failure be damned.
  RestorePageProtections();

  return ret;
}

bool IATPatchWorker::VisitImport(
    const base::win::PEImage &image, LPCSTR module, DWORD ordinal,
    LPCSTR name, DWORD hint, PIMAGE_THUNK_DATA iat, PVOID cookie) {
  if (!name)
    return true;

  IATPatchWorker* worker = reinterpret_cast<IATPatchWorker*>(cookie);
  return worker->OnImport(name, iat);
}

bool IATPatchWorker::OnImport(const char* name, PIMAGE_THUNK_DATA iat) {
  auto it = patch_.find(name);
  // See whether this is a function we care about.
  if (it == patch_.end())
    return true;

  // Make the containing page writable.
  if (!EnsureContainingPageWritable(iat))
    return false;

  return UpdateImportThunk(iat, it->second);
}

bool IATPatchWorker::EnsureContainingPageWritable(void* addr) {
  void* page = common::AlignDown(addr, kPageSize);

  // Check whether we've already unprotected this page.
  for (auto unprotected_page : unprotected_pages_) {
    if (unprotected_page.first == page)
      return true;
  }

  // We didn't unprotect this yet, make the page writable.
  MEMORY_BASIC_INFORMATION memory_info {};
  if (!::VirtualQuery(page, &memory_info, sizeof(memory_info))) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "VirtualQuery failed: " << common::LogWe(error);
    return false;
  }

  // It is valid for a PE binary to locate the IAT in an executable code
  // section. It's therefore necessary to preserve the potential executable
  // permission on the IAT page during patching.
  DWORD is_executable = (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) &
                        memory_info.Protect;
  DWORD new_prot = PAGE_READWRITE;
  if (is_executable)
    new_prot = PAGE_EXECUTE_READWRITE;

  DWORD old_prot = 0;
  if (!::VirtualProtect(page, kPageSize, new_prot, &old_prot)) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "VirtualProtect failed: " << common::LogWe(error);
    return false;
  }

  // Make a note that we modified this page, as well as its original settings.
  unprotected_pages_.push_back(std::make_pair(page, old_prot));

  return true;
}

void IATPatchWorker::RestorePageProtections() {
  // Best-effort restore the old page protections.
  for (auto unprotected_page : unprotected_pages_) {
    DWORD old_prot = 0;
    if (!::VirtualProtect(unprotected_page.first,
                          kPageSize,
                          unprotected_page.second, &old_prot)) {
      DWORD error = ::GetLastError();
      LOG(ERROR) << "VirtualProtect failed: " << common::LogWe(error);
    }
  }
}

}  // namespace

bool PatchIATForModule(HMODULE module, const IATPatchMap& patch_map) {
  base::win::PEImage image(module);

  if (!image.VerifyMagic())
    return false;

  IATPatchWorker worker(patch_map);

  return worker.PatchImage(&image);
}

}  // namespace asan
}  // namespace agent
