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
#include "syzygy/agent/asan/scoped_page_protections.h"
#include "syzygy/common/align.h"
#include "syzygy/common/com_utils.h"

namespace agent {
namespace asan {

namespace {

using OnUnprotectCallback = ScopedPageProtections::OnUnprotectCallback;

PatchResult UpdateImportThunk(volatile PIMAGE_THUNK_DATA iat,
                              FunctionPointer function) {
  // Writing to an IAT is inherently racy, as there may be other parties also
  // writing the same page at the same time. This gets ugly where multiple
  // parties mess with page protections, as VirtualProtect causes surprising
  // serialization. We therefore proceed with an abundance of caution, by
  // running inside an exception handler and using a compare-and-swap to
  // detect races on VM operations as well as on assignment.

  __try {
    uintptr_t old_fn = iat->u1.Function;
    uintptr_t new_fn = reinterpret_cast<uintptr_t>(function);
    uintptr_t prev_fn =
        ::InterlockedCompareExchange(&iat->u1.Function, new_fn, old_fn);
    // Check whether we collided on the assignment.
    if (prev_fn != old_fn)
      return PATCH_FAILED_RACY_WRITE;
  } __except(EXCEPTION_EXECUTE_HANDLER) {
    // We took an exception, that goes down as failure. This can occur if we
    // are racing with another thread in our process to patch the IAT entries
    // in the same physical page.
    return PATCH_FAILED_ACCESS_VIOLATION;
  }

  // All shiny!
  return PATCH_SUCCEEDED;
}

class IATPatchWorker {
 public:
  explicit IATPatchWorker(const IATPatchMap& patch);

  PatchResult PatchImage(base::win::PEImage* image);

  void set_on_unprotect(OnUnprotectCallback on_unprotect) {
    scoped_page_protections_.set_on_unprotect(on_unprotect);
  }

 private:
  static bool VisitImport(const base::win::PEImage &image, LPCSTR module,
                          DWORD ordinal, LPCSTR name, DWORD hint,
                          PIMAGE_THUNK_DATA iat, PVOID cookie);
  PatchResult OnImport(const char* name, PIMAGE_THUNK_DATA iat);

  ScopedPageProtections scoped_page_protections_;
  const IATPatchMap& patch_;
  PatchResult result_;

  DISALLOW_COPY_AND_ASSIGN(IATPatchWorker);
};

IATPatchWorker::IATPatchWorker(const IATPatchMap& patch)
    : patch_(patch), result_(PATCH_SUCCEEDED) {
}

PatchResult IATPatchWorker::PatchImage(base::win::PEImage* image) {
  DCHECK_NE(static_cast<base::win::PEImage*>(nullptr), image);

  // This is actually '0', so ORing error conditions to it is just fine.
  result_ = PATCH_SUCCEEDED;

  // The IAT patching takes place during enumeration.
  image->EnumAllImports(&VisitImport, this);

  // Clean up whatever we soiled, success or failure be damned.
  if (!scoped_page_protections_.RestorePageProtections())
    result_ |= PATCH_FAILED_REPROTECT_FAILED;

  return result_;
}

bool IATPatchWorker::VisitImport(
    const base::win::PEImage &image, LPCSTR module, DWORD ordinal,
    LPCSTR name, DWORD hint, PIMAGE_THUNK_DATA iat, PVOID cookie) {
  if (!name)
    return true;

  IATPatchWorker* worker = reinterpret_cast<IATPatchWorker*>(cookie);
  PatchResult result = worker->OnImport(name, iat);
  if (result == PATCH_SUCCEEDED)
    return true;

  // Remember the reason for failure.
  worker->result_ |= result;
  return false;
}

PatchResult IATPatchWorker::OnImport(const char* name, PIMAGE_THUNK_DATA iat) {
  auto it = patch_.find(name);
  // See whether this is a function we care about.
  if (it == patch_.end())
    return PATCH_SUCCEEDED;

  // Make the containing page writable.
  if (!scoped_page_protections_.EnsureContainingPagesWritable(
          iat, sizeof(IMAGE_THUNK_DATA))) {
    return PATCH_FAILED_UNPROTECT_FAILED;
  }

  return UpdateImportThunk(iat, it->second);
}

}  // namespace

PatchResult PatchIATForModule(HMODULE module, const IATPatchMap& patch_map) {
  OnUnprotectCallback dummy_on_unprotect;
  return PatchIATForModule(module, patch_map, dummy_on_unprotect);
}

PatchResult PatchIATForModule(HMODULE module, const IATPatchMap& patch_map,
    OnUnprotectCallback on_unprotect) {
  base::win::PEImage image(module);
  if (!image.VerifyMagic())
    return PATCH_FAILED_INVALID_IMAGE;

  IATPatchWorker worker(patch_map);
  worker.set_on_unprotect(on_unprotect);
  return worker.PatchImage(&image);
}

}  // namespace asan
}  // namespace agent
