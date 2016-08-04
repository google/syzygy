// Copyright 2013 Google Inc. All Rights Reserved.
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

#include "syzygy/agent/common/stack_capture.h"

#include <algorithm>

#include "base/logging.h"
#include "syzygy/agent/common/stack_walker.h"
#include "syzygy/core/address_space.h"

// http://blogs.msdn.com/oldnewthing/archive/2004/10/25/247180.aspx
extern "C" IMAGE_DOS_HEADER __ImageBase;

namespace agent {
namespace common {

// The number of bottom frames to skip per stack trace.
size_t StackCapture::bottom_frames_to_skip_ =
    ::common::kDefaultBottomFramesToSkip;

size_t StackCapture::GetSize(size_t max_num_frames) {
  DCHECK_LT(0u, max_num_frames);
  max_num_frames = std::min(max_num_frames, kMaxNumFrames);
  return offsetof(StackCapture, frames_) + max_num_frames * sizeof(void*);
}

size_t StackCapture::GetMaxNumFrames(size_t bytes) {
  if (bytes < offsetof(StackCapture, frames_))
    return 0;
  bytes -= offsetof(StackCapture, frames_);
  bytes /= sizeof(void*);
  return bytes;
}

void StackCapture::AddRef() {
  if (RefCountIsSaturated())
    return;
  DCHECK_GT(kMaxRefCount, ref_count_);
  ++ref_count_;
}

void StackCapture::RemoveRef() {
  DCHECK_LT(0u, ref_count_);
  if (RefCountIsSaturated())
    return;
  --ref_count_;
}

StackId StackCapture::relative_stack_id() const {
  // Note that by design 0 is a not a valid stack ID.
  if (!relative_stack_id_)
    ComputeRelativeStackId();
  return relative_stack_id_;
}

// static
void StackCapture::Init() {
  bottom_frames_to_skip_ = ::common::kDefaultBottomFramesToSkip;
}

void StackCapture::InitFromBuffer(const void* const* frames,
                                  size_t num_frames) {
  DCHECK(frames != NULL);
  DCHECK_LT(0U, num_frames);

  // Determine how many frames we can actually store.
  num_frames_ =
      std::min<uint8_t>(static_cast<uint8_t>(num_frames), max_num_frames_);

  ::memcpy(frames_, frames, num_frames_ * sizeof(*frames_));

  ComputeAbsoluteStackId();
}

void StackCapture::InitFromExistingStack(const StackCapture& stack_capture) {
  DCHECK(stack_capture.frames() != NULL);
  DCHECK_LT(0U, stack_capture.num_frames());

  // Determine how many frames we can actually store.
  num_frames_ = std::min<uint8_t>(
      static_cast<uint8_t>(stack_capture.num_frames()), max_num_frames_);

  ::memcpy(frames_, stack_capture.frames(), num_frames_ * sizeof(*frames_));

  // If the number of frames differs, we recalculate the stack ID.
  if (num_frames_ == stack_capture.num_frames())
    absolute_stack_id_ = stack_capture.absolute_stack_id();
  else
    ComputeAbsoluteStackId();
}

// Disable optimizations so that this function generates a standard frame, and
// don't allow it to be inlined.
#pragma optimize("", off)
void __declspec(noinline) StackCapture::InitFromStack() {
  num_frames_ = static_cast<uint8_t>(agent::common::WalkStack(
      1, max_num_frames_, frames_, &absolute_stack_id_));

  if (bottom_frames_to_skip_) {
    num_frames_ -=
        std::min(static_cast<uint8_t>(bottom_frames_to_skip_), num_frames_);
    ComputeAbsoluteStackId();
  }
}
#pragma optimize("", on)

namespace {

// An address space for storing false modules. These will be reported via
// GetModuleFromAddress, used in ComputeRelativeStackId.
using FalseModuleSpace = core::AddressSpace<uintptr_t, uintptr_t, const char*>;
FalseModuleSpace false_module_space;

// Returns an untracked handle to the module containing the given address, if
// there is one. Returns nullptr if no module is found. If false modules have
// been injected via the testing seam, will first check those.
HMODULE GetModuleFromAddress(void* address) {
  // Try the false module space first.
  if (!false_module_space.empty()) {
    FalseModuleSpace::Range range(reinterpret_cast<uintptr_t>(address), 1);
    auto it = false_module_space.FindContaining(range);
    if (it != false_module_space.end())
      return reinterpret_cast<HMODULE>(it->first.start());
  }

  // Query the OS for any loaded modules that house the given address.
  HMODULE instance = nullptr;
  if (!::GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            static_cast<char*>(address),
                            &instance)) {
    // Because of JITted code it is entirely possible to encounter frames
    // that lie outside of all modules. In this case GetModuleHandlExA will
    // fail, which actually causes an error in base::GetModuleHandleExA.
    return nullptr;
  }
  return instance;
}

}  // namespace

void StackCapture::AddFalseModule(
    const char* name, void* address, size_t length) {
  FalseModuleSpace::Range range(reinterpret_cast<uintptr_t>(address),
                                static_cast<uintptr_t>(length));
  CHECK(false_module_space.Insert(range, name));
}

void StackCapture::ClearFalseModules() {
  false_module_space.Clear();
}

void StackCapture::ComputeAbsoluteStackId() {
  absolute_stack_id_ = StartStackId();

  for (uint8_t i = 0; i < num_frames_; ++i)
    absolute_stack_id_ = UpdateStackId(absolute_stack_id_, frames_[i]);

  absolute_stack_id_ = FinalizeStackId(absolute_stack_id_, num_frames_);
}

void StackCapture::ComputeRelativeStackId() const {
  // We want to ignore the frames relative to our module to be able to get the
  // same trace id even if we update our runtime.
  HANDLE asan_handle = reinterpret_cast<HANDLE>(&__ImageBase);
  DCHECK(asan_handle != NULL);
  DCHECK(!relative_stack_id_);

  relative_stack_id_ = StartStackId();
  for (size_t i = 0; i < num_frames_; ++i) {
    // NULL stack frames may be returned from ::CaptureStackBackTrace.
    // This has been observed on Windows 8.
    if (frames_[i] == nullptr)
      continue;

    // Entirely skip frames that lie inside this module. This allows the
    // relative stack ID to be stable across different versions of the RTL
    // even if stack depth/layout changes.
    HMODULE module = GetModuleFromAddress(frames_[i]);
    if (module == asan_handle)
      continue;

    // Consider frames that are dynamically generated, but consider only their
    // indices, not their addresses.
    uintptr_t frame = i;
    if (module != nullptr) {
      // For frames that fall within a module, consider their relative address
      // in the module.
      frame = reinterpret_cast<uintptr_t>(frames_[i]) -
              reinterpret_cast<uintptr_t>(module);
    }

    relative_stack_id_ =
        UpdateStackId(relative_stack_id_, reinterpret_cast<void*>(frame));
  }

  relative_stack_id_ = FinalizeStackId(relative_stack_id_, num_frames_);

  // We could end up with the value 0, in which case we set it to something
  // else, as 0 is considered uninitialized.
  if (!relative_stack_id_)
    relative_stack_id_ = ~relative_stack_id_;
}

}  // namespace common
}  // namespace agent
