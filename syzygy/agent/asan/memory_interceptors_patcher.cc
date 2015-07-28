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

#include "syzygy/agent/asan/memory_interceptors_patcher.h"

#include <map>

#include "base/win/pe_image.h"
#include "syzygy/agent/asan/memory_interceptors.h"
#include "syzygy/agent/asan/scoped_page_protections.h"
#include "syzygy/agent/asan/shadow.h"
#include "syzygy/common/align.h"

// The linker satisfies this symbol. This gets us a pointer to our own module
// when we're loaded.
extern "C" IMAGE_DOS_HEADER __ImageBase;

namespace agent {
namespace asan {

namespace {

static const char kProbesSectionName[] = ".probes";
static const char kReadOnlySectionName[] = ".rdata";

// Gets the extents of the given section, writing them to |begin| and |end|.
// Returns true on success, false otherwise. Logs verbosely on failure.
bool GetSectionExtents(const base::win::PEImage& image,
                       const char* section_name,
                       uint8_t** begin,
                       uint8_t** end) {
  DCHECK_NE(static_cast<char*>(nullptr), section_name);
  DCHECK_NE(static_cast<uint8_t**>(nullptr), begin);
  DCHECK_NE(static_cast<uint8_t**>(nullptr), end);

  const IMAGE_SECTION_HEADER* section_header =
      image.GetImageSectionHeaderByName(section_name);
  if (section_header == nullptr) {
    LOG(ERROR) << "Image does not contain a " << kProbesSectionName
               << " section.";
    return false;
  }
  *begin = reinterpret_cast<uint8_t*>(image.GetDosHeader()) +
      section_header->VirtualAddress;
  *end = *begin + section_header->Misc.VirtualSize;

  return true;
}

// An exception filter that triggers only for access violations.
DWORD AccessViolationFilter(EXCEPTION_POINTERS* e) {
  if (e->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
    return EXCEPTION_EXECUTE_HANDLER;
  return EXCEPTION_CONTINUE_SEARCH;
}

// Return status used by WritePointerImpl.
enum WritePointerStatus {
  kWritePointerSuccess,
  kWritePointerUnexpectedPreviousValue,
  kWritePointerAccessViolation,
};

// Safely writes the given value to the given address under an exception
// handler. If this fails with an access violation then it silently swallows
// the exception. Returns a detailed status.
WritePointerStatus WritePointerImpl(const void* expected_old_value,
                                    const void* value,
                                    volatile void** address) {
  DCHECK_NE(static_cast<void*>(nullptr), address);

  // The value to be written is not necessarily pointer aligned and may require
  // two writes. Determine the bounds of pointer aligned data to be written.
  volatile uint8_t* dst = reinterpret_cast<volatile uint8_t*>(address);
  volatile uint8_t* dst_begin = ::common::AlignDown(dst, sizeof(uintptr_t));
  volatile uint8_t* dst_end =
      ::common::AlignUp(dst + sizeof(uintptr_t), sizeof(uintptr_t));
  size_t offset = reinterpret_cast<uintptr_t>(address) % sizeof(uintptr_t);

  // Copy the original range of bytes. This will serve as a template for
  // reading and writing.
  uintptr_t old_values[2] = {};
  uintptr_t new_values[2] = {};
  ::memcpy(old_values, const_cast<uint8_t*>(dst_begin), dst_end - dst_begin);
  ::memcpy(new_values, old_values, sizeof(old_values));

  // The data we copied should have the expected original pointer, otherwise
  // somebody has been tinkering at the same time as us.
  void* copied_old_value = *reinterpret_cast<void**>(
      reinterpret_cast<uint8_t*>(old_values) + offset);
  if (copied_old_value != expected_old_value)
    return kWritePointerUnexpectedPreviousValue;

  // Stamp the new value into the template.
  *reinterpret_cast<void**>(reinterpret_cast<uint8_t*>(new_values) + offset) =
      const_cast<void*>(value);

  // Up until now everything has been 'safe' reads. Stamp in the new data,
  // but use interlocked operations to be extra careful.
  __try {
    uintptr_t old_value = ::InterlockedCompareExchange(
        reinterpret_cast<volatile uintptr_t*>(dst_begin),
        new_values[0], old_values[0]);
    if (old_value != old_values[0])
      return kWritePointerUnexpectedPreviousValue;

    // If no second write is required (the actual pointer value being written
    // was aligned) then the write is complete.
    if (dst_end - dst_begin == sizeof(uintptr_t))
      return kWritePointerSuccess;

    // Otherwise try to write the second half of the pointer.
    old_value = ::InterlockedCompareExchange(
        reinterpret_cast<volatile uintptr_t*>(dst_begin) + 1,
        new_values[1], old_values[1]);
    if (old_value != old_values[1])
      return kWritePointerUnexpectedPreviousValue;
  } __except (AccessViolationFilter(GetExceptionInformation())) {  // NOLINT
    return kWritePointerAccessViolation;
  }

  return kWritePointerSuccess;
}

// Safely writes the given value to the given address under an exception
// handler. Returns true on succes, false on failure. Logs verbosely on
// failure.
bool WritePointer(const void* expected_old_value,
                  const void* value,
                  volatile void** address) {
  DCHECK_NE(static_cast<void*>(nullptr), address);

  WritePointerStatus status =
      WritePointerImpl(expected_old_value, value, address);
  switch (status) {
    case kWritePointerSuccess:
      return true;
    case kWritePointerUnexpectedPreviousValue: {
      LOG(ERROR) << "Unexpected previous value. Racy write to this location?";
      return false;
    }
    case kWritePointerAccessViolation: {
      LOG(ERROR) << "Access violation during write. Racy protection changes?";
      return false;
    }
  }

  NOTREACHED();
  return false;
}

bool PatchMemoryInterceptorShadowReferencesInternalImpl(
    HMODULE module,
    const uint8_t* current_shadow_memory,
    const void** shadow_memory_references,
    const uint8_t* new_shadow_memory,
    ScopedPageProtections* scoped_page_protections) {
  DCHECK_NE(static_cast<HMODULE>(nullptr), module);
  DCHECK_NE(static_cast<uint8_t*>(nullptr), current_shadow_memory);
  DCHECK_NE(static_cast<void**>(nullptr), shadow_memory_references);
  DCHECK_NE(static_cast<uint8_t*>(nullptr), new_shadow_memory);
  DCHECK_NE(static_cast<ScopedPageProtections*>(nullptr),
            scoped_page_protections);

  base::win::PEImage image(module);
  if (!image.VerifyMagic()) {
    LOG(ERROR) << "Does not appear to be a valid image handle.";
    return false;
  }

  uint8_t* probes_begin = nullptr;
  uint8_t* probes_end = nullptr;
  if (!GetSectionExtents(image, kProbesSectionName, &probes_begin,
                         &probes_end)) {
    return false;
  }

  uint8_t* rdata_begin = nullptr;
  uint8_t* rdata_end = nullptr;
  if (!GetSectionExtents(image, kReadOnlySectionName, &rdata_begin,
                         &rdata_end)) {
    return false;
  }

  // Iterate over the shadow memory references and patch them.
  uint8_t** cursor = reinterpret_cast<uint8_t**>(const_cast<void**>(
      shadow_memory_references));
  for (; *cursor != nullptr; ++cursor) {
    // Ensure the table entry itself is within the .rdata section.
    if (reinterpret_cast<uint8_t*>(cursor) < rdata_begin ||
        reinterpret_cast<uint8_t*>(cursor) + sizeof(uintptr_t) >= rdata_end) {
      LOG(ERROR) << "Shadow reference table entry is outside of "
                 << kProbesSectionName << " section";
      return false;
    }

    // Ensure the reference is within the probes section.
    if (*cursor < probes_begin || *cursor + sizeof(uintptr_t) >= probes_end) {
      LOG(ERROR) << "Shadow reference is outside of " << kProbesSectionName
                 << " section";
      return false;
    }

    // The shadow reference must be a direct pointer to the current shadow.
    volatile uint8_t** shadow_ref =
        reinterpret_cast<volatile uint8_t**>(*cursor);
    if (*shadow_ref != current_shadow_memory) {
      // In the general case the offsets may be anything. However, given how the
      // probes are currently generated the offsets must be zero.
      LOG(ERROR) << "Invalid shadow memory reference.";
      return false;
    }

    // Update the shadow memory reference to point to the new shadow memory.
    if (!scoped_page_protections->EnsureContainingPagesWritable(
            shadow_ref, sizeof(*shadow_ref))) {
      LOG(ERROR) << "Failed to make page writable.";
      return false;
    }
    if (!WritePointer(current_shadow_memory, new_shadow_memory,
                      reinterpret_cast<volatile void**>(shadow_ref))) {
      return false;
    }
  }

  return true;
}

bool PatchMemoryInterceptorShadowReferencesImpl(
    HMODULE module,
    const uint8_t* current_shadow_memory,
    const void** shadow_memory_references,
    const uint8_t* new_shadow_memory) {
  DCHECK_NE(static_cast<HMODULE>(nullptr), module);
  DCHECK_NE(static_cast<uint8_t*>(nullptr), current_shadow_memory);
  DCHECK_NE(static_cast<void**>(nullptr), shadow_memory_references);
  DCHECK_NE(static_cast<uint8_t*>(nullptr), new_shadow_memory);

  bool did_succeed = true;
  ScopedPageProtections scoped_page_protections;
  if (!PatchMemoryInterceptorShadowReferencesInternalImpl(
          module, current_shadow_memory, shadow_memory_references,
          new_shadow_memory, &scoped_page_protections)) {
    did_succeed = false;
  }

  // Try hard to restore the page protections.
  bool protections_restored = false;
  for (size_t i = 0; i < 3; ++i) {
    if (scoped_page_protections.RestorePageProtections()) {
      protections_restored = true;
      break;
    }
  }
  if (!protections_restored)
    did_succeed = false;

  return did_succeed;
}

}  // namespace

bool PatchMemoryInterceptorShadowReferences(const uint8_t* old_shadow_memory,
                                            const uint8_t* new_shadow_memory) {
  DCHECK_NE(static_cast<uint8_t*>(nullptr), new_shadow_memory);
  if (!PatchMemoryInterceptorShadowReferencesImpl(
          reinterpret_cast<HMODULE>(&__ImageBase), old_shadow_memory,
          asan_shadow_references, new_shadow_memory)) {
    return false;
  }
  return true;
}

}  // namespace asan
}  // namespace agent
