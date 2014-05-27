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
// Declares a DirectAllocation class. This is a wrapper class that handles
// making (large) memory allocations directly from the operating system. It
// encapsulates various utilities for setting up and dealing with guard
// pages, reserved vs committed memory, etc.
//
// A DirectAllocation object doesn't do much in the way of error handling;
// if an operation fails the object may be left in an inconsistent state
// (for example, while changing page protections). At this point the safest
// thing to do is simply to free the allocation and destroy the object.

#ifndef SYZYGY_AGENT_ASAN_DIRECT_ALLOCATION_H_
#define SYZYGY_AGENT_ASAN_DIRECT_ALLOCATION_H_

#include <map>
#include <set>

#include "syzygy/agent/asan/asan_shadow.h"

namespace agent {
namespace asan {

class DirectAllocation {
 public:
  // The default allocation alignment matches that used by the shadow.
  static const size_t kDefaultAlignment = Shadow::kShadowGranularity;

  // Describes the justification of the allocated memory within the larger
  // spread of pages that were returned by the OS.
  enum Justification {
    // Justification will be decided at the time of allocation, based on the
    // left/right redzone and guard page settings. All things being equal this
    // will prefer to catch overflows when it makes sense as they are more
    // common.
    kAutoJustification,
    // Justification will be to the left. Preferentially catches underflows.
    kLeftJustification,
    // Justification will be to the right. Preferentially catches overflows.
    kRightJustification,
  };

  // Describes the state of the pages backing the allocation.
  enum MemoryState {
    // No pages have been set aside for the allocation.
    kNoPages,
    // Address space has been reserved for the allocation, but no physical
    // memory yet backs it.
    kReservedPages,
    // The allocation is committed, and backed by physical memory.
    kAllocatedPages,
  };

  // Describes the state of access to the pages backing the allocation.
  enum ProtectionState {
    // None of the pages are protected, and they are all read/write.
    kNoPagesProtected,
    // The body of the allocation is unprotected, but the guard pages
    // are protected.
    kGuardPagesProtected,
    // The entire allocation is protected.
    kAllPagesProtected,
  };

  // Constructor.
  DirectAllocation();

  // Destructor. Frees the allocation.
  ~DirectAllocation();

  // @name Configures the allocation. These may only be called when the
  //     memory is not allocated (in kNoPages state).
  // @{
  // @param size The size of the allocation.
  void set_size(size_t size);
  // @param alignment The alignment of the allocation. Must be a power of two,
  //     between 1 and GetPageSize().
  void set_alignment(size_t alignment);
  // @param left_guard_page If true then will allocate a left guard page.
  void set_left_guard_page(bool left_guard_page);
  // @param right_guard_page If true then will allocate a right guard page.
  void set_right_guard_page(bool right_guard_page);
  // @param left_redzone_size The minimum size of the left red zone.
  void set_left_redzone_size(size_t left_redzone_size);
  // @param right_redzone_size The minimum size of the right red zone.
  void set_right_redzone_size(size_t right_redzone_size);
  // @param justification The justification of the allocation.
  void set_justification(Justification justification);
  // @}

  // @name Accessors.
  // @{
  size_t size() const { return size_; }
  size_t alignment() const { return alignment_; }
  bool left_guard_page() const { return left_guard_page_; }
  bool right_guard_page() const { return right_guard_page_; }
  size_t left_redzone_size() const { return left_redzone_size_; }
  size_t right_redzone_size() const { return right_redzone_size_; }
  Justification justification() const { return justification_; }
  MemoryState memory_state() const { return memory_state_; }
  ProtectionState protection_state() const { return protection_state_; }
  void* pages() const { return pages_; }
  // @}

  // @name State changes. These toggle the allocation between the various
  //     states of interest in the context of an ASAN instrumented binary.
  // @{
  // This is the state the memory should be in while the allocation is live.
  // The memory is reserved and committed, and any guard pages are protected.
  // Memory state will be kAllocatedPages and protection state will be
  // kGuardPagesProtected or kNoPagesProtected.
  // @returns true on success, false otherwise.
  bool Allocate();
  // This transitions the memory to a quarantined state. The memory remains
  // committed and all of the pages are protected to catch invalid accesses.
  // Memory state will be kAllocatedPages and protection state will be
  // kAllPagesProtected.
  // @returns true on success, false otherwise.
  bool QuarantineKeepContents();
  // This transitions the memory to a quarantined state, but discards the
  // contents of the allocation. The address space remains reserved and all of
  // the pages are protected to catch invalid accesses. Memory state will be
  // kReservedPages and protection state will be kAllPagesProtected.
  // @returns true on success, false otherwise.
  bool QuarantineDiscardContents();
  // This transitions the memory to a free state. The memory is decommitted and
  // the address space is returned entirely to the OS. Memory state will be
  // kNoPages and protection state will be kNoPagesProtected.
  // @returns true on success, false otherwise.
  bool Free();
  // @}

  // @name Accessors for the underlying allocation itself. These are only valid
  //     after a valid memory state transition, or FinalizeParameters has been
  //     called.
  // @{
  // @returns the number of pages that were reserved/allocated from the OS.
  size_t GetPageCount() const;
  // @return the number of bytes that were reserved/allocated from the OS.
  size_t GetTotalSize() const;
  // @returns a pointer to the left redzone, NULL if there is none.
  void* GetLeftRedZone() const;
  // @returns a pointer to the right redzone, NULL if there is none.
  void* GetRightRedZone() const;
  // @returns a pointer to the allocation itself, NULL if there is none.
  void* GetAllocation() const;
  // @returns a pointer to the left guard page, or NULL if there is none. If
  //     there is one this is the same as GetLeftRedZone.
  void* GetLeftGuardPage() const;
  // @returns a pointer to the right guard page, or NULL if there is none.
  void* GetRightGuardPage() const;
  // @returns the number of left guard pages that are present.
  size_t GetLeftGuardPageCount() const;
  // @returns the number of right guard pages that are present.
  size_t GetRightGuardPageCount() const;
  // @returns true if guard pages are present.
  bool HasGuardPages() const;
  // @}

  // @returns the size of a page on the current system.
  static size_t GetPageSize();

 protected:
  // Finalizes the configured parameters, calculating actual redzone sizes,
  // auto-justification, etc. This is automatically called on any transition
  // away from kNoPages, but may be manually called if so desired.
  void FinalizeParameters();

  // @name Controls the pages backing the allocation.
  // @{
  // Transitions from kReservedPages or kAllocatedPages to kNoPages. Sets
  // protection to kNoPagesProtected, to be consistent with the default state
  // of the class.
  // @returns true on success, false otherwise.
  bool ToNoPages();
  // Transitions from kNoPages or kAllocatedPages to kReservedPages. Sets
  // protection to kAllPagesProtected.
  // @returns true on success, false otherwise.
  bool ToReservedPages();
  // Transitions from kNoPages to kReservedPages to kAllocatedPages. Sets
  // protection to kNoPagesProtected.
  // @returns true on success, false otherwise.
  bool ToAllocatedPages();
  // @}

  // @name Protection state transition functions. These are only able to be
  //     called when the memory is fully allocated.
  // @{
  // Transitions from kGuardPagesProtected or kAllPagesProtected to
  // kNoPagesProtected.
  // @return true on success, false otherwise.
  bool ProtectNoPages();
  // Transitions from kNoPagesProtected or kAllPagesProtected to
  // kGuardPagesProtected.
  // @return true on success, false otherwise.
  bool ProtectGuardPages();
  // Transitions from kNoPagesProtected or kGuardPagesProtected to
  // kAllPagesProtected.
  // @return true on success, false otherwise.
  bool ProtectAllPages();
  // @}

  // @name Configuration of the allocation.
  // @{
  // The size of the allocation, in bytes. The actual allocation will be
  // rounded up to an even number of pages.
  size_t size_;
  // The alignment of the allocation.
  size_t alignment_;
  // Indicates if the allocation contains a leading guard page.
  bool left_guard_page_;
  // Indicates if the allocation contains a trailing guard page.
  bool right_guard_page_;
  // The size of the left red-zone.
  size_t left_redzone_size_;
  // The size of the right red-zone.
  size_t right_redzone_size_;
  // The justification of the alignment. A left justification means that
  // the returned address of the allocation will be flush with the left
  // size of the allocation, and vice-versa. If using guard pages the
  // allocation will be as close as possible to the guard page as the alignment
  // and size of the allocation allow.
  Justification justification_;
  // @}

  // @name State of the allocation.
  // @{
  MemoryState memory_state_;
  ProtectionState protection_state_;
  // @}

  // The actual allocation.
  void* pages_;

 private:
  DISALLOW_COPY_AND_ASSIGN(DirectAllocation);
};

// A small 'heap' for making and keeping track of large allocations that are
// made directly with the OS.
class DirectAllocationHeap {
 public:
  // Constructor.
  DirectAllocationHeap() { }

  // Destructor. Cleans up outstanding allocations.
  ~DirectAllocationHeap();

  // Performs a direct allocation. Will automatically reserve an entire
  // page of left and right redzone.
  // @param alignment The alignment of the body of the allocation.
  // @param size The size of the allocation.
  // @return NULL on failure, or a pointer to the allocation on success.
  DirectAllocation* Allocate(size_t alignment,
                             size_t size);

  // Looks up the allocation containing the given address.
  // @param address The address to be looked up.
  // @return NULL on failure, or a pointer to the allocation on success.
  DirectAllocation* Lookup(void* address);

  // Frees the given allocation.
  // @param allocation The allocation to be freed. Must have been previously
  //     returned by this heap.
  // @return true on success, false otherwise.
  bool Free(DirectAllocation* allocation);

 protected:
  // Allocations, sorted by the underlying object itself.
  typedef std::set<DirectAllocation*> AllocationSet;
  AllocationSet allocation_set_;

  // A map of all active allocations, sorted by address. These are inserted
  // when the allocation is made, and removed when it is freed.
  typedef std::map<void*, DirectAllocation*> AllocationMap;
  AllocationMap allocation_map_;

 private:
  DISALLOW_COPY_AND_ASSIGN(DirectAllocationHeap);
};

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_DIRECT_ALLOCATION_H_
