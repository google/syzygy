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

#include "syzygy/agent/asan/direct_allocation.h"

#include <windows.h>

#include <algorithm>

#include "base/logging.h"
#include "base/memory/scoped_ptr.h"
#include "syzygy/common/align.h"

namespace agent {
namespace asan {

DirectAllocation::DirectAllocation()
    : size_(0), alignment_(kDefaultAlignment), left_guard_page_(false),
      right_guard_page_(false), left_redzone_size_(0), right_redzone_size_(0),
      justification_(kAutoJustification), memory_state_(kNoPages),
      protection_state_(kNoPagesProtected), pages_(NULL) {
}

DirectAllocation::~DirectAllocation() {
  // Make sure the allocation gets cleaned up with this object.
  ToNoPages();
}

void DirectAllocation::set_size(size_t size) {
  DCHECK_EQ(kNoPages, memory_state_);
  size_ = size;
}

void DirectAllocation::set_alignment(size_t alignment) {
  DCHECK_EQ(kNoPages, memory_state_);
  DCHECK_LT(0u, alignment);
  DCHECK_GE(GetPageSize(), alignment);
  DCHECK(common::IsPowerOfTwo(alignment));
  alignment_ = alignment;
}

void DirectAllocation::set_left_guard_page(bool left_guard_page) {
  DCHECK_EQ(kNoPages, memory_state_);
  left_guard_page_ = left_guard_page;
}

void DirectAllocation::set_right_guard_page(bool right_guard_page) {
  DCHECK_EQ(kNoPages, memory_state_);
  right_guard_page_ = right_guard_page;
}

void DirectAllocation::set_left_redzone_size(size_t left_redzone_size) {
  DCHECK_EQ(kNoPages, memory_state_);
  left_redzone_size_ = left_redzone_size;
}

void DirectAllocation::set_right_redzone_size(size_t right_redzone_size) {
  DCHECK_EQ(kNoPages, memory_state_);
  right_redzone_size_ = right_redzone_size;
}

void DirectAllocation::set_justification(Justification justification) {
  DCHECK_EQ(kNoPages, memory_state_);
  justification_ = justification;
}

void DirectAllocation::FinalizeParameters() {
  DCHECK_LT(0u, size_);
  DCHECK_EQ(kNoPages, memory_state_);

#ifndef OFFICIAL_BUILD
  size_t min_left_redzone_size = left_redzone_size_;
  size_t min_right_redzone_size = right_redzone_size_;
#endif

  // If we're using guard pages then make sure the redzones are sufficiently
  // big to house one. Also use these to automatically set the justification,
  // preferring right justification.
  if (right_guard_page_) {
    right_redzone_size_ = std::max(right_redzone_size_, GetPageSize());
    if (justification_ == kAutoJustification)
      justification_ = kRightJustification;
  }
  if (left_guard_page_) {
    left_redzone_size_ = std::max(left_redzone_size_, GetPageSize());
    if (justification_ == kAutoJustification)
      justification_ = kLeftJustification;
  }

  // If the justification still hasn't been inferred then set it based on the
  // presence of left or right redzones.
  if (justification_ == kAutoJustification) {
    if (right_redzone_size_ > 0)
      justification_ = kRightJustification;
    else if (left_redzone_size_ > 0)
      justification_ = kLeftJustification;
  }

  // Finally, if the auto-justification decision wasn't guided by the presence
  // of guard pages or redzones then prefer right justification by default.
  if (justification_ == kAutoJustification)
    justification_ = kRightJustification;

  // Optimizing layout for right justification is the same as optimizing for
  // left justification, if the allocation is a multiple of |alignment_| in
  // length, and we swap the left and right redzone sizes.
  size_t orig_size = size_;
  if (justification_ == kRightJustification) {
    std::swap(left_redzone_size_, right_redzone_size_);
    size_ = common::AlignUp(size_, alignment_);
  }

  // Determine the minimum size of the left redzone such that the allocation
  // will be appropriately aligned.
  left_redzone_size_ = common::AlignUp(left_redzone_size_, alignment_);

  // Determine the next spot that would place the allocation as close as
  // possible to a page boundary.
  size_t next_page = common::AlignUp(left_redzone_size_,
                                      std::min(GetPageSize(), alignment_));

  // Figure out the actual size of the allocation assuming minimal left
  // redzone, and how much extra redzone we have to play with.
  size_t alloc_size = left_redzone_size_ + size_ + right_redzone_size_;
  size_t page_size = common::AlignUp(alloc_size, GetPageSize());
  size_t extra = page_size - alloc_size;

  // If the allocation can be shifted right until it's left boundary is *on*
  // the next page boundary, then do so. This makes the guard page maximally
  // useful.
  if (next_page <= left_redzone_size_ + extra) {
    left_redzone_size_ = next_page;
  } else if (left_redzone_size_ < GetPageSize()) {
    // If we're going to have a guard page then leave the left redzone as it
    // is. This will keep the allocation as close as possible to it. Otherwise
    // split the extra space between the left and right redzones to make them
    // both more useful.
    size_t left_extra = ( (extra + alignment_ - 1) / alignment_ / 2 ) *
        alignment_;
    left_redzone_size_ += left_extra;
  }

  // The right redzone picks up the rest of the slack.
  right_redzone_size_ = page_size - left_redzone_size_ - size_;

  // If we are actually doing a right justification layout, then swap things
  // back and remove the padding we added to |size_|, adding it to the right
  // redzone instead.
  if (justification_ == kRightJustification) {
    std::swap(left_redzone_size_, right_redzone_size_);
    size_t delta = size_ - orig_size;
    size_ = orig_size;
    right_redzone_size_ += delta;
  }

#ifndef OFFICIAL_BUILD
  // Ensure the final allocation layout makes sense.
  DCHECK_LE(min_left_redzone_size, left_redzone_size_);
  DCHECK_LE(min_right_redzone_size, right_redzone_size_);
  DCHECK_EQ(0u, left_redzone_size_ % alignment_);
  DCHECK_EQ(0u, (left_redzone_size_ + size_ + right_redzone_size_) %
                    GetPageSize());
#endif

  // Finally, automatically enable guard pages if possible. They cost nothing
  // and we may as well use them if the redzones are already sufficiently
  // large.
  if (left_redzone_size_ >= GetPageSize())
    left_guard_page_ = true;
  if (right_redzone_size_ >= GetPageSize())
    right_guard_page_ = true;
}

bool DirectAllocation::ToNoPages() {
  if (memory_state_ == kNoPages)
    return true;

  // When releasing the allocation memory it is expected that we pass in a size
  // of zero, implying that the entire allocation is to be freed.
  DCHECK_NE(reinterpret_cast<void*>(NULL), pages_);
  bool success = ::VirtualFree(pages_, 0, MEM_RELEASE) != 0;
  if (!success)
    return false;
  pages_ = NULL;
  memory_state_ = kNoPages;
  protection_state_ = kNoPagesProtected;
  return true;
}

bool DirectAllocation::ToReservedPages() {
  if (memory_state_ == kReservedPages)
    return true;

  // No pages are reserved or allocated. Reserve pages for use, and protect
  // them to prevent reading and writing.
  if (memory_state_ == kNoPages) {
    FinalizeParameters();
    pages_ = ::VirtualAlloc(NULL, GetTotalSize(), MEM_RESERVE, PAGE_NOACCESS);
    if (pages_ == NULL)
      return false;
    memory_state_ = kReservedPages;
    protection_state_ = kAllPagesProtected;
    return true;
  }

  // Pages are allocated. Decommit them, returning the physical memory
  // to the OS. This loses the contents of the pages, but keeps the address
  // space reserved.
  DCHECK_EQ(kAllocatedPages, memory_state_);
  DCHECK_NE(reinterpret_cast<void*>(NULL), pages_);
  bool success = ::VirtualFree(pages_, GetTotalSize(), MEM_DECOMMIT) != 0;
  if (!success)
    return false;
  memory_state_ = kReservedPages;
  protection_state_ = kAllPagesProtected;
  return true;
}

bool DirectAllocation::ToAllocatedPages() {
  if (memory_state_ == kAllocatedPages)
    return true;

  // Finalize the parameters if we have to.
  if (memory_state_ == kNoPages)
    FinalizeParameters();

  // Commit the pages. This does a reserve and commit if none were
  // previously reserved, or it commits the existing reservation.
  pages_ = ::VirtualAlloc(pages_, GetTotalSize(), MEM_COMMIT, PAGE_READWRITE);
  if (pages_ == NULL)
    return false;
  memory_state_ = kAllocatedPages;
  protection_state_ = kNoPagesProtected;
  return true;
}

bool DirectAllocation::ProtectNoPages() {
  if (memory_state_ != kAllocatedPages)
    return false;

  DWORD old_protection = 0;
  bool success = ::VirtualProtect(pages_, GetTotalSize(), PAGE_READWRITE,
                                  &old_protection) != 0;
  if (!success)
    return false;

  protection_state_ = kNoPagesProtected;
  return true;
}

bool DirectAllocation::ProtectGuardPages() {
  if (memory_state_ != kAllocatedPages)
    return false;

  // If there are no guard pages to protect then return false.
  size_t left_guard_size = GetLeftGuardPageCount() * GetPageSize();
  size_t right_guard_size = GetRightGuardPageCount() * GetPageSize();
  if (left_guard_size == 0 && right_guard_size == 0)
    return true;

  // Protect the left guard pages if necessary.
  size_t alloc_size = GetTotalSize() - left_guard_size - right_guard_size;
  DWORD old_protection = 0;
  uint8* page = reinterpret_cast<uint8*>(pages_);
  bool success1 = true;
  if (left_guard_size > 0) {
    success1 = ::VirtualProtect(page, left_guard_size, PAGE_NOACCESS,
                                &old_protection) != 0;
  }

  // Unprotect the body of the allocation.
  page += left_guard_size;
  bool success2 = ::VirtualProtect(page, alloc_size, PAGE_READWRITE,
                                   &old_protection) != 0;

  // Protect the right guard pages if necessary.
  page += alloc_size;
  bool success3 = true;
  if (right_guard_size > 0) {
    success3 = ::VirtualProtect(page, right_guard_size, PAGE_NOACCESS,
                                &old_protection) != 0;
  }

  // All three page protection changes must have succeeded.
  if (!success1 || !success2 || !success3)
    return false;

  protection_state_ = kGuardPagesProtected;
  return true;
}

bool DirectAllocation::ProtectAllPages() {
  if (memory_state_ != kAllocatedPages)
    return false;

  DWORD old_protection = 0;
  bool success = ::VirtualProtect(pages_, GetTotalSize(), PAGE_NOACCESS,
                                  &old_protection) != 0;
  if (!success)
    return false;

  protection_state_ = kAllPagesProtected;
  return true;
}

size_t DirectAllocation::GetPageCount() const {
  return GetTotalSize() / GetPageSize();
}

size_t DirectAllocation::GetTotalSize() const {
  return left_redzone_size_ + size_ + right_redzone_size_;
}

void* DirectAllocation::GetLeftRedZone() const {
  if (left_redzone_size_ == 0 || pages_ == NULL)
    return NULL;
  return pages_;
}

void* DirectAllocation::GetRightRedZone() const {
  if (right_redzone_size_ == 0 || pages_ == NULL)
    return NULL;
  return reinterpret_cast<uint8*>(pages_) + left_redzone_size_ + size_;
}

void* DirectAllocation::GetAllocation() const {
  if (pages_ == NULL)
    return NULL;
  return reinterpret_cast<uint8*>(pages_) + left_redzone_size_;
}

void* DirectAllocation::GetLeftGuardPage() const {
  if (!left_guard_page_ || pages_ == NULL)
    return NULL;
  return pages_;
}

void* DirectAllocation::GetRightGuardPage() const {
  size_t count = GetRightGuardPageCount();
  if (count == 0)
    return NULL;
  uint8* end = reinterpret_cast<uint8*>(pages_) + GetTotalSize();
  uint8* right_guard_page = end - count * GetPageSize();
  return right_guard_page;
}

size_t DirectAllocation::GetLeftGuardPageCount() const {
  if (!left_guard_page_ || pages_ == NULL)
    return 0;
  size_t count = left_redzone_size_ / GetPageSize();
  return count;
}

size_t DirectAllocation::GetRightGuardPageCount() const {
  if (!right_guard_page_ || pages_ == NULL)
    return 0;
  size_t count = right_redzone_size_ / GetPageSize();
  return count;
}

bool DirectAllocation::HasGuardPages() const {
  return left_guard_page_ || right_guard_page_;
}

size_t DirectAllocation::GetPageSize() {
  // This is inherently racy, but it's fine if the value gets looked up
  // repeatedly.
  static size_t page_size = 0;
  if (page_size != 0)
    return page_size;
  SYSTEM_INFO system_info = {};
  ::GetSystemInfo(&system_info);
  page_size = system_info.dwPageSize;
  return page_size;
}

bool DirectAllocation::Allocate() {
  if (!ToAllocatedPages())
    return false;
  if (!ProtectGuardPages())
    return false;
  return true;
}

bool DirectAllocation::QuarantineKeepContents() {
  if (!ToAllocatedPages())
    return false;
  if (!ProtectAllPages())
    return false;
  return true;
}

bool DirectAllocation::QuarantineDiscardContents() {
  if (!ToReservedPages())
    return false;
  // No need to manually protect the pages as this happens implicitly.
  DCHECK_EQ(kAllPagesProtected, protection_state_);
  return true;
}

bool DirectAllocation::Free() {
  if (!ToNoPages())
    return false;
  return true;
}

DirectAllocationHeap::~DirectAllocationHeap() {
  AllocationSet::iterator it = allocation_set_.begin();
  for (; it != allocation_set_.end(); ++it)
    delete (*it);
}

DirectAllocation* DirectAllocationHeap::Allocate(size_t alignment,
                                                 size_t size) {
  DCHECK_LT(0u, alignment);
  DCHECK_LT(0u, size);

  scoped_ptr<DirectAllocation> allocation(new DirectAllocation());
  allocation->set_left_guard_page(true);
  allocation->set_right_guard_page(true);
  allocation->set_alignment(alignment);
  allocation->set_size(size);
  if (!allocation->Allocate())
    return NULL;

  DirectAllocation* a = allocation.release();
  allocation_map_.insert(std::make_pair(a->GetLeftRedZone(), a));
  allocation_set_.insert(a);

  return a;
}

DirectAllocation* DirectAllocationHeap::Lookup(void* address) {
  if (allocation_map_.empty())
    return NULL;

  // Find the first element past the element of interest.
  AllocationMap::iterator it = allocation_map_.upper_bound(address);
  if (it == allocation_map_.begin())
    return NULL;
  --it;  // This is valid because we're not the first element in the map.
  DCHECK(it != allocation_map_.end());

  // If the end of the allocation falls before the address of interest then
  // this heap does not own the address.
  uint8* end = reinterpret_cast<uint8*>(it->second->GetRightRedZone());
  end += it->second->right_redzone_size();
  if (end <= address)
    return NULL;

  return it->second;
}

bool DirectAllocationHeap::Free(DirectAllocation* allocation) {
  DCHECK_NE(reinterpret_cast<DirectAllocation*>(NULL), allocation);

  // Find the allocation in the set and the map, expecting an exact
  // match.
  AllocationSet::iterator it_set = allocation_set_.find(allocation);
  DCHECK(it_set != allocation_set_.end());

  AllocationMap::iterator it_map = allocation_map_.find(
      allocation->GetLeftRedZone());
  DCHECK(it_map != allocation_map_.end());
  DCHECK_EQ(allocation, it_map->second);

  allocation_set_.erase(it_set);
  allocation_map_.erase(it_map);
  delete allocation;

  return true;
}

}  // namespace asan
}  // namespace agent
