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

#include "syzygy/agent/asan/page_protection_helpers.h"

namespace agent {
namespace asan {

// TODO(chrisha): Move the page protections bits out of the shadow to an entire
//     class that lives here. Or move all of this to shadow.

::common::RecursiveLock block_protect_lock;

bool GetBlockInfo(const Shadow* shadow,
                  const BlockBody* body,
                  CompactBlockInfo* block_info) {
  DCHECK_NE(static_cast<Shadow*>(nullptr), shadow);
  DCHECK_NE(static_cast<BlockBody*>(nullptr), body);
  DCHECK_NE(static_cast<CompactBlockInfo*>(nullptr), block_info);

  // Try reading directly from memory first.
  const uint8_t* addr_in_redzone = reinterpret_cast<const uint8_t*>(body) - 1;
  if (!shadow->PageIsProtected(addr_in_redzone)) {
    // If this succeeds then we're done. It can fail if the page protections
    // are actually active, or if the header is corrupt. In this case we'll
    // fall through and look at the shadow memory.
    BlockHeader* header = BlockGetHeaderFromBody(body);
    if (header != nullptr && BlockInfoFromMemory(header, block_info))
      return true;
  }

  if (!shadow->BlockInfoFromShadow(body, block_info))
    return false;

  return true;
}

bool GetBlockInfo(const Shadow* shadow,
                  const BlockBody* body,
                  BlockInfo* block_info) {
  DCHECK_NE(static_cast<Shadow*>(nullptr), shadow);
  DCHECK_NE(static_cast<BlockBody*>(nullptr), body);
  DCHECK_NE(static_cast<BlockInfo*>(nullptr), block_info);
  CompactBlockInfo compact = {};
  if (!GetBlockInfo(shadow, body, &compact))
    return false;
  ConvertBlockInfo(compact, block_info);
  return true;
}

void BlockProtectNone(const BlockInfo& block_info, Shadow* shadow) {
  DCHECK_NE(static_cast<Shadow*>(nullptr), shadow);
  if (block_info.block_pages_size == 0)
    return;

  ::common::AutoRecursiveLock lock(block_protect_lock);
  DCHECK_NE(static_cast<uint8_t*>(nullptr), block_info.block_pages);
  DWORD old_protection = 0;
  DWORD ret = ::VirtualProtect(block_info.block_pages,
                               block_info.block_pages_size,
                               PAGE_READWRITE, &old_protection);
  CHECK_NE(0u, ret);
  shadow->MarkPagesUnprotected(block_info.block_pages,
                               block_info.block_pages_size);
}

void BlockProtectRedzones(const BlockInfo& block_info, Shadow* shadow) {
  DCHECK_NE(static_cast<Shadow*>(nullptr), shadow);
  if (block_info.block_pages_size == 0)
    return;

  ::common::AutoRecursiveLock lock(block_protect_lock);
  BlockProtectNone(block_info, shadow);

  // Protect the left redzone pages if any.
  DWORD old_protection = 0;
  DWORD ret = 0;
  if (block_info.left_redzone_pages_size > 0) {
    DCHECK_NE(static_cast<uint8_t*>(nullptr), block_info.left_redzone_pages);
    ret = ::VirtualProtect(block_info.left_redzone_pages,
                           block_info.left_redzone_pages_size,
                           PAGE_NOACCESS, &old_protection);
    DCHECK_NE(0u, ret);
    shadow->MarkPagesProtected(block_info.left_redzone_pages,
                               block_info.left_redzone_pages_size);
  }

  // Protect the right redzone pages if any.
  if (block_info.right_redzone_pages_size > 0) {
    DCHECK_NE(static_cast<uint8_t*>(nullptr), block_info.right_redzone_pages);
    ret = ::VirtualProtect(block_info.right_redzone_pages,
                           block_info.right_redzone_pages_size,
                           PAGE_NOACCESS, &old_protection);
    DCHECK_NE(0u, ret);
    shadow->MarkPagesProtected(block_info.right_redzone_pages,
                               block_info.right_redzone_pages_size);
  }
}

void BlockProtectAll(const BlockInfo& block_info, Shadow* shadow) {
  DCHECK_NE(static_cast<Shadow*>(nullptr), shadow);
  if (block_info.block_pages_size == 0)
    return;

  ::common::AutoRecursiveLock lock(block_protect_lock);
  DCHECK_NE(static_cast<uint8_t*>(nullptr), block_info.block_pages);
  DWORD old_protection = 0;
  DWORD ret = ::VirtualProtect(block_info.block_pages,
                               block_info.block_pages_size,
                               PAGE_NOACCESS, &old_protection);
  DCHECK_NE(0u, ret);
  shadow->MarkPagesProtected(block_info.block_pages,
                             block_info.block_pages_size);
}

void BlockProtectAuto(const BlockInfo& block_info, Shadow* shadow) {
  DCHECK_NE(static_cast<Shadow*>(nullptr), shadow);
  if (block_info.block_pages_size == 0)
    return;

  ::common::AutoRecursiveLock lock(block_protect_lock);

  // Remove the page protection from the header if necessary.
  if (!shadow->IsAccessible(block_info.block_pages)) {
    DWORD old_protection = 0;
    DWORD ret = ::VirtualProtect(block_info.block_pages,
                                 GetPageSize(),
                                 PAGE_READWRITE, &old_protection);
    DCHECK_NE(0u, ret);
  }

  // Now set page protections based on the block state.
  switch (block_info.header->state) {
    // An allocated block has an accessible body but protected redzones.
    case ALLOCATED_BLOCK: {
      BlockProtectRedzones(block_info, shadow);
      break;
    }

    // No part of a quarantined or freed block is accessible.
    case QUARANTINED_BLOCK:
    case QUARANTINED_FLOODED_BLOCK:
    case FREED_BLOCK: {
      BlockProtectAll(block_info, shadow);
      break;
    }

    default: NOTREACHED();
  }
}

}  // namespace asan
}  // namespace agent
