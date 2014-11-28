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

bool GetBlockInfo(const void* raw_body, CompactBlockInfo* block_info) {
  DCHECK_NE(static_cast<void*>(NULL), raw_body);
  DCHECK_NE(static_cast<CompactBlockInfo*>(NULL), block_info);

  // Try reading directly from memory first.
  const uint8* addr_in_redzone = reinterpret_cast<const uint8*>(raw_body) - 1;
  if (!Shadow::PageIsProtected(addr_in_redzone)) {
    // If this succeeds then we're done. It can fail if the page protections
    // are actually active, or if the header is corrupt. In this case we'll
    // fall through the looking at the shadow memory.
    void* block = BlockGetHeaderFromBody(raw_body);
    if (block != NULL && BlockInfoFromMemory(block, block_info))
      return true;
  }

  if (!Shadow::BlockInfoFromShadow(raw_body, block_info))
    return false;

  return true;
}

bool GetBlockInfo(const void* raw_block, BlockInfo* block_info) {
  DCHECK_NE(static_cast<void*>(NULL), raw_block);
  DCHECK_NE(static_cast<BlockInfo*>(NULL), block_info);
  CompactBlockInfo compact = {};
  if (!GetBlockInfo(raw_block, &compact))
    return false;
  ConvertBlockInfo(compact, block_info);
  return true;
}

void BlockProtectNone(const BlockInfo& block_info) {
  if (block_info.block_pages_size == 0)
    return;
  DCHECK_NE(static_cast<uint8*>(NULL), block_info.block_pages);
  DWORD old_protection = 0;
  DWORD ret = ::VirtualProtect(block_info.block_pages,
                               block_info.block_pages_size,
                               PAGE_READWRITE, &old_protection);
  CHECK_NE(0u, ret);
  Shadow::MarkPagesUnprotected(block_info.block_pages,
                               block_info.block_pages_size);
}

void BlockProtectRedzones(const BlockInfo& block_info) {
  BlockProtectNone(block_info);

  // Protect the left redzone pages if any.
  DWORD old_protection = 0;
  DWORD ret = 0;
  if (block_info.left_redzone_pages_size > 0) {
    DCHECK_NE(static_cast<uint8*>(NULL), block_info.left_redzone_pages);
    ret = ::VirtualProtect(block_info.left_redzone_pages,
                           block_info.left_redzone_pages_size,
                           PAGE_NOACCESS, &old_protection);
    DCHECK_NE(0u, ret);
    Shadow::MarkPagesProtected(block_info.left_redzone_pages,
                               block_info.left_redzone_pages_size);
  }

  // Protect the right redzone pages if any.
  if (block_info.right_redzone_pages_size > 0) {
    DCHECK_NE(static_cast<uint8*>(NULL), block_info.right_redzone_pages);
    ret = ::VirtualProtect(block_info.right_redzone_pages,
                           block_info.right_redzone_pages_size,
                           PAGE_NOACCESS, &old_protection);
    DCHECK_NE(0u, ret);
    Shadow::MarkPagesProtected(block_info.right_redzone_pages,
                               block_info.right_redzone_pages_size);
  }
}

void BlockProtectAll(const BlockInfo& block_info) {
  if (block_info.block_pages_size == 0)
    return;
  DCHECK_NE(static_cast<uint8*>(NULL), block_info.block_pages);
  DWORD old_protection = 0;
  DWORD ret = ::VirtualProtect(block_info.block_pages,
                               block_info.block_pages_size,
                               PAGE_NOACCESS, &old_protection);
  DCHECK_NE(0u, ret);
  Shadow::MarkPagesProtected(block_info.block_pages,
                             block_info.block_pages_size);
}

void BlockProtectAuto(const BlockInfo& block_info) {
  switch (block_info.header->state) {
    // An allocated block has an accessible body but protected redzones.
    case ALLOCATED_BLOCK: {
      BlockProtectRedzones(block_info);
      break;
    }

    // No part of a quarantined or freed block is accessible.
    case QUARANTINED_BLOCK:
    case FREED_BLOCK: {
      BlockProtectAll(block_info);
      break;
    }

    default: NOTREACHED();
  }
}

}  // namespace asan
}  // namespace agent
