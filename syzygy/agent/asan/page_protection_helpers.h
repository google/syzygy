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
// Collection of functions and objects for modifying page protections in a
// consistent way.

#ifndef SYZYGY_AGENT_ASAN_PAGE_PROTECTION_HELPERS_H_
#define SYZYGY_AGENT_ASAN_PAGE_PROTECTION_HELPERS_H_

#include "syzygy/agent/asan/block.h"
#include "syzygy/agent/asan/shadow.h"
#include "syzygy/common/recursive_lock.h"

namespace agent {
namespace asan {

// A global recursive lock. This gates all access to block protection
// functions. This is exposed for crash processing, which wants to block
// other threads from tinkering with page protections.
extern ::common::RecursiveLock block_protect_lock;

// Given a pointer to the body of a block extracts its layout. If the block
// header is not under any block protections then the layout will be read from
// the header. If the header is corrupt, or the memory is otherwise unreadable,
// this will be inferred from the shadow memory (less efficient, but not subject
// to corruption). This is effectively a wrapper to BlockInfoFromMemory and
// Shadow::GetBlockInfo.
// @param shadow The shadow to query.
// @param body A pointer to the body of a block.
// @param block_info The description of the block to be populated.
// @returns true if a valid block was encountered at the provided location,
//     false otherwise.
bool GetBlockInfo(const Shadow* shadow,
                  const BlockBody* body,
                  CompactBlockInfo* block_info);
bool GetBlockInfo(const Shadow* shadow,
                  const BlockBody* body,
                  BlockInfo* block_info);

// Unprotects all pages fully covered by the given block. All pages
// intersecting but not fully covered by the block will be left in their
// current state.
// @param block_info The block whose protections are to be modified.
// @param shadow The shadow to update.
// @note Under block_protect_lock.
void BlockProtectNone(const BlockInfo& block_info, Shadow* shadow);

// Protects all entire pages that are spanned by the redzones of the
// block. All pages intersecting the body of the block will be explicitly
// unprotected. All pages not intersecting the body but only partially
// covered by the redzone will be left in their current state.
// @param block_info The block whose protections are to be modified.
// @param shadow The shadow to update.
// @note Under block_protect_lock.
void BlockProtectRedzones(const BlockInfo& block_info, Shadow* shadow);

// Protects all pages completely spanned by the block. All pages
// intersecting but not fully covered by the block will be left in their
// current state.
// @param block_info The block whose protections are to be modified.
// @param shadow The shadow to update.
// @note Under block_protect_lock.
void BlockProtectAll(const BlockInfo& block_info, Shadow* shadow);

// Sets the block protections according to the block state. If in the allocated
// state uses BlockProtectRedzones. If in quarantined or freed uses
// BlockProtectAll.
// @param block_info The block whose protections are to be modified.
// @param shadow The shadow to update.
// @note Under block_protect_lock.
void BlockProtectAuto(const BlockInfo& block_info, Shadow* shadow);

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_PAGE_PROTECTION_HELPERS_H_
