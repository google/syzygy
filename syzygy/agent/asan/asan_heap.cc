// Copyright 2012 Google Inc.
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
#include "syzygy/agent/asan/asan_heap.h"

#include "base/logging.h"
#include "syzygy/agent/asan/asan_shadow.h"

namespace agent {
namespace asan {

namespace {

// Redzone size allocated at the start of every heap block.
const size_t kRedZoneSize = 32;

}  // namespace

HeapProxy::HeapProxy()
    : heap_(NULL),
      head_(NULL),
      tail_(NULL),
      quarantine_size_(0) {
}

HeapProxy::~HeapProxy() {
  if (heap_ != NULL)
    Destroy();

  DCHECK(heap_ == NULL);
}

HANDLE HeapProxy::ToHandle(HeapProxy* proxy) {
  return proxy;
}

HeapProxy* HeapProxy::FromHandle(HANDLE heap) {
  return reinterpret_cast<HeapProxy*>(heap);
}

bool HeapProxy::Create(DWORD options,
                       size_t initial_size,
                       size_t maximum_size) {
  DCHECK(heap_ == NULL);

  heap_ = ::HeapCreate(options, initial_size, maximum_size);
  if (heap_ != NULL)
    return true;

  return false;
}

bool HeapProxy::Destroy(){
  DCHECK(heap_ != NULL);
  if (::HeapDestroy(heap_)) {
    heap_ = NULL;
    return true;
  }

  return false;
}

void* HeapProxy::Alloc(DWORD flags, size_t bytes){
  DCHECK(heap_ != NULL);

  size_t alloc_size = GetAllocSize(bytes);
  BlockHeader* block =
      reinterpret_cast<BlockHeader*>(::HeapAlloc(heap_, flags, alloc_size));

  if (block == NULL)
    return NULL;

  // Poison head and tail zones, and unpoison alloc.
  size_t header_size = kRedZoneSize;
  size_t trailer_size = alloc_size - kRedZoneSize - bytes;
  memset(block, '0xCC', header_size);
  Shadow::Poison(block, kRedZoneSize);

  Shadow::Unpoison(ToAlloc(block), bytes);

  memset(ToAlloc(block) + bytes, '0xCD', trailer_size);
  Shadow::Poison(ToAlloc(block) + bytes, trailer_size);

  block->size = bytes;

  return ToAlloc(block);
}

void* HeapProxy::ReAlloc(DWORD flags, void* mem, size_t bytes){
  DCHECK(heap_ != NULL);

  void *new_mem = Alloc(flags, bytes);
  if (new_mem != NULL && mem != NULL)
    memcpy(new_mem, mem, std::min(bytes, Size(0, mem)));

  if (mem)
    Free(flags, mem);

  return new_mem;
}

bool HeapProxy::Free(DWORD flags, void* mem){
  DCHECK(heap_ != NULL);
  BlockHeader* block = ToBlock(mem);
  if (block == NULL)
    return true;

  QuarantineBlock(block);

  return true;
}

size_t HeapProxy::Size(DWORD flags, const void* mem){
  DCHECK(heap_ != NULL);
  BlockHeader* block = ToBlock(mem);
  if (block == NULL)
    return -1;

  return block->size;
}

bool HeapProxy::Validate(DWORD flags, const void* mem){
  DCHECK(heap_ != NULL);
  return ::HeapValidate(heap_, flags, ToBlock(mem)) == TRUE;
}

size_t HeapProxy::Compact(DWORD flags){
  DCHECK(heap_ != NULL);
  return ::HeapCompact(heap_, flags);
}

bool HeapProxy::Lock(){
  DCHECK(heap_ != NULL);
  return ::HeapLock(heap_) == TRUE;
}

bool HeapProxy::Unlock(){
  DCHECK(heap_ != NULL);
  return ::HeapUnlock(heap_) == TRUE;
}

bool HeapProxy::Walk(PROCESS_HEAP_ENTRY* entry){
  DCHECK(heap_ != NULL);
  return ::HeapWalk(heap_, entry) == TRUE;
}

bool HeapProxy::SetInformation(HEAP_INFORMATION_CLASS info_class,
                               void* info,
                               size_t info_length){
  DCHECK(heap_ != NULL);
  return ::HeapSetInformation(heap_, info_class, info, info_length) == TRUE;
}

bool HeapProxy::QueryInformation(HEAP_INFORMATION_CLASS info_class,
                                 void* info,
                                 size_t info_length,
                                 unsigned long* return_length){
  DCHECK(heap_ != NULL);
  return ::HeapQueryInformation(heap_,
                                info_class,
                                info,
                                info_length,
                                return_length) == TRUE;
}

void HeapProxy::QuarantineBlock(BlockHeader* block) {
  base::AutoLock lock(lock_);
  FreeBlockHeader* free_block = static_cast<FreeBlockHeader*>(block);

  free_block->next = NULL;
  if (tail_ != NULL) {
    tail_->next = free_block;
  } else {
    DCHECK(head_ == NULL);
    head_ = free_block;
  }
  tail_ = free_block;

  // Poison the released alloc.
  size_t alloc_size = GetAllocSize(free_block->size);
  // Trash the data in the block and poison it.
  memset(ToAlloc(free_block), 0xCC, free_block->size);
  Shadow::Poison(free_block, alloc_size);
  quarantine_size_ += alloc_size;

  // Arbitrarily keep ten megabytes of quarantine per heap.
  const size_t kMaxQuarantineSizeBytes = 10 * 1024 * 1024;

  // Flush quarantine overage.
  while (quarantine_size_ > kMaxQuarantineSizeBytes) {
    DCHECK(head_ != NULL && tail_ != NULL);

    free_block = head_;
    head_ = free_block->next;
    if (head_ == NULL)
      tail_ = NULL;

    alloc_size = GetAllocSize(free_block->size);
    Shadow::Unpoison(free_block, alloc_size);
    ::HeapFree(heap_, 0, free_block);

    DCHECK_GE(quarantine_size_, alloc_size);
    quarantine_size_ -= alloc_size;
  }
}

size_t HeapProxy::GetAllocSize(size_t bytes) {
  bytes += kRedZoneSize;
  return (bytes + kRedZoneSize + kRedZoneSize - 1) & ~(kRedZoneSize - 1);
}

HeapProxy::BlockHeader* HeapProxy::ToBlock(const void* alloc) {
  if (alloc == NULL)
    return NULL;

  uint8* mem = reinterpret_cast<uint8*>(const_cast<void*>(alloc));

  return reinterpret_cast<BlockHeader*>(mem - kRedZoneSize);
}

uint8* HeapProxy::ToAlloc(BlockHeader* block) {
  uint8* mem = reinterpret_cast<uint8*>(block);

  return mem + kRedZoneSize;
}

}  // namespace asan
}  // namespace agent
