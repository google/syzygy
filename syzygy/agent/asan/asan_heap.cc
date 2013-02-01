// Copyright 2012 Google Inc. All Rights Reserved.
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
#include "base/stringprintf.h"
#include "base/sys_string_conversions.h"
#include "base/debug/stack_trace.h"
#include "syzygy/agent/asan/asan_logger.h"
#include "syzygy/agent/asan/asan_shadow.h"

namespace agent {
namespace asan {
namespace {

// Redzone size allocated at the start of every heap block.
const size_t kRedZoneSize = 32U;

// Utility class which implements an auto lock for a HeapProxy.
class HeapLocker {
 public:
  explicit HeapLocker(HeapProxy* const heap) : heap_(heap) {
    DCHECK(heap != NULL);
    if (!heap->Lock()) {
      LOG(ERROR) << "Unable to lock the heap.";
    }
  }

  ~HeapLocker() {
    DCHECK(heap_ != NULL);
    if (!heap_->Unlock()) {
      LOG(ERROR) << "Unable to lock the heap.";
    }
  }

 private:
  HeapProxy* const heap_;

  DISALLOW_COPY_AND_ASSIGN(HeapLocker);
};

}  // namespace

// Arbitrarily keep 16 megabytes of quarantine per heap by default.
size_t HeapProxy::default_quarantine_max_size_ = 16 * 1024 * 1024;

void ASANDbgCmd(const wchar_t* fmt, ...) {
  // The string should start with "ASAN" to be interpreted by the debugger as a
  // command.
  std::wstring command_wstring = L"ASAN ";
  va_list args;
  va_start(args, fmt);

  // Append the actual command to the wstring.
  base::StringAppendV(&command_wstring, fmt, args);

  // Append "; g" to make sure that the debugger continue its execution after
  // executing this command. This is needed because when the .ocommand function
  // is used under Windbg the debugger will break on OutputDebugString.
  command_wstring.append(L"; g");

  OutputDebugString(command_wstring.c_str());
}

void ASANDbgMessage(const wchar_t* fmt, ...) {
  // Prepend the message with the .echo command so it'll be printed into the
  // debugger's console.
  std::wstring message_wstring = L".echo ";
  va_list args;
  va_start(args, fmt);

  // Append the actual message to the wstring.
  base::StringAppendV(&message_wstring, fmt, args);

  // Treat the message as a command to print it.
  ASANDbgCmd(message_wstring.c_str());
}

// Switch to the caller's context and print its stack trace in Windbg.
void ASANDbgPrintContext(const CONTEXT& context) {
  ASANDbgMessage(L"Caller's context (%p) and stack trace:", &context);
  ASANDbgCmd(L".cxr %p; kv", reinterpret_cast<uint32>(&context));
}

HeapProxy::HeapProxy(StackCaptureCache* stack_cache, AsanLogger* logger)
    : heap_(NULL),
      stack_cache_(stack_cache),
      logger_(logger),
      head_(NULL),
      tail_(NULL),
      quarantine_size_(0),
      quarantine_max_size_(0) {
  DCHECK(stack_cache != NULL);
  DCHECK(logger != NULL);
}

HeapProxy::~HeapProxy() {
  if (heap_ != NULL)
    Destroy();

  DCHECK(heap_ == NULL);
}

HANDLE HeapProxy::ToHandle(HeapProxy* proxy) {
  DCHECK(proxy != NULL);
  return proxy;
}

HeapProxy* HeapProxy::FromHandle(HANDLE heap) {
  DCHECK(heap != NULL);
  return reinterpret_cast<HeapProxy*>(heap);
}

bool HeapProxy::Create(DWORD options,
                       size_t initial_size,
                       size_t maximum_size) {
  DCHECK(heap_ == NULL);
  COMPILE_ASSERT(sizeof(HeapProxy::BlockHeader) <= kRedZoneSize,
                 asan_block_header_too_big);

  SetQuarantineMaxSize(default_quarantine_max_size_);

  heap_ = ::HeapCreate(options, initial_size, maximum_size);
  if (heap_ != NULL)
    return true;

  return false;
}

bool HeapProxy::Destroy() {
  DCHECK(heap_ != NULL);

  // Flush the quarantine.
  SetQuarantineMaxSize(0);

  if (::HeapDestroy(heap_)) {
    heap_ = NULL;
    return true;
  }

  return false;
}

void* HeapProxy::Alloc(DWORD flags, size_t bytes) {
  DCHECK(heap_ != NULL);

  size_t alloc_size = GetAllocSize(bytes);
  BlockHeader* block =
      reinterpret_cast<BlockHeader*>(::HeapAlloc(heap_, flags, alloc_size));

  if (block == NULL)
    return NULL;

  // Poison head and tail zones, and un-poison alloc.
  size_t header_size = kRedZoneSize;
  size_t trailer_size = alloc_size - kRedZoneSize - bytes;
  memset(block, 0xCC, header_size);
  Shadow::Poison(block, kRedZoneSize);

  // Capture the current stack. We call the CaptureStackBackTrace function
  // directly (instead of via a wrapper) to preserve the greatest number of
  // frames we can capture.
  ULONG stack_id = 0;
  void* frames[StackCapture::kMaxNumFrames];
  size_t num_frames = ::CaptureStackBackTrace(
      0, StackCapture::kMaxNumFrames, frames, &stack_id);

  // Initialize the block fields.
  block->magic_number = kBlockHeaderSignature;
  block->size = bytes;
  block->state = ALLOCATED;
  block->alloc_stack =
      stack_cache_->SaveStackTrace(stack_id, frames, num_frames);
  block->free_stack = NULL;

  uint8* block_alloc = ToAlloc(block);
  Shadow::Unpoison(block_alloc, bytes);

  memset(block_alloc + bytes, 0xCD, trailer_size);
  Shadow::Poison(block_alloc + bytes, trailer_size);

  return block_alloc;
}

void* HeapProxy::ReAlloc(DWORD flags, void* mem, size_t bytes) {
  DCHECK(heap_ != NULL);

  void *new_mem = Alloc(flags, bytes);
  if (new_mem != NULL && mem != NULL)
    memcpy(new_mem, mem, std::min(bytes, Size(0, mem)));

  if (mem)
    Free(flags, mem);

  return new_mem;
}

bool HeapProxy::Free(DWORD flags, void* mem) {
  DCHECK(heap_ != NULL);
  BlockHeader* block = ToBlock(mem);
  // The standard allows to call free on a null pointer. ToBlock returns null if
  // the given pointer is null so we return true here.
  if (block == NULL)
    return true;

  if (block->state != ALLOCATED) {
    // We're not supposed to see another kind of block here, the FREED state
    // is only applied to block after invalidating their magic number and freed
    // them.
    DCHECK(block->state == QUARANTINED);

    BadAccessKind bad_access_kind =
        GetBadAccessKind(static_cast<const uint8*>(mem), block);
    DCHECK_NE(UNKNOWN_BAD_ACCESS, bad_access_kind);
    CONTEXT context = {};
    ::RtlCaptureContext(&context);
    ReportAsanError("attempting double-free", static_cast<const uint8*>(mem),
                    context, bad_access_kind, block, ASAN_UNKNOWN_ACCESS, 0);

    return false;
  }

  // Capture the current stack. We call the CaptureStackBackTrace function
  // directly (instead of via a wrapper) to preserve the greatest number of
  // frames we can capture.
  ULONG stack_id = 0;
  void* frames[StackCapture::kMaxNumFrames];
  size_t num_frames = ::CaptureStackBackTrace(
      0, StackCapture::kMaxNumFrames, frames, &stack_id);

  block->free_stack =
      stack_cache_->SaveStackTrace(stack_id, frames, num_frames);
  DCHECK(ToAlloc(block) == mem);

  // If the size of the allocation is zero then we shouldn't check the shadow
  // memory as it'll only contain the red-zone for the head and tail of this
  // block.
  if (block->size != 0 && !Shadow::IsAccessible(ToAlloc(block)))
    return false;
  QuarantineBlock(block);
  return true;
}

size_t HeapProxy::Size(DWORD flags, const void* mem) {
  DCHECK(heap_ != NULL);
  BlockHeader* block = ToBlock(mem);
  if (block == NULL)
    return -1;

  return block->size;
}

bool HeapProxy::Validate(DWORD flags, const void* mem) {
  DCHECK(heap_ != NULL);
  return ::HeapValidate(heap_, flags, ToBlock(mem)) == TRUE;
}

size_t HeapProxy::Compact(DWORD flags) {
  DCHECK(heap_ != NULL);
  return ::HeapCompact(heap_, flags);
}

bool HeapProxy::Lock() {
  DCHECK(heap_ != NULL);
  return ::HeapLock(heap_) == TRUE;
}

bool HeapProxy::Unlock() {
  DCHECK(heap_ != NULL);
  return ::HeapUnlock(heap_) == TRUE;
}

bool HeapProxy::Walk(PROCESS_HEAP_ENTRY* entry) {
  DCHECK(heap_ != NULL);
  return ::HeapWalk(heap_, entry) == TRUE;
}

bool HeapProxy::SetInformation(HEAP_INFORMATION_CLASS info_class,
                               void* info,
                               size_t info_length) {
  DCHECK(heap_ != NULL);
  return ::HeapSetInformation(heap_, info_class, info, info_length) == TRUE;
}

bool HeapProxy::QueryInformation(HEAP_INFORMATION_CLASS info_class,
                                 void* info,
                                 size_t info_length,
                                 unsigned long* return_length) {
  DCHECK(heap_ != NULL);
  return ::HeapQueryInformation(heap_,
                                info_class,
                                info,
                                info_length,
                                return_length) == TRUE;
}

void HeapProxy::SetQuarantineMaxSize(size_t quarantine_max_size) {
  base::AutoLock lock(lock_);
  quarantine_max_size_ = quarantine_max_size;

  while (quarantine_size_ > quarantine_max_size_)
    PopQuarantineUnlocked();
}

void HeapProxy::PopQuarantineUnlocked() {
  DCHECK(head_ != NULL && tail_ != NULL);
  // The caller should have locked the quarantine.
  lock_.AssertAcquired();

  FreeBlockHeader* free_block = head_;
  head_ = free_block->next;
  if (head_ == NULL)
    tail_ = NULL;

  size_t alloc_size = GetAllocSize(free_block->size);
  Shadow::Unpoison(free_block, alloc_size);
  free_block->state = FREED;
  free_block->magic_number = ~kBlockHeaderSignature;
  free_block->alloc_stack = NULL;
  free_block->free_stack = NULL;

  DCHECK_NE(kBlockHeaderSignature, free_block->magic_number);
  ::HeapFree(heap_, 0, free_block);

  DCHECK_GE(quarantine_size_, alloc_size);
  quarantine_size_ -= alloc_size;
}

void HeapProxy::QuarantineBlock(BlockHeader* block) {
  DCHECK(block != NULL);
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
  // Mark the block as quarantined.
  free_block->state = QUARANTINED;

  // Flush quarantine overage.
  while (quarantine_size_ > quarantine_max_size_)
    PopQuarantineUnlocked();
}

size_t HeapProxy::GetAllocSize(size_t bytes) {
  bytes += kRedZoneSize;
  return (bytes + kRedZoneSize + kRedZoneSize - 1) & ~(kRedZoneSize - 1);
}

HeapProxy::BlockHeader* HeapProxy::ToBlock(const void* alloc) {
  if (alloc == NULL)
    return NULL;

  const uint8* mem = static_cast<const uint8*>(alloc);
  const BlockHeader* header =
      reinterpret_cast<const BlockHeader*>(mem -kRedZoneSize);
  if (header->magic_number != kBlockHeaderSignature) {
    CONTEXT context = {};
    ::RtlCaptureContext(&context);
    if (!OnBadAccess(mem, context, ASAN_UNKNOWN_ACCESS, 0)) {
      ReportUnknownError(mem, context, ASAN_UNKNOWN_ACCESS, 0);
      Shadow::PrintShadowMemoryForAddress(alloc);
    }
    return NULL;
  }

  return const_cast<BlockHeader*>(header);
}

uint8* HeapProxy::ToAlloc(BlockHeader* block) {
  DCHECK(block != NULL);
  DCHECK_EQ(kBlockHeaderSignature, block->magic_number);
  DCHECK(block->state == ALLOCATED || block->state == QUARANTINED);

  uint8* mem = reinterpret_cast<uint8*>(block);

  return mem + kRedZoneSize;
}

void HeapProxy::ReportAddressInformation(const void* addr,
                                         BlockHeader* header,
                                         BadAccessKind bad_access_kind) {
  DCHECK(addr != NULL);
  DCHECK(header != NULL);
  uint8* block_alloc = ToAlloc(header);
  int offset = 0;
  char* offset_relativity = "";
  switch (bad_access_kind) {
    case HEAP_BUFFER_OVERFLOW:
      offset = static_cast<const uint8*>(addr) - block_alloc - header->size;
      offset_relativity = "to the right";
      break;
    case HEAP_BUFFER_UNDERFLOW:
      offset = block_alloc - static_cast<const uint8*>(addr);
      offset_relativity = "to the left";
      break;
    case USE_AFTER_FREE:
      offset = static_cast<const uint8*>(addr) - block_alloc;
      offset_relativity = "inside";
      break;
    default:
      NOTREACHED() << "Error trying to dump address information.";
  }

  logger_->Write(base::StringPrintf(
      "0x%08X is located %d bytes %s of %d-bytes region [0x%08X,0x%08X)\n",
      addr,
      offset,
      offset_relativity,
      header->size,
      block_alloc,
      block_alloc + header->size));
  if (header->free_stack != NULL) {
    logger_->WriteWithStackTrace("freed here:\n",
                                 header->free_stack->frames(),
                                 header->free_stack->num_frames());
  }
  if (header->alloc_stack != NULL) {
    logger_->WriteWithStackTrace("previously allocated here:\n",
                                 header->alloc_stack->frames(),
                                 header->alloc_stack->num_frames());
  }

  std::string shadow_text;
  Shadow::AppendShadowMemoryText(addr, &shadow_text);
  logger_->Write(shadow_text);
}

HeapProxy::BadAccessKind HeapProxy::GetBadAccessKind(const void* addr,
                                                     BlockHeader* header) {
  DCHECK(addr != NULL);
  DCHECK(header != NULL);

  BadAccessKind bad_access_kind = UNKNOWN_BAD_ACCESS;

  if (header->state == QUARANTINED) {
    // At this point we can't know if this address belongs to this
    // quarantined block... If the block containing this address has been
    // moved from the quarantine list its memory space could have been re-used
    // and freed again (so having this block in the quarantine list don't
    // guarantee that this is the original block).
    // TODO(sebmarchand): Find a way to fix this bug.
    bad_access_kind = USE_AFTER_FREE;
  } else {
    if (addr < (ToAlloc(header)))
      bad_access_kind = HEAP_BUFFER_UNDERFLOW;
    else if (addr >= (ToAlloc(header) + header->size))
      bad_access_kind = HEAP_BUFFER_OVERFLOW;
  }
  return bad_access_kind;
}

HeapProxy::BlockHeader* HeapProxy::FindAddressBlock(const void* addr) {
  DCHECK(addr != NULL);
  PROCESS_HEAP_ENTRY heap_entry = {};
  memset(&heap_entry, 0, sizeof(heap_entry));
  BlockHeader* header = NULL;

  // Walk through the heap to find the block containing @p addr.
  HeapLocker heap_locker(this);
  while (Walk(&heap_entry)) {
    uint8* entry_upper_bound =
        static_cast<uint8*>(heap_entry.lpData) + heap_entry.cbData;

    if (heap_entry.lpData <= addr && entry_upper_bound > addr) {
      header = reinterpret_cast<BlockHeader*>(heap_entry.lpData);
      // Ensures that the block have been allocated by this proxy.
      if (header->magic_number == kBlockHeaderSignature) {
        DCHECK(header->state != FREED);
        break;
      } else {
        header = NULL;
      }
    }
  }

  return header;
}

bool HeapProxy::OnBadAccess(const void* addr,
                            const CONTEXT& context,
                            AccessMode access_mode,
                            size_t access_size) {
  DCHECK(addr != NULL);
  base::AutoLock lock(lock_);
  BadAccessKind bad_access_kind = UNKNOWN_BAD_ACCESS;
  BlockHeader* header = FindAddressBlock(addr);

  if (header == NULL)
    return false;

  bad_access_kind = GetBadAccessKind(addr, header);
  // Get the bad access description if we've been able to determine its kind.
  if (bad_access_kind != UNKNOWN_BAD_ACCESS) {
    const char* bug_descr = AccessTypeToStr(bad_access_kind);
    ReportAsanError(bug_descr,
                    addr,
                    context,
                    bad_access_kind,
                    header,
                    access_mode,
                    access_size);
    return true;
  }

  return false;
}

void HeapProxy::ReportUnknownError(const void* addr,
                                   const CONTEXT& context,
                                   AccessMode access_mode,
                                   size_t access_size) {
  DCHECK(addr != NULL);
  ReportAsanErrorBase("unknown-crash",
                      addr,
                      context,
                      UNKNOWN_BAD_ACCESS,
                      access_mode,
                      access_size);

  ASANDbgPrintContext(context);
}

void HeapProxy::ReportAsanError(const char* bug_descr,
                                const void* addr,
                                const CONTEXT& context,
                                BadAccessKind bad_access_kind,
                                BlockHeader* header,
                                AccessMode access_mode,
                                size_t access_size) {
  DCHECK(bug_descr != NULL);
  DCHECK(addr != NULL);
  DCHECK(header != NULL);

  ReportAsanErrorBase(bug_descr,
                      addr,
                      context,
                      bad_access_kind,
                      access_mode,
                      access_size);

  // Print the Windbg information to display the allocation stack if present.
  if (header->alloc_stack != NULL) {
    ASANDbgMessage(L"Allocation stack trace:");
    ASANDbgCmd(L"dps %p l%d",
               header->alloc_stack->frames(),
               header->alloc_stack->num_frames());
  }

  // Print the Windbg information to display the free stack if present.
  if (header->free_stack != NULL) {
    ASANDbgMessage(L"Free stack trace:");
    ASANDbgCmd(L"dps %p l%d",
               header->free_stack->frames(),
               header->free_stack->num_frames());
  }

  ReportAddressInformation(addr, header, bad_access_kind);

  ASANDbgPrintContext(context);
}

void HeapProxy::ReportAsanErrorBase(const char* bug_descr,
                                    const void* addr,
                                    const CONTEXT& context,
                                    BadAccessKind bad_access_kind,
                                    AccessMode access_mode,
                                    size_t access_size) {
  DCHECK(bug_descr != NULL);
  DCHECK(addr != NULL);

  // Print the base of the Windbg help message.
  ASANDbgMessage(L"An Asan error has been found (%ls), here are the details:",
                 base::SysUTF8ToWide(bug_descr).c_str());

  // TODO(sebmarchand): Print PC, BP and SP.
  std::string output(base::StringPrintf(
      "SyzyASAN error: %s on address 0x%08X\n", bug_descr, addr));
  if (access_mode != ASAN_UNKNOWN_ACCESS) {
    const char* access_mode_str = NULL;
    if (access_mode == ASAN_READ_ACCESS)
      access_mode_str = "READ";
    else
      access_mode_str = "WRITE";
    base::StringAppendF(&output,
                        "%s of size %d at 0x%08X\n",
                        access_mode_str,
                        access_size);
  }

  // Log the failure and stack.
  logger_->WriteWithContext(output, context);
}

const char* HeapProxy::AccessTypeToStr(BadAccessKind bad_access_kind) {
  switch (bad_access_kind) {
    case USE_AFTER_FREE:
      return "heap-use-after-free";
    case HEAP_BUFFER_UNDERFLOW:
      return "heap-buffer-underflow";
    case HEAP_BUFFER_OVERFLOW:
      return "heap-buffer-overflow";
    default:
      NOTREACHED() << "Unexpected bad access kind.";
      return NULL;
  }
}

LIST_ENTRY* HeapProxy::ToListEntry(HeapProxy* proxy) {
  DCHECK(proxy != NULL);
  return &proxy->list_entry_;
}

HeapProxy* HeapProxy::FromListEntry(LIST_ENTRY* list_entry) {
  DCHECK(list_entry != NULL);
  return CONTAINING_RECORD(list_entry, HeapProxy, list_entry_);
}

}  // namespace asan
}  // namespace agent
