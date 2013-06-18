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
#include "base/string_util.h"
#include "base/stringprintf.h"
#include "base/time.h"
#include "base/debug/alias.h"
#include "base/debug/stack_trace.h"
#include "base/strings/sys_string_conversions.h"
#include "syzygy/agent/asan/asan_logger.h"
#include "syzygy/agent/asan/asan_runtime.h"
#include "syzygy/agent/asan/asan_shadow.h"
#include "syzygy/common/align.h"
#include "syzygy/trace/common/clock.h"

namespace agent {
namespace asan {
namespace {

typedef StackCapture::StackId StackId;

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

// Returns the number of CPU cycles per microsecond.
double GetCpuCyclesPerUs() {
  trace::common::TimerInfo tsc_info = {};
  trace::common::GetTscTimerInfo(&tsc_info);

  if (tsc_info.frequency != 0) {
    return (tsc_info.frequency /
        static_cast<double>(base::Time::kMicrosecondsPerSecond));
  } else {
    uint64 cycle_start = trace::common::GetTsc();
    ::Sleep(HeapProxy::kSleepTimeForApproximatingCPUFrequency);
    return (trace::common::GetTsc() - cycle_start) /
        (HeapProxy::kSleepTimeForApproximatingCPUFrequency *
             static_cast<double>(base::Time::kMicrosecondsPerSecond));
  }
}

// Verify that the memory range [mem, mem + len[ is accessible.
bool MemoryRangeIsAccessible(uint8* mem, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    if (!Shadow::IsAccessible(mem + i))
      return false;
  }
  return true;
}

}  // namespace

double HeapProxy::cpu_cycles_per_us_ = 0.0;
// The default quarantine size for a new Heap.
size_t HeapProxy::default_quarantine_max_size_ = kDefaultQuarantineMaxSize_;
const char* HeapProxy::kHeapUseAfterFree = "heap-use-after-free";
const char* HeapProxy::kHeapBufferUnderFlow = "heap-buffer-underflow";
const char* HeapProxy::kHeapBufferOverFlow = "heap-buffer-overflow";
const char* HeapProxy::kAttemptingDoubleFree = "attempting double-free";
const char* HeapProxy::kWildAccess = "wild access";
const char* HeapProxy::kHeapUnknownError = "heap-unknown-error";

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

void HeapProxy::Init() {
  default_quarantine_max_size_ = kDefaultQuarantineMaxSize_;
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

  SetQuarantineMaxSize(default_quarantine_max_size_);

  HANDLE heap_new = ::HeapCreate(options, initial_size, maximum_size);
  if (heap_new == NULL)
    return false;

  heap_ = heap_new;

  return true;
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
  BlockHeader* block_header =
      reinterpret_cast<BlockHeader*>(::HeapAlloc(heap_, flags, alloc_size));

  if (block_header == NULL)
    return NULL;

  // Poison head and tail zones, and un-poison alloc.
  size_t header_size = sizeof(BlockHeader);
  size_t trailer_size = alloc_size - sizeof(BlockHeader) - bytes;
  Shadow::Poison(block_header, sizeof(BlockHeader), Shadow::kHeapLeftRedzone);

  // Capture the current stack. InitFromStack is inlined to preserve the
  // greatest number of stack frames.
  StackCapture stack;
  stack.InitFromStack();

  // Initialize the block fields.
  block_header->magic_number = kBlockHeaderSignature;
  block_header->block_size = bytes;
  block_header->state = ALLOCATED;
  block_header->alloc_stack = stack_cache_->SaveStackTrace(stack);
  block_header->alloc_tid = ::GetCurrentThreadId();

  BlockTrailer* block_trailer = GetBlockTrailer(block_header);
  block_trailer->free_stack = NULL;
  block_trailer->free_tid = 0;
  block_trailer->next_free_block = NULL;

  uint8* block_alloc = ToAlloc(block_header);
  DCHECK(MemoryRangeIsAccessible(block_alloc, bytes));

  Shadow::Poison(block_alloc + bytes, trailer_size, Shadow::kHeapRightRedzone);

  return block_alloc;
}

void* HeapProxy::ReAlloc(DWORD flags, void* mem, size_t bytes) {
  DCHECK(heap_ != NULL);

  // Always fail in-place reallocation requests.
  if ((flags & HEAP_REALLOC_IN_PLACE_ONLY) != 0)
    return NULL;

  void *new_mem = Alloc(flags, bytes);
  // Bail early if the new allocation didn't succeed
  // and avoid freeing the existing allocation.
  if (new_mem == NULL)
    return NULL;

  if (mem != NULL) {
    memcpy(new_mem, mem, std::min(bytes, Size(0, mem)));
    Free(flags, mem);
  }

  return new_mem;
}

bool HeapProxy::Free(DWORD flags, void* mem) {
  DCHECK(heap_ != NULL);
  BlockHeader* block = ToBlockHeader(mem);
  // The standard allows to call free on a null pointer. ToBlock returns null if
  // the given pointer is null so we return true here.
  if (block == NULL)
    return true;

  // Capture the current stack.
  StackCapture stack;
  stack.InitFromStack();

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
    AsanErrorInfo error_info = {};
    error_info.error_type = UNKNOWN_BAD_ACCESS;

    ReportAsanError(kAttemptingDoubleFree, static_cast<const uint8*>(mem),
                    context, stack, bad_access_kind, block,
                    ASAN_UNKNOWN_ACCESS, 0, &error_info);

    return false;
  }

  DCHECK(ToAlloc(block) == mem);
  BlockTrailer* trailer = GetBlockTrailer(block);
  trailer->free_stack = stack_cache_->SaveStackTrace(stack);
  trailer->free_timestamp = trace::common::GetTsc();
  trailer->free_tid = ::GetCurrentThreadId();

  // If the size of the allocation is zero then we shouldn't check the shadow
  // memory as it'll only contain the red-zone for the head and tail of this
  // block.
  if (block->block_size != 0 && !Shadow::IsAccessible(ToAlloc(block)))
    return false;

  QuarantineBlock(block);
  return true;
}

size_t HeapProxy::Size(DWORD flags, const void* mem) {
  DCHECK(heap_ != NULL);
  BlockHeader* block = ToBlockHeader(mem);
  if (block == NULL)
    return -1;

  return block->block_size;
}

bool HeapProxy::Validate(DWORD flags, const void* mem) {
  DCHECK(heap_ != NULL);
  return ::HeapValidate(heap_, flags, ToBlockHeader(mem)) == TRUE;
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
  {
    base::AutoLock lock(lock_);
    quarantine_max_size_ = quarantine_max_size;
  }

  TrimQuarantine();
}

void HeapProxy::TrimQuarantine() {
  while (true) {
    BlockHeader* free_block = NULL;
    BlockTrailer* trailer = NULL;
    size_t alloc_size = 0;

    // This code runs under a critical lock. Try to keep as much work out of
    // this scope as possible!
    {
      base::AutoLock lock(lock_);
      if (quarantine_size_ <= quarantine_max_size_)
        return;

      DCHECK(head_ != NULL);
      DCHECK(tail_ != NULL);

      free_block = head_;
      trailer = GetBlockTrailer(free_block);
      DCHECK(trailer != NULL);

      head_ = trailer->next_free_block;
      if (head_ == NULL)
        tail_ = NULL;

      alloc_size = GetAllocSize(free_block->block_size);

      DCHECK_GE(quarantine_size_, alloc_size);
      quarantine_size_ -= alloc_size;
    }

    // Return pointers to the stacks for reference counting purposes. We do this
    // outside of the heap lock to reduce contention.
    if (free_block->alloc_stack != NULL) {
      stack_cache_->ReleaseStackTrace(free_block->alloc_stack);
      free_block->alloc_stack = NULL;
    }
    if (trailer->free_stack != NULL) {
      stack_cache_->ReleaseStackTrace(trailer->free_stack);
      trailer->free_stack = NULL;
    }

    free_block->state = FREED;
    Shadow::Unpoison(free_block, alloc_size);
    ::HeapFree(heap_, 0, free_block);
  }
}

void HeapProxy::QuarantineBlock(BlockHeader* block) {
  DCHECK(block != NULL);

  BlockTrailer* free_block_trailer = GetBlockTrailer(block);
  DCHECK(free_block_trailer->next_free_block == NULL);
  block->state = QUARANTINED;

  // Poison the released alloc (marked as freed) and quarantine the block.
  // Note that the original data is left intact. This may make it easier
  // to debug a crash report/dump on access to a quarantined block.
  size_t alloc_size = GetAllocSize(block->block_size);
  uint8* mem = ToAlloc(block);
  Shadow::MarkAsFreed(mem, block->block_size);

  {
    base::AutoLock lock(lock_);

    quarantine_size_ += alloc_size;
    if (tail_ != NULL) {
      GetBlockTrailer(tail_)->next_free_block = block;
    } else {
      DCHECK(head_ == NULL);
      head_ = block;
    }
    tail_ = block;
  }

  TrimQuarantine();
}

size_t HeapProxy::GetAllocSize(size_t bytes) {
  // The Windows heap is 8-byte granular, so there's no gain in a lower
  // allocation granularity.
  const size_t kAllocGranularity = 8;
  bytes += sizeof(BlockHeader);
  bytes += sizeof(BlockTrailer);
  return common::AlignUp(bytes, kAllocGranularity);
}

HeapProxy::BlockHeader* HeapProxy::ToBlockHeader(const void* alloc) {
  if (alloc == NULL)
    return NULL;

  const uint8* mem = static_cast<const uint8*>(alloc);
  const BlockHeader* header = reinterpret_cast<const BlockHeader*>(mem) - 1;
  if (header->magic_number != kBlockHeaderSignature) {
    CONTEXT context = {};
    ::RtlCaptureContext(&context);

    StackCapture stack;
    stack.InitFromStack();

    AsanErrorInfo bad_access_info = {};
    base::debug::Alias(&bad_access_info);

    if (!OnBadAccess(mem,
                     context,
                     stack,
                     ASAN_UNKNOWN_ACCESS,
                     0,
                     &bad_access_info)) {
      bad_access_info.error_type = UNKNOWN_BAD_ACCESS;
      ReportAsanErrorBase("unknown bad access",
                          mem,
                          context,
                          stack,
                          UNKNOWN_BAD_ACCESS,
                          ASAN_READ_ACCESS,
                          0);
    }
    return NULL;
  }

  return const_cast<BlockHeader*>(header);
}

HeapProxy::BlockTrailer* HeapProxy::GetBlockTrailer(const BlockHeader* header) {
  DCHECK(header != NULL);
  DCHECK_EQ(kBlockHeaderSignature, header->magic_number);
  // We want the block trailers to be 4 byte aligned after the end of a block.
  const size_t kBlockTrailerAlignment = 4;

  uint8* mem = reinterpret_cast<uint8*>(const_cast<BlockHeader*>(header));
  size_t aligned_size =
      common::AlignUp(sizeof(BlockHeader) + header->block_size,
                      kBlockTrailerAlignment);

  return reinterpret_cast<BlockTrailer*>(mem + aligned_size);
}

uint8* HeapProxy::ToAlloc(BlockHeader* block) {
  DCHECK(block != NULL);
  DCHECK_EQ(kBlockHeaderSignature, block->magic_number);
  DCHECK(block->state == ALLOCATED || block->state == QUARANTINED);

  uint8* mem = reinterpret_cast<uint8*>(block);

  return mem + sizeof(BlockHeader);
}

void HeapProxy::ReportAddressInformation(const void* addr,
                                         BlockHeader* header,
                                         BadAccessKind bad_access_kind,
                                         AsanErrorInfo* bad_access_info) {
  DCHECK(addr != NULL);
  DCHECK(header != NULL);
  DCHECK(bad_access_info != NULL);

  BlockTrailer* trailer = GetBlockTrailer(header);
  DCHECK(trailer != NULL);

  uint8* block_alloc = ToAlloc(header);
  int offset = 0;
  char* offset_relativity = "";
  switch (bad_access_kind) {
    case HEAP_BUFFER_OVERFLOW:
      offset = static_cast<const uint8*>(addr) - block_alloc
          - header->block_size;
      offset_relativity = "beyond";
      break;
    case HEAP_BUFFER_UNDERFLOW:
      offset = block_alloc - static_cast<const uint8*>(addr);
      offset_relativity = "before";
      break;
    case USE_AFTER_FREE:
      offset = static_cast<const uint8*>(addr) - block_alloc;
      offset_relativity = "inside";
      break;
    default:
      NOTREACHED() << "Error trying to dump address information.";
  }

  size_t shadow_info_bytes = base::snprintf(
      bad_access_info->shadow_info,
      arraysize(bad_access_info->shadow_info) - 1,
      "%08X is %d bytes %s %d-byte block [%08X,%08X)\n",
      addr,
      offset,
      offset_relativity,
      header->block_size,
      block_alloc,
      block_alloc + header->block_size);

  // Ensure that we had enough space to store the full shadow info message.
  DCHECK_LE(shadow_info_bytes, arraysize(bad_access_info->shadow_info) - 1);

  // If we're not writing textual logs we can return here.
  if (!logger_->log_as_text())
    return;

  logger_->Write(bad_access_info->shadow_info);
  if (trailer->free_stack != NULL) {
    std::string message = base::StringPrintf(
        "freed here (stack_id=0x%08X):\n", trailer->free_stack->stack_id());
    logger_->WriteWithStackTrace(message,
                                 trailer->free_stack->frames(),
                                 trailer->free_stack->num_frames());
  }
  if (header->alloc_stack != NULL) {
    std::string message = base::StringPrintf(
        "previously allocated here (stack_id=0x%08X):\n",
        header->alloc_stack->stack_id());
    logger_->WriteWithStackTrace(message,
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
    else if (addr >= (ToAlloc(header) + header->block_size))
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
                            const StackCapture& stack,
                            AccessMode access_mode,
                            size_t access_size,
                            AsanErrorInfo* bad_access_info) {
  DCHECK(addr != NULL);
  base::AutoLock lock(lock_);
  BadAccessKind bad_access_kind = UNKNOWN_BAD_ACCESS;
  BlockHeader* header = FindAddressBlock(addr);

  if (header == NULL)
    return false;

  BlockTrailer* trailer = GetBlockTrailer(header);
  DCHECK(trailer != NULL);

  bad_access_kind = GetBadAccessKind(addr, header);
  // Get the bad access description if we've been able to determine its kind.
  if (bad_access_kind != UNKNOWN_BAD_ACCESS) {
    bad_access_info->error_type = bad_access_kind;
    bad_access_info->microseconds_since_free = GetTimeSinceFree(header);

    const char* bug_descr = AccessTypeToStr(bad_access_kind);
    if (header->alloc_stack != NULL) {
      memcpy(bad_access_info->alloc_stack,
             header->alloc_stack->frames(),
             header->alloc_stack->num_frames() * sizeof(void*));
      bad_access_info->alloc_stack_size = header->alloc_stack->num_frames();
      bad_access_info->alloc_tid = header->alloc_tid;
    }
    if (trailer->free_stack != NULL) {
      memcpy(bad_access_info->free_stack,
             trailer->free_stack->frames(),
             trailer->free_stack->num_frames() * sizeof(void*));
      bad_access_info->free_stack_size = trailer->free_stack->num_frames();
      bad_access_info->free_tid = trailer->free_tid;
    }
    ReportAsanError(bug_descr,
                    addr,
                    context,
                    stack,
                    bad_access_kind,
                    header,
                    access_mode,
                    access_size,
                    bad_access_info);
    return true;
  }

  return false;
}

void HeapProxy::ReportWildAccess(const void* addr,
                                 const CONTEXT& context,
                                 const StackCapture& stack,
                                 AccessMode access_mode,
                                 size_t access_size) {
  DCHECK(addr != NULL);
  ReportAsanErrorBase(AccessTypeToStr(WILD_ACCESS),
                      addr,
                      context,
                      stack,
                      WILD_ACCESS,
                      access_mode,
                      access_size);

  ASANDbgPrintContext(context);
}

void HeapProxy::ReportAsanError(const char* bug_descr,
                                const void* addr,
                                const CONTEXT& context,
                                const StackCapture& stack,
                                BadAccessKind bad_access_kind,
                                BlockHeader* header,
                                AccessMode access_mode,
                                size_t access_size,
                                AsanErrorInfo* bad_access_info) {
  DCHECK(bug_descr != NULL);
  DCHECK(addr != NULL);
  DCHECK(header != NULL);

  BlockTrailer* trailer = GetBlockTrailer(header);
  DCHECK(trailer != NULL);

  ReportAsanErrorBase(bug_descr,
                      addr,
                      context,
                      stack,
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
  if (trailer->free_stack != NULL) {
    ASANDbgMessage(L"Free stack trace:");
    ASANDbgCmd(L"dps %p l%d",
               trailer->free_stack->frames(),
               trailer->free_stack->num_frames());
  }

  ReportAddressInformation(addr, header, bad_access_kind, bad_access_info);

  ASANDbgPrintContext(context);
}

void HeapProxy::ReportAsanErrorBase(const char* bug_descr,
                                    const void* addr,
                                    const CONTEXT& context,
                                    const StackCapture& stack,
                                    BadAccessKind bad_access_kind,
                                    AccessMode access_mode,
                                    size_t access_size) {
  DCHECK(bug_descr != NULL);
  DCHECK(addr != NULL);

  // If we're not logging text
  if (!logger_->log_as_text())
    return;

  // Print the base of the Windbg help message.
  ASANDbgMessage(L"An Asan error has been found (%ls), here are the details:",
                 base::SysUTF8ToWide(bug_descr).c_str());

  // TODO(sebmarchand): Print PC, BP and SP.
  std::string output(base::StringPrintf(
      "SyzyASAN error: %s on address 0x%08X (stack_id=0x%08X)\n",
      bug_descr, addr, stack.stack_id()));
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
      return kHeapUseAfterFree;
    case HEAP_BUFFER_UNDERFLOW:
      return kHeapBufferUnderFlow;
    case HEAP_BUFFER_OVERFLOW:
      return kHeapBufferOverFlow;
    case WILD_ACCESS:
      return kWildAccess;
    case UNKNOWN_BAD_ACCESS:
      return kHeapUnknownError;
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

uint64 HeapProxy::GetTimeSinceFree(const BlockHeader* header) {
  DCHECK(header != NULL);

  if (header->state == ALLOCATED)
    return 0;

  BlockTrailer* trailer = GetBlockTrailer(header);
  DCHECK(trailer != NULL);

  uint64 cycles_since_free = trace::common::GetTsc() - trailer->free_timestamp;

  // On x86/64, as long as cpu_cycles_per_us_ is 64-bit aligned, the write is
  // atomic, which means we don't care about multiple writers since it's not an
  // update based on the previous value.
  if (cpu_cycles_per_us_ == 0.0)
    cpu_cycles_per_us_ = GetCpuCyclesPerUs();
  DCHECK_NE(0.0, cpu_cycles_per_us_);

  return cycles_since_free / cpu_cycles_per_us_;
}

}  // namespace asan
}  // namespace agent
