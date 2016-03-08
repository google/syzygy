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
// Implementations of the Asan heap interceptors. These functions are
// instrumented and log detailed function call information to the call-trace
// service.

#include <windows.h>

#include "base/hash.h"
#include "base/synchronization/lock.h"
#include "syzygy/agent/memprof/memprof.h"

// A wrapper to EMIT_DETAILED_FUNCTION_CALL that provides the MemoryProfiler
// FunctionCallLogger instance.
#define EMIT_DETAILED_HEAP_FUNCTION_CALL(...)  \
    DCHECK_NE(static_cast<agent::memprof::MemoryProfiler*>(nullptr),  \
              agent::memprof::memory_profiler.get());  \
    EMIT_DETAILED_FUNCTION_CALL(  \
        &agent::memprof::memory_profiler->function_call_logger(),  \
        agent::memprof::memory_profiler->GetOrAllocateThreadState()->  \
            segment(),  \
        __VA_ARGS__);

// A conditional scoped lock, based on timestamp serialization. Used to
// completely serialize heap access when enabled.
struct ConditionalScopedLock {
 public:
  ConditionalScopedLock() : locked_(
      agent::memprof::memory_profiler->parameters().serialize_timestamps) {
    if (locked_)
      conditional_lock_.Acquire();
  }

  ~ConditionalScopedLock() {
    if (locked_)
      conditional_lock_.Release();
  }

 private:
  static base::Lock conditional_lock_;
  bool locked_;
};
base::Lock ConditionalScopedLock::conditional_lock_;

extern "C" {

HANDLE WINAPI asan_GetProcessHeap() {
  // This function doesn't need to be logged, but does need to be implemented
  // for compatibility with old ASAN implementations.
  return ::GetProcessHeap();
}

HANDLE WINAPI asan_HeapCreate(DWORD options,
                              SIZE_T initial_size,
                              SIZE_T maximum_size) {
  // This ensures that all heap access is synchronous if 'serialize_timestamps'
  // is enabled.
  ConditionalScopedLock conditional_scoped_lock;
  HANDLE ret = ::HeapCreate(options, initial_size, maximum_size);
  EMIT_DETAILED_HEAP_FUNCTION_CALL(options, initial_size, maximum_size, ret);
  return ret;
}

BOOL WINAPI asan_HeapDestroy(HANDLE heap) {
  // This ensures that all heap access is synchronous if 'serialize_timestamps'
  // is enabled.
  ConditionalScopedLock conditional_scoped_lock;
  BOOL ret = ::HeapDestroy(heap);
  EMIT_DETAILED_HEAP_FUNCTION_CALL(heap, ret);
  return ret;
}

LPVOID WINAPI asan_HeapAlloc(HANDLE heap,
                             DWORD flags,
                             SIZE_T bytes) {
  // This ensures that all heap access is synchronous if 'serialize_timestamps'
  // is enabled.
  ConditionalScopedLock conditional_scoped_lock;
  LPVOID ret = ::HeapAlloc(heap, flags, bytes);
  EMIT_DETAILED_HEAP_FUNCTION_CALL(heap, flags, bytes, ret);
  return ret;
}

LPVOID WINAPI asan_HeapReAlloc(HANDLE heap,
                               DWORD flags,
                               LPVOID mem,
                               SIZE_T bytes) {
  // This ensures that all heap access is synchronous if 'serialize_timestamps'
  // is enabled.
  ConditionalScopedLock conditional_scoped_lock;
  LPVOID ret = ::HeapReAlloc(heap, flags, mem, bytes);
  EMIT_DETAILED_HEAP_FUNCTION_CALL(heap, flags, mem, bytes, ret);
  return ret;
}

BOOL WINAPI asan_HeapFree(HANDLE heap,
                          DWORD flags,
                          LPVOID mem) {
  // Calculate a hash value of the contents if necessary.
  uint32_t hash = 0;
  if (mem != nullptr &&
      agent::memprof::memory_profiler->parameters().hash_contents_at_free) {
    size_t size = ::HeapSize(heap, 0, mem);
    hash = base::SuperFastHash(reinterpret_cast<const char*>(mem), size);
  }

  // This ensures that all heap access is synchronous if 'serialize_timestamps'
  // is enabled.
  ConditionalScopedLock conditional_scoped_lock;
  BOOL ret = ::HeapFree(heap, flags, mem);
  EMIT_DETAILED_HEAP_FUNCTION_CALL(heap, flags, mem, ret, hash);
  return ret;
}

SIZE_T WINAPI asan_HeapSize(HANDLE heap,
                            DWORD flags,
                            LPCVOID mem) {
  // This ensures that all heap access is synchronous if 'serialize_timestamps'
  // is enabled.
  ConditionalScopedLock conditional_scoped_lock;
  SIZE_T ret = ::HeapSize(heap, flags, mem);
  EMIT_DETAILED_HEAP_FUNCTION_CALL(heap, flags, mem, ret);
  return ret;
}

BOOL WINAPI asan_HeapValidate(HANDLE heap,
                              DWORD flags,
                              LPCVOID mem) {
  // This ensures that all heap access is synchronous if 'serialize_timestamps'
  // is enabled.
  ConditionalScopedLock conditional_scoped_lock;
  BOOL ret = ::HeapValidate(heap, flags, mem);
  EMIT_DETAILED_HEAP_FUNCTION_CALL(heap, flags, mem, ret);
  return ret;
}

SIZE_T WINAPI asan_HeapCompact(HANDLE heap,
                               DWORD flags) {
  // This ensures that all heap access is synchronous if 'serialize_timestamps'
  // is enabled.
  ConditionalScopedLock conditional_scoped_lock;
  SIZE_T ret = ::HeapCompact(heap, flags);
  EMIT_DETAILED_HEAP_FUNCTION_CALL(heap, flags, ret);
  return ret;
}

BOOL WINAPI asan_HeapLock(HANDLE heap) {
  // This ensures that all heap access is synchronous if 'serialize_timestamps'
  // is enabled.
  ConditionalScopedLock conditional_scoped_lock;
  BOOL ret = ::HeapLock(heap);
  EMIT_DETAILED_HEAP_FUNCTION_CALL(heap, ret);
  return ret;
}

BOOL WINAPI asan_HeapUnlock(HANDLE heap) {
  // This ensures that all heap access is synchronous if 'serialize_timestamps'
  // is enabled.
  ConditionalScopedLock conditional_scoped_lock;
  BOOL ret = ::HeapUnlock(heap);
  EMIT_DETAILED_HEAP_FUNCTION_CALL(heap, ret);
  return ret;
}

BOOL WINAPI asan_HeapWalk(HANDLE heap,
                          LPPROCESS_HEAP_ENTRY entry) {
  // This ensures that all heap access is synchronous if 'serialize_timestamps'
  // is enabled.
  ConditionalScopedLock conditional_scoped_lock;
  BOOL ret = ::HeapWalk(heap, entry);
  EMIT_DETAILED_HEAP_FUNCTION_CALL(heap, entry, ret);
  return ret;
}

BOOL WINAPI asan_HeapSetInformation(
    HANDLE heap, HEAP_INFORMATION_CLASS info_class,
    PVOID info, SIZE_T info_length) {
  // This ensures that all heap access is synchronous if 'serialize_timestamps'
  // is enabled.
  ConditionalScopedLock conditional_scoped_lock;
  BOOL ret = ::HeapSetInformation(heap, info_class, info, info_length);
  EMIT_DETAILED_HEAP_FUNCTION_CALL(heap, info_class, info, info_length, ret);
  return ret;
}

BOOL WINAPI asan_HeapQueryInformation(
    HANDLE heap, HEAP_INFORMATION_CLASS info_class,
    PVOID info, SIZE_T info_length, PSIZE_T return_length) {
  // This ensures that all heap access is synchronous if 'serialize_timestamps'
  // is enabled.
  ConditionalScopedLock conditional_scoped_lock;
  BOOL ret = ::HeapQueryInformation(
      heap, info_class, info, info_length, return_length);
  EMIT_DETAILED_HEAP_FUNCTION_CALL(
      heap, info_class, info, info_length, return_length, ret);
  return ret;
}

}  // extern "C"
