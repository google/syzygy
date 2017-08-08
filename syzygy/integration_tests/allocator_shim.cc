// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file defines symbols to override the same functions in the Visual C++
// CRT implementation.

#include <windows.h>
#include <malloc.h>

extern "C" {

namespace {

// Definitions of the following heap management functions provided by
// the SyzyAsan library:
// heap_create, heap_destroy, heap_alloc, heap_realloc, and heap_free.
typedef HANDLE(WINAPI* HeapCreatePtr)(DWORD, SIZE_T, SIZE_T);
typedef BOOL(WINAPI* HeapDestroyPtr)(HANDLE);
typedef LPVOID(WINAPI* HeapAllocPtr)(HANDLE, DWORD, SIZE_T);
typedef LPVOID(WINAPI* HeapReAllocPtr)(HANDLE, DWORD, LPVOID, SIZE_T);
typedef BOOL(WINAPI* HeapFreePtr)(HANDLE, DWORD, LPVOID);
typedef BOOL(WINAPI* HeapDestroyPtr)(HANDLE);

struct AsanRuntimePointers {
  AsanRuntimePointers() {
    // It retrieves the handle for the syzyasan_rtl.dll module
    // and the heap functions that it provides.
    if (asan_runtime.asan_module == nullptr) {
      asan_runtime.asan_module = GetModuleHandle(L"syzyasan_rtl.dll");
      if (asan_runtime.asan_module != nullptr) {
        asan_runtime.heap_create = reinterpret_cast<HeapCreatePtr>(
            ::GetProcAddress(asan_runtime.asan_module, "asan_HeapCreate"));
        asan_runtime.heap_alloc = reinterpret_cast<HeapAllocPtr>(
            ::GetProcAddress(asan_runtime.asan_module, "asan_HeapAlloc"));
        asan_runtime.heap_free = reinterpret_cast<HeapFreePtr>(
            ::GetProcAddress(asan_runtime.asan_module, "asan_HeapFree"));
        asan_runtime.heap_realloc = reinterpret_cast<HeapReAllocPtr>(
            ::GetProcAddress(asan_runtime.asan_module, "asan_HeapReAlloc"));
        asan_runtime.heap_destroy = reinterpret_cast<HeapDestroyPtr>(
            ::GetProcAddress(asan_runtime.asan_module, "asan_HeapDestroy"));
        asan_runtime.asan_heap = asan_runtime.heap_create(0, 0, 0);
      }
    }
  };

  static AsanRuntimePointers asan_runtime;
  HANDLE asan_heap = nullptr;
  HMODULE asan_module = nullptr;
  HeapCreatePtr heap_create = nullptr;
  HeapAllocPtr heap_alloc = nullptr;
  HeapFreePtr heap_free = nullptr;
  HeapReAllocPtr heap_realloc = nullptr;
  HeapDestroyPtr heap_destroy = nullptr;
};

// The no_sanitize_address attribute is needed to prevent instrumentation
// because that requires additional methods from Asan that are not supported
// in the SyzyAsan runtime library.
AsanRuntimePointers
    __attribute__((no_sanitize_address)) AsanRuntimePointers::asan_runtime;

inline HANDLE get_heap_handle() {
  return AsanRuntimePointers::asan_runtime.asan_heap;
}

}  // namespace

// These symbols override the CRT's implementation of the same functions.
__declspec(restrict) void* malloc(size_t size) {
  return AsanRuntimePointers::asan_runtime.heap_alloc(get_heap_handle(), 0,
                                                      size);
}

void free(void* ptr) {
  AsanRuntimePointers::asan_runtime.heap_free(get_heap_handle(), 0, ptr);
}

__declspec(restrict) void* realloc(void* ptr, size_t size) {
  return AsanRuntimePointers::asan_runtime.heap_realloc(get_heap_handle(), 0,
                                                        ptr, size);
}

__declspec(restrict) void* calloc(size_t n, size_t size) {
  void* ptr = malloc(size * n);
  if (ptr != nullptr)
    ::memset(ptr, 0, size * n);
  return ptr;
}

// The symbols
//   * __acrt_heap
//   * __acrt_initialize_heap
//   * __acrt_uninitialize_heap
//   * _get_heap_handle
// must be overridden all or none, as they are otherwise supplied
// by heap_handle.obj in the ucrt.lib file.
HANDLE __acrt_heap = nullptr;

bool __acrt_initialize_heap() {
  // The core CRT functions don't use the CRT's memory management
  // functions, instead they directly use |__acrt_heap| and calls the
  // ::Heap* functions. Because of this it's not possible to replace this
  // heap by an Asan one.
  __acrt_heap = ::HeapCreate(0, 0, 0);
  return true;
}

bool __acrt_uninitialize_heap() {
  ::HeapDestroy(__acrt_heap);
  __acrt_heap = nullptr;
  return true;
}

intptr_t _get_heap_handle(void) {
  return reinterpret_cast<intptr_t>(__acrt_heap);
}

}  // extern "C"
