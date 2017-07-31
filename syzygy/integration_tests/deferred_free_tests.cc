// Copyright 2016 Google Inc. All Rights Reserved.
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
#include "syzygy/integration_tests/deferred_free_tests.h"

#include <windows.h>  // NOLINT

#include "syzygy/common/asan_parameters.h"

namespace testing {

namespace {

// Since the TLS callback should not be invoked for other tests,
// |tls_callback_enabled| is checked by the callback before calling the
// real implementation.
bool tls_callback_enabled = false;

// Used to validate that the TLS callback actually ran.
bool tls_callback_ran = false;

// Real implementation of the TLS callback.
void NTAPI TlsCallbackImpl(DWORD dwReason) {
  // Only interested in the syzyasan_rtl module being detached. On that event,
  // free enough blocks to trigger a trim. This must not deadlock.
  if (dwReason == DLL_THREAD_DETACH) {
    // 10x quantine size is more than enough to trigger a trim.
    for (int i = 0; i < 20000; i++) {
      int* a = new int[common::kDefaultQuarantineSize / 1000];
      delete[] a;
    }
  }
  tls_callback_ran = true;
}

// This will be set as the TLS callback. It calls the real implementation only
// if |tls_callback_enabled| is set.
void NTAPI TlsCallback(PVOID, DWORD dwReason, PVOID) {
  if (tls_callback_enabled)
    TlsCallbackImpl(dwReason);
}

// Magic to set the TLS callback.
#ifdef _WIN64
#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:tls_callback_func")
#else
#pragma comment(linker, "/INCLUDE:__tls_used")
#pragma comment(linker, "/INCLUDE:_tls_callback_func")
#endif

#ifdef _WIN64
#pragma const_seg(".CRT$XLF")
#else
#pragma data_seg(".CRT$XLF")
#endif

EXTERN_C PIMAGE_TLS_CALLBACK tls_callback_func = TlsCallback;

#ifdef _WIN64
#pragma const_seg()
#else
#pragma data_seg()
#endif  //_WIN64

}  // namespace

// Implementation of the AsanDeferredFreeTLS test. Returns 0 on success, 1 on
// failure.
size_t AsanDeferredFreeTLSImpl() {
  tls_callback_ran = false;

  // Enable the deferred free thread. This will spawn up a new thread, which
  // will trigger the TLS callback (this event is ignored by our TLS
  // implementation).
  HMODULE syzyasan_handle = ::GetModuleHandle(L"syzyasan_rtl.dll");
  if (!syzyasan_handle)
    return 1;

  typedef VOID(WINAPI * SyzyasanEnableDeferredFreeThreadFunc)(VOID);
  SyzyasanEnableDeferredFreeThreadFunc syzyasan_enable_deferred_free =
      reinterpret_cast<SyzyasanEnableDeferredFreeThreadFunc>(
          ::GetProcAddress(syzyasan_handle, "asan_EnableDeferredFreeThread"));
  if (syzyasan_enable_deferred_free) {
    syzyasan_enable_deferred_free();
  } else {
    return 1;
  }

  // Disable the deferred free thread. This will shutdown the thread which will
  // again trigger the TLS callback. This is the event we're interested in.
  typedef VOID(WINAPI * SyzyasanDisableDeferredFreeThreadFunc)(VOID);
  if (syzyasan_handle) {
    SyzyasanDisableDeferredFreeThreadFunc syzyasan_disable_deferred_free =
        reinterpret_cast<SyzyasanDisableDeferredFreeThreadFunc>(
            ::GetProcAddress(syzyasan_handle,
                             "asan_DisableDeferredFreeThread"));
    if (syzyasan_disable_deferred_free) {
      syzyasan_disable_deferred_free();
    } else {
      return 1;
    }
  }

  // |tls_callback_ran| should have been set otherwise something went wrong and
  // return an error.
  if (!tls_callback_ran)
    return 1;

  return 0;
}

// This test was added after a shutdown hang was found. It makes sure that TLS
// callbacks do not deadlock if they free enough blocks to trigger a trim.
// Returns 0 on success, 1 on failure.
size_t AsanDeferredFreeTLS() {
  tls_callback_enabled = true;
  size_t ret = AsanDeferredFreeTLSImpl();
  tls_callback_enabled = false;

  return ret;
}

}  // namespace testing
