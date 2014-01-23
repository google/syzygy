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

#include "syzygy/agent/asan/asan_system_interceptors.h"

#include <algorithm>

#include "base/logging.h"
#include "syzygy/agent/asan/asan_rtl_utils.h"

namespace {

using agent::asan::HeapProxy;
using agent::asan::Shadow;
using agent::asan::TestMemoryRange;
using agent::asan::TestStructure;

// A callback that will be used in the functions interceptors once the call
// to the intercepted function has been done. This is for testing purposes
// only.
InterceptorTailCallback interceptor_tail_callback = NULL;

}  // namespace

extern "C" {

void asan_SetInterceptorCallback(InterceptorTailCallback callback) {
  interceptor_tail_callback = callback;
}

BOOL WINAPI asan_ReadFile(HANDLE file_handle,
                          LPVOID buffer,
                          DWORD bytes_to_read,
                          LPDWORD bytes_read,
                          LPOVERLAPPED overlapped) {
  // TODO(sebmarchand): Add more checks for the asynchronous calls to this
  //     function. More details about the asynchronous calls to ReadFile are
  //     available here: http://support.microsoft.com/kb/156932.

  // Ensures that the input values are accessible.

  TestMemoryRange(reinterpret_cast<uint8*>(buffer),
                  bytes_to_read,
                  HeapProxy::ASAN_WRITE_ACCESS);

  if (bytes_read != NULL)
    TestStructure<DWORD>(bytes_read, HeapProxy::ASAN_WRITE_ACCESS);

  if (overlapped != NULL)
    TestStructure<OVERLAPPED>(overlapped, HeapProxy::ASAN_READ_ACCESS);

  BOOL ret = ::ReadFile(file_handle,
                        buffer,
                        bytes_to_read,
                        bytes_read,
                        overlapped);

  // Run the interceptor callback if it has been set.
  if (interceptor_tail_callback != NULL)
    (*interceptor_tail_callback)();

  if (ret == FALSE)
    return ret;

  // Even if the overlapped pointer wasn't NULL it might become invalid after
  // the call to ReadFile, and so we can't test that this structure is
  // accessible.

  DCHECK_EQ(TRUE, ret);
  CHECK(bytes_read == NULL || *bytes_read <= bytes_to_read);
  TestMemoryRange(reinterpret_cast<uint8*>(buffer),
                  bytes_to_read,
                  HeapProxy::ASAN_WRITE_ACCESS);

  if (bytes_read != NULL)
    TestStructure<DWORD>(bytes_read, HeapProxy::ASAN_WRITE_ACCESS);

  return ret;
}

BOOL WINAPI asan_WriteFile(HANDLE file_handle,
                           LPCVOID buffer,
                           DWORD bytes_to_write,
                           LPDWORD bytes_written,
                           LPOVERLAPPED overlapped) {
  // Ensures that the input values are accessible.

  TestMemoryRange(reinterpret_cast<const uint8*>(buffer),
                  bytes_to_write,
                  HeapProxy::ASAN_READ_ACCESS);

  if (bytes_written != NULL)
    TestStructure<DWORD>(bytes_written, HeapProxy::ASAN_WRITE_ACCESS);

  if (overlapped != NULL)
    TestStructure<OVERLAPPED>(overlapped, HeapProxy::ASAN_READ_ACCESS);

  BOOL ret = ::WriteFile(file_handle,
                         buffer,
                         bytes_to_write,
                         bytes_written,
                         overlapped);

  // Run the interceptor callback if it has been set.
  if (interceptor_tail_callback != NULL)
    (*interceptor_tail_callback)();

  if (ret == FALSE)
    return ret;

  // Even if the overlapped pointer wasn't NULL it might become invalid after
  // the call to WriteFile, and so we can't test that this structure is
  // accessible.

  DCHECK_EQ(TRUE, ret);
  CHECK(bytes_written == NULL || *bytes_written <= bytes_to_write);
  TestMemoryRange(reinterpret_cast<const uint8*>(buffer),
                  bytes_to_write,
                  HeapProxy::ASAN_READ_ACCESS);

  if (bytes_written != NULL)
    TestStructure<DWORD>(bytes_written, HeapProxy::ASAN_WRITE_ACCESS);

  return ret;
}

}  // extern "C"
