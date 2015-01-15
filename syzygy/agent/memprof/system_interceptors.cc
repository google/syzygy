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
// Implementations of the Asan system interceptors. These are simple
// pass-throughs to the original functions for the purpose of Asan
// compatibility.

#include "windows.h"

extern "C" {

BOOL WINAPI asan_ReadFile(HANDLE hFile,
                          LPVOID lpBuffer,
                          DWORD nNumberOfBytesToRead,
                          LPDWORD lpNumberOfBytesRead,
                          LPOVERLAPPED lpOverlapped) {
  return ::ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead,
                    lpOverlapped);
}

BOOL WINAPI asan_ReadFileEx(
    HANDLE hFile,
    LPVOID lpBuffer,
    DWORD nNumberOfBytesToRead,
    LPOVERLAPPED lpOverlapped,
    LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
  return ::ReadFileEx(hFile, lpBuffer, nNumberOfBytesToRead, lpOverlapped,
                      lpCompletionRoutine);
}

BOOL WINAPI asan_WriteFile(HANDLE hFile,
                           LPCVOID lpBuffer,
                           DWORD nNumberOfBytesToWrite,
                           LPDWORD lpNumberOfBytesWritten,
                           LPOVERLAPPED lpOverlapped) {
  return ::WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite,
                     lpNumberOfBytesWritten, lpOverlapped);
}

BOOL WINAPI asan_WriteFileEx(
    HANDLE hFile,
    LPCVOID lpBuffer,
    DWORD nNumberOfBytesToWrite,
    LPOVERLAPPED lpOverlapped,
    LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
  return ::WriteFileEx(hFile, lpBuffer, nNumberOfBytesToWrite, lpOverlapped,
                       lpCompletionRoutine);
}

long WINAPI asan_InterlockedCompareExchange(long volatile* Destination,
                                            long Exchange,
                                            long Comperand) {
  return ::InterlockedCompareExchange(Destination, Exchange, Comperand);
}

long WINAPI asan_InterlockedIncrement(long* lpAddend) {
  return ::InterlockedIncrement(lpAddend);
}

long WINAPI asan_InterlockedDecrement(long* lpAddend) {
  return ::InterlockedDecrement(lpAddend);
}

long WINAPI asan_InterlockedExchange(long volatile* Target, long Value) {
  return ::InterlockedExchange(Target, Value);
}

long WINAPI asan_InterlockedExchangeAdd(long volatile* Addend, long Value) {
  return ::InterlockedExchangeAdd(Addend, Value);
}

}  // extern "C"
