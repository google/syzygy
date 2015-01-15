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
// Implementations of Asan-specific functions. These are stubs that don't
// actually do anything, but are necessary for ABI compatibility.

#include <windows.h>

namespace agent {
namespace asan {
struct AsanErrorInfo;  // Forward declaration.
}  // namespace asan
}  // namespace agent

namespace {
typedef void (*AsanErrorCallBack)(agent::asan::AsanErrorInfo*);
}  // namespace

extern "C" {

void WINAPI asan_SetCallBack(AsanErrorCallBack callback) {
  return;
}

void __declspec(naked) asan_SetAllocationFilterFlag() {
  __asm ret
}

void __declspec(naked) asan_ClearAllocationFilterFlag() {
  __asm ret
}

int asan_CrashForException(EXCEPTION_POINTERS* exception) {
  return EXCEPTION_CONTINUE_SEARCH;
}

}  // extern "C"
