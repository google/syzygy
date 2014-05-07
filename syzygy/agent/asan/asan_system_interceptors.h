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
// Defines the ASan system interceptors.
#ifndef SYZYGY_AGENT_ASAN_ASAN_SYSTEM_INTERCEPTORS_H_
#define SYZYGY_AGENT_ASAN_ASAN_SYSTEM_INTERCEPTORS_H_

#include <windows.h>

// Exposes the system interceptors.
extern "C" {

// Allows specifying a callback that will be called by the function interceptors
// once the internal call to the intercepted function returns. This is for
// testing purposes only.
typedef void (*InterceptorTailCallback)(void);
void asan_SetInterceptorTailCallback(InterceptorTailCallback callback);

}  // extern "C"

#endif  // SYZYGY_AGENT_ASAN_ASAN_SYSTEM_INTERCEPTORS_H_
