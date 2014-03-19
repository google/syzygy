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
// Declares a collection of static hooks that are used to provide ASAN with
// information about the bulk allocation and freeing of memory.

#ifndef WTF_AsanHooks_h
#define WTF_AsanHooks_h

namespace WTF {

// This is called by the underlying allocator to indicate that a region of
// memory has been bulk reserved from the operating system, yet is reserved
// for use by the allocator. The ASAN instrumentation will redzone this memory.
// As memory is doled out by the allocator the ASAN instrumentation can then
// green zone it, and subsequently redzone it when it is returned (freed) to
// the allocator.
// @param addr The starting address of the reserved memory.
// @param length The size of the reservation.
typedef void (*AsanMemoryReservedCallback)(void* addr, size_t length);

// This is called by the underlying allocator to indicate that a region of
// memory has been returned to the operating system. This region of memory is
// then potentially accessible by other things running in the process. The ASAN
// instrumentation will consequently greenzone the memory.
// @param addr The starting address of the released memory.
// @param length The size of the released memory.
typedef void (*AsanMemoryReleasedCallback)(void* addr, size_t length);

// Static callbacks.
extern AsanMemoryReservedCallback gAsanMemoryReservedCallback;
extern AsanMemoryReleasedCallback gAsanMemoryReleasedCallback;

}  // namespace WTF

#endif  // WTF_AsanHooks_h
