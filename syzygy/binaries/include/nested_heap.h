// Copyright 2013 Google Inc. All Rights Reserved.
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
// Implements the functions that a custom heap can use to provide necessary
// metadata to the SyzyASan bookkeeping.
#ifndef SYZYGY_AGENT_ASAN_NESTED_HEAP_H_
#define SYZYGY_AGENT_ASAN_NESTED_HEAP_H_

extern "C" {

// Poisons the given range of memory, marking it as inaccessible. This should
// be done when a block of unused memory is allocated from the OS.
// @pre address + size mod 8 == 0.
// @param address The starting address.
// @param size The size of the memory to poison.
void asan_PoisonMemoryRange(const void* address, size_t size);

// Unpoisons the given range of memory, marking it as accessible. This should
// be done after a block of memory has been returned to the OS.
// @pre address mod 8 == 0 && size mod 8 == 0.
// @param addr The starting address.
// @param size The size of the memory to unpoison.
void asan_UnpoisonMemoryRange(const void* address, size_t size);

// Given a desired user object size and alignment, returns the size of memory
// required to wrap the object with ASAN headers and footers. Assumes the
// ASAN-wrapped object will be placed with the same alignment.
// @param user_object_size The user object size.
// @param alignment The user object alignment.
size_t asan_GetAsanObjectSize(size_t user_object_size, size_t alignment);

// Mark the given block as allocated. This will red-zone the header and
// trailer, green zone the user data, and grab an allocation stack trace and
// other metadata.
// @param asan_pointer The ASan block to initialize.
// @param user_object_size The user object size.
// @param alignment The user object alignment.
void asan_InitializeObject(void* asan_pointer,
                           size_t user_object_size,
                           size_t alignment);

// Given a pointer to an ASAN wrapped allocation, returns the location and
// size of the user data contained within.
// @param asan_pointer The pointer to the ASan block.
// @param user_pointer Receives the user pointer.
// @param size Receives the size of the user part of this block.
void asan_GetUserExtent(const void* asan_pointer,
                        void** user_pointer,
                        size_t* size);

// Return the location and size of the ASAN block wrapping the given user
// pointer.
// @param user_pointer The user pointer for this ASan block.
// @param asan_pointer Receives the ASan pointer.
// @param size Receives the size of this ASan block.
void asan_GetAsanExtent(const void* user_pointer,
                        void** asan_pointer,
                        size_t* size);

// Mark the given block as freed, but still residing in memory. This will
// red-zone the user data and grab a free stack trace and other metadata.
// After this call the object is effectively quarantined and access to it will
// be caught as errors.
// @param asan_pointer The pointer to the ASan block to quarantine.
void asan_QuarantineObject(void* asan_pointer);

// Clean up the object's metadata. The object is dead entirely, clean up the
// metadata. This makes sure that we can decrement stack trace ref-counts and
// reap them. This leaves the memory red-zoned (inaccessible).
// NOTE: If the memory has been returned to the OS then it must also be
//       unpoisoned.
// @param asan_pointer The pointer to the ASan block to destroy.
void asan_DestroyObject(void* asan_pointer);

// Clones an object from one location to another. This mediates access to the
// protected header and footer wrapping the user object, as the client code
// may itself be instrumented. This will also copy the shadow memory: the new
// object will preserve the alive or free status of the old object.
// NOTES:
// - The client must ensure there is sufficient room at the destination
//   for the object to be cloned.
// - If the source object is no longer needed it is up to the client to call
//   QuarantineObject or DestroyObject.
// - It is up to the client to ensure that the destination address meets any
//   alignment requirements of the source object.
// @param src_asan_pointer The pointer to the ASan source block.
// @param dst_asan_pointer The pointer to the ASan destination block.
void asan_CloneObject(const void* src_asan_pointer,
                      void* dst_asan_pointer);

}  // extern "C"

#endif  // SYZYGY_AGENT_ASAN_NESTED_HEAP_H_
