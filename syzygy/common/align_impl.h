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
// Internal implementations for align.h. Not meant to be included directly.

#ifndef SYZYGY_COMMON_ALIGN_IMPL_H_
#define SYZYGY_COMMON_ALIGN_IMPL_H_

namespace common {

template<typename T> bool IsPowerOfTwo(const T* pointer) {
  return IsPowerOfTwo(reinterpret_cast<uintptr_t>(pointer));
}

template<typename T> T* AlignUp(T* pointer, size_t alignment) {
  return reinterpret_cast<T*>(AlignUp(
      reinterpret_cast<uintptr_t>(pointer), alignment));
}

template<typename T> const T* AlignUp(const T* pointer, size_t alignment) {
  return reinterpret_cast<const T*>(AlignUp(
      reinterpret_cast<uintptr_t>(pointer), alignment));
}

template<typename T> T* AlignDown(T* pointer, size_t alignment) {
  return reinterpret_cast<T*>(AlignDown(
      reinterpret_cast<uintptr_t>(pointer), alignment));
}

template<typename T> const T* AlignDown(const T* pointer, size_t alignment) {
  return reinterpret_cast<const T*>(AlignDown(
      reinterpret_cast<uintptr_t>(pointer), alignment));
}

template<typename T> bool IsAligned(const T* pointer, size_t alignment) {
  return IsAligned(reinterpret_cast<uintptr_t>(pointer), alignment);
}

template<typename T> size_t GetAlignment(const T* pointer) {
  return GetAlignment(reinterpret_cast<uintptr_t>(pointer));
}

}  // namespace common

#endif  // SYZYGY_COMMON_ALIGN_IMPL_H_
