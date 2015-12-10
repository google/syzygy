// Copyright 2015 Google Inc. All Rights Reserved.
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

#ifndef SYZYGY_REFINERY_PROCESS_STATE_RECORD_TRAITS_H_
#define SYZYGY_REFINERY_PROCESS_STATE_RECORD_TRAITS_H_

#include "syzygy/refinery/process_state/refinery.pb.h"

namespace refinery {

enum class RecordId {
  BYTES,
  STACK,
  STACK_FRAME,
  TYPED_BLOCK,
  MODULE,
  HEAP_METADATA,
  HEAP_ALLOCATION,
};

template <typename T>
class RecordTraits;

template<>
class RecordTraits<Bytes> {
 public:
  static const RecordId ID = RecordId::BYTES;
};

template<>
class RecordTraits<Stack> {
 public:
  static const RecordId ID = RecordId::STACK;
};

template<>
class RecordTraits<StackFrame> {
 public:
  static const RecordId ID = RecordId::STACK_FRAME;
};

template<>
class RecordTraits<TypedBlock> {
 public:
  static const RecordId ID = RecordId::TYPED_BLOCK;
};

template<>
class RecordTraits<Module> {
 public:
  static const RecordId ID = RecordId::MODULE;
};

template <>
class RecordTraits<HeapMetadata> {
 public:
  static const RecordId ID = RecordId::HEAP_METADATA;
};

template <>
class RecordTraits<HeapAllocation> {
 public:
  static const RecordId ID = RecordId::HEAP_ALLOCATION;
};

}  // namespace refinery

#endif  // SYZYGY_REFINERY_PROCESS_STATE_RECORD_TRAITS_H_
