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
//
// Implements an experimental command line tool that tallies the amount
// of object code contributed to an executable by source line.

#ifndef SYZYGY_EXPERIMENTAL_HEAP_ENUMERATE_HEAP_ENUMERATE_H_
#define SYZYGY_EXPERIMENTAL_HEAP_ENUMERATE_HEAP_ENUMERATE_H_

#include <windows.h>
#include <map>

#include "syzygy/refinery/core/address.h"
#include "syzygy/refinery/types/type.h"
#include "syzygy/refinery/types/typed_data.h"

// fwd.
class SegmentEntryWalker;
class LFHBinWalker;

class HeapEnumerate {
 public:
  HeapEnumerate();
  ~HeapEnumerate();

  bool Initialize();
  void EnumerateHeap(FILE* output_file);

 private:
  class HeapEnumerator;

  void EnumSegment(const HeapEnumerator& enumerator,
                   SegmentEntryWalker* walker);
  void EnumLFHBin(const HeapEnumerator& enumerator, LFHBinWalker* walker);

  bool AllocateSomeBlocks();

  // Outputs the allocations from alloc_ that start within @p range.
  void PrintAllocsInRange(const refinery::AddressRange& range);

  void DumpTypedData(const refinery::TypedData& data, size_t indent);

  HANDLE heap_;
  FILE* output_;
  std::map<refinery::Address, size_t> allocs_;
};

#endif  // SYZYGY_EXPERIMENTAL_HEAP_ENUMERATE_HEAP_ENUMERATE_H_
