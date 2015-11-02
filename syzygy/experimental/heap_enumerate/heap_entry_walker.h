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
// Implements an experimental command line tool that allocates a heap, and
// makes some allocations in it, then dumps same to text through introspection
// with symbols.

#ifndef SYZYGY_EXPERIMENTAL_HEAP_ENUMERATE_HEAP_ENTRY_WALKER_H_
#define SYZYGY_EXPERIMENTAL_HEAP_ENUMERATE_HEAP_ENTRY_WALKER_H_

#include "syzygy/refinery/core/bit_source.h"
#include "syzygy/refinery/types/type.h"
#include "syzygy/refinery/types/typed_data.h"

// As seen in Windbg help on the "!heap command".
enum HeapEntryFlags {
  HEAP_ENTRY_BUSY = 0x01,
  HEAP_ENTRY_EXTRA_PRESENT = 0x02,
  HEAP_ENTRY_FILL_PATTERN = 0x04,
  HEAP_ENTRY_VIRTUAL_ALLOC = 0x08,
  HEAP_ENTRY_LAST_ENTRY = 0x10,
  HEAP_ENTRY_SETTABLE_FLAG1 = 0x20,
  HEAP_ENTRY_SETTABLE_FLAG2 = 0x40,
  HEAP_ENTRY_SETTABLE_FLAG3 = 0x80,
};

//   The LFH mode mixes an ntdll local variable, with the HEAP pointer/handle
//   with the address of the entry for obfuscation.
class HeapEntryWalker {
 public:
  struct HeapEntry {
    uint16_t size;
    uint8_t flags;
    uint8_t tag;
    uint16_t prev_size;
    uint8_t segment_index;  // TODO(siggi): is this right???
    uint8_t unused_bytes;
  };
  COMPILE_ASSERT(sizeof(HeapEntry) == 8, heap_entry_is_not_8_bytes);

  HeapEntryWalker();

  // Returns the current entry decoded.
  virtual bool GetDecodedEntry(HeapEntry* entry) = 0;

  // Returns true iff the current entry is at or past the segment range.
  virtual bool AtEnd() const = 0;

  // Walk to the next entry in the segment.
  bool Next();

  // Accessor.
  const refinery::TypedData& curr_entry() const { return curr_entry_; }

 protected:
  virtual ~HeapEntryWalker() {}

  // Initialize the walker.
  bool Initialize(refinery::BitSource* bit_source);

  // A bit source that covers all memory we have for the heap.
  refinery::BitSource* heap_bit_source_;

  // The current heap entry.
  refinery::TypedData curr_entry_;

 private:
  DISALLOW_COPY_AND_ASSIGN(HeapEntryWalker);
};

// A class that knows how to de-obfuscate and walk heap segments.
// This XORs the "Encoding" field into the HEAP_ENTRY, given the
// "EncodeFlagMask" value is just so.
class SegmentEntryWalker : public HeapEntryWalker {
 public:
  SegmentEntryWalker() = default;

  // Initialize the walker to walk @p segment.
  bool Initialize(const refinery::TypedData& heap,
                  const refinery::TypedData& segment);

  // Returns the current entry decoded.
  bool GetDecodedEntry(HeapEntry* entry) override;
  bool AtEnd() const override;

 private:
  // An address range covering the segment under enumeration.
  refinery::AddressRange segment_range_;

  // The encoding for entries in this range.
  std::vector<uint8_t> encoding_;

  DISALLOW_COPY_AND_ASSIGN(SegmentEntryWalker);
};

// The LFH mode mixes an ntdll local variable, with the HEAP pointer/handle
// with the address of the entry for obfuscation.
class LFHBinEntryWalker : public HeapEntryWalker {
 public:
  LFHBinEntryWalker() = default;

  bool Initialize(refinery::BitSource* bit_source,
                  refinery::UserDefinedTypePtr heap_user_data_header_type,
                  SegmentEntryWalker* walker);

  bool GetDecodedEntry(HeapEntry* entry) override;
  bool AtEnd() const override;

  // Accessor.
  const refinery::TypedData& heap_userdata_header() const {
    return heap_userdata_header_;
  }

 private:
  // An address range covering the bin under enumeration.
  refinery::AddressRange bin_range_;
  refinery::TypedData heap_userdata_header_;

  DISALLOW_COPY_AND_ASSIGN(LFHBinEntryWalker);
};

#endif  // SYZYGY_EXPERIMENTAL_HEAP_ENUMERATE_HEAP_ENTRY_WALKER_H_
