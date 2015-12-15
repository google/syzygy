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

// A base class for the segment and LFH entry walkers.
class HeapEntryWalker {
 public:
  HeapEntryWalker();

  // Returns true iff the current entry is at or past the segment range.
  virtual bool AtEnd() const = 0;

  // Walk to the next entry in the segment.
  virtual bool Next() = 0;

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
  struct HeapEntry {
    uint16_t size;
    uint8_t flags;
    uint8_t tag;
    uint16_t prev_size;
    uint8_t segment_index;  // TODO(siggi): is this right???
    uint8_t unused_bytes;
  };
  static_assert(sizeof(HeapEntry) == 8, "HeapEntry is not 8 bytes.");

  SegmentEntryWalker() = default;

  // Initialize the walker to walk @p segment.
  bool Initialize(refinery::BitSource* bit_source,
                  const refinery::TypedData& heap,
                  const refinery::TypedData& segment);

  // Returns the current entry decoded.
  bool GetDecodedEntry(HeapEntry* entry);

  bool Next() override;
  bool AtEnd() const override;

 private:
  // An address range covering the segment under enumeration.
  refinery::AddressRange segment_range_;

  // The encoding for entries in this range.
  std::vector<uint8_t> encoding_;

  DISALLOW_COPY_AND_ASSIGN(SegmentEntryWalker);
};

// Walks the entries in a single LFH bin.
class LFHBinWalker : public HeapEntryWalker {
 public:
  struct LFHEntry {
    uint32_t heap_subsegment;
    uint16_t prev_size;
    uint8_t segment_index;  // TODO(siggi): is this right???
    uint8_t unused_bytes;
  };
  static_assert(sizeof(LFHEntry) == sizeof(SegmentEntryWalker::HeapEntry),
                "LFHEntry size mismatch.");

  LFHBinWalker();

  bool Initialize(refinery::Address heap,
                  refinery::BitSource* bit_source,
                  refinery::UserDefinedTypePtr heap_user_data_header_type,
                  SegmentEntryWalker* walker);

  bool GetDecodedEntry(LFHEntry* entry);
  bool Next() override;
  bool AtEnd() const override;

  // Accessor.
  const refinery::TypedData& heap_userdata_header() const {
    return heap_userdata_header_;
  }

  uint64_t entry_byte_size() const { return entry_byte_size_; }
  uint64_t lfh_key() const { return lfh_key_; }

 private:
  // An address range covering the bin under enumeration.
  refinery::AddressRange bin_range_;
  refinery::TypedData heap_userdata_header_;

  // The byte size of each entry in the bin.
  uint64_t entry_byte_size_;
  // The LFHKey decoded from this bin.
  uint64_t lfh_key_;
  // The heap this bin is associated with, as provided by Initialize.
  refinery::Address heap_;

  DISALLOW_COPY_AND_ASSIGN(LFHBinWalker);
};

#endif  // SYZYGY_EXPERIMENTAL_HEAP_ENUMERATE_HEAP_ENTRY_WALKER_H_
