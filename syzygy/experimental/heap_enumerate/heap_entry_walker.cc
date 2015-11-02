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

#include "syzygy/experimental/heap_enumerate/heap_entry_walker.h"

namespace {

// XORs a memory range into another memory range.
void memxor(void* dst, const void* src, size_t num_bytes) {
  uint8_t* dst_ptr = reinterpret_cast<uint8_t*>(dst);
  const uint8_t* src_ptr = reinterpret_cast<const uint8_t*>(src);

  for (size_t i = 0; i < num_bytes; ++i)
    *dst_ptr++ ^= *src_ptr++;
}

bool GetNamedValueUnsigned(const refinery::TypedData& data,
                           base::StringPiece16 field_name,
                           uint64* value) {
  DCHECK(value);
  refinery::TypedData field;
  if (!data.GetNamedField(field_name, &field) ||
      !field.GetUnsignedValue(value)) {
    return false;
  }

  return true;
}

}  // namespace

HeapEntryWalker::HeapEntryWalker() : heap_bit_source_(nullptr) {
}

bool HeapEntryWalker::Initialize(refinery::BitSource* bit_source) {
  heap_bit_source_ = bit_source;

  return true;
}

bool HeapEntryWalker::Next() {
  HeapEntry decoded = {};
  if (!GetDecodedEntry(&decoded))
    return false;

  return curr_entry_.OffsetAndCast(decoded.size, curr_entry_.type(),
                                   &curr_entry_);
}

bool SegmentEntryWalker::Initialize(const refinery::TypedData& heap,
                                    const refinery::TypedData& segment) {
  if (!HeapEntryWalker::Initialize(heap.bit_source()))
    return false;

  refinery::TypedData encode_flag_mask;
  refinery::TypedData encoding;
  bool has_flags = heap.GetNamedField(L"EncodeFlagMask", &encode_flag_mask);
  bool has_encoding = heap.GetNamedField(L"Encoding", &encoding);
  if (has_flags != has_encoding) {
    LOG(ERROR) << "Strangeness in types: "
               << "only one of Encoding and EncodeFlagMask present!";
    return false;
  }

  if (has_flags) {
    uint64 value = 0;
    if (!encode_flag_mask.GetUnsignedValue(&value)) {
      LOG(ERROR) << "Unable to get heap flags mask.";
      return false;
    }
    // From observation of some heaps.
    const uint64 kEncodingEnabled = 0x00100000;
    if (value & kEncodingEnabled) {
      refinery::BitSource* source = encoding.bit_source();
      encoding_.resize(encoding.type()->size());
      if (!source->GetAll(encoding.GetRange(), &encoding_.at(0)))
        return false;
    }
  }

  // Get the first entry.
  if (!segment.GetNamedField(L"Entry", &curr_entry_))
    return false;

  // Get the end address of the mapped part of the segment.
  uint64_t last_valid_entry = 0;
  if (!GetNamedValueUnsigned(segment, L"LastValidEntry", &last_valid_entry))
    return false;

  // Note that the segment can be discontiguous if it contains any uncommitted
  // ranges. Uncommitted ranges are stored as a list of whole pages with
  // _HEAP_UCR_DESCRIPTOR structures.
  segment_range_ = refinery::AddressRange(
      segment.addr(), refinery::Address(last_valid_entry) - segment.addr());

  return true;
}

bool SegmentEntryWalker::GetDecodedEntry(HeapEntry* entry) {
  DCHECK(entry);
  HeapEntry tmp = {};

  // Bail if the current entry is for some reason not of the right size.
  if (curr_entry_.type()->size() != sizeof(tmp))
    return false;

  // Get the raw entry.
  if (!heap_bit_source_->GetAll(curr_entry_.GetRange(), &tmp))
    return false;

  // Unencode it.
  if (encoding_.size() == sizeof(tmp))
    memxor(&tmp, &encoding_.at(0), sizeof(tmp));

  *entry = tmp;

  return true;
}

bool SegmentEntryWalker::AtEnd() const {
  if (curr_entry_.addr() + curr_entry_.type()->size() >= segment_range_.end())
    return true;

  return false;
}

bool LFHBinEntryWalker::Initialize(
    refinery::BitSource* bit_source,
    refinery::UserDefinedTypePtr heap_userdata_header_type,
    SegmentEntryWalker* walker) {
  DCHECK(bit_source);
  DCHECK(walker);

  if (!HeapEntryWalker::Initialize(bit_source))
    return false;

  // TODO(siggi): Acquire the data necessary to decode the entries.
  refinery::AddressRange entry_range = walker->curr_entry().GetRange();

  HeapEntry entry = {};
  if (!walker->GetDecodedEntry(&entry))
    return false;

  bin_range_ = refinery::AddressRange(entry_range.start(),
                                      entry.size * entry_range.size());

  // The bin is comprised of a _HEAP_USERDATA_HEADER, followed by a
  // concatenation of heap entries.
  if (!walker->curr_entry().OffsetAndCast(1, heap_userdata_header_type,
                                          &heap_userdata_header_)) {
    return false;
  }

  // TODO(siggi): This is an awkard way to acquire this type.
  if (!heap_userdata_header_.OffsetAndCast(1, walker->curr_entry().type(),
                                           &curr_entry_)) {
    return false;
  }

  return true;
}

bool LFHBinEntryWalker::GetDecodedEntry(HeapEntry* entry) {
  // TODO(siggi): writeme.
  return false;
}

bool LFHBinEntryWalker::AtEnd() const {
  if (curr_entry_.GetRange().end() >= bin_range_.end())
    return true;

  return false;
}
