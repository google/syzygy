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
                           uint64_t* value) {
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

bool SegmentEntryWalker::Initialize(refinery::BitSource* bit_source,
                                    const refinery::TypedData& heap,
                                    const refinery::TypedData& segment) {
  if (!HeapEntryWalker::Initialize(bit_source))
    return false;

  // Retrieve the EncodeFlagMask and the Encoding fields from the heap.
  refinery::TypedData encode_flag_mask;
  refinery::TypedData encoding;
  bool has_flags = heap.GetNamedField(L"EncodeFlagMask", &encode_flag_mask);
  bool has_encoding = heap.GetNamedField(L"Encoding", &encoding);
  if (has_flags != has_encoding) {
    LOG(ERROR) << "Strangeness in types: "
               << "only one of Encoding and EncodeFlagMask present!";
    return false;
  }

  // Check the EncodeFlagMask, and store Encoding if appropriate. This is used
  // to XOR all _HEAP_ENTRY fields in the heap.
  if (has_flags) {
    uint64_t value = 0;
    if (!encode_flag_mask.GetUnsignedValue(&value)) {
      LOG(ERROR) << "Unable to get heap flags mask.";
      return false;
    }
    // From observation of some heaps.
    const uint64_t kEncodingEnabled = 0x00100000;
    if (value & kEncodingEnabled) {
      encoding_.resize(encoding.type()->size());
      if (!heap_bit_source_->GetAll(encoding.GetRange(), &encoding_.at(0)))
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

bool SegmentEntryWalker::Next() {
  HeapEntry decoded = {};
  if (!GetDecodedEntry(&decoded))
    return false;

  return curr_entry_.OffsetAndCast(decoded.size, curr_entry_.type(),
                                   &curr_entry_);
}

LFHBinWalker::LFHBinWalker() : entry_byte_size_(0), heap_(0) {
}

bool LFHBinWalker::Initialize(
    refinery::Address heap,
    refinery::BitSource* bit_source,
    refinery::UserDefinedTypePtr heap_userdata_header_type,
    SegmentEntryWalker* walker) {
  DCHECK(bit_source);
  DCHECK(walker);

  heap_ = heap;

  if (!HeapEntryWalker::Initialize(bit_source))
    return false;

  refinery::AddressRange entry_range = walker->curr_entry().GetRange();
  // Get then entry preceding the bin.
  SegmentEntryWalker::HeapEntry entry = {};
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

  // Dereference the heap subsegment. This contains the size, entry count
  // and other information on this bin.
  refinery::TypedData subsegment;
  refinery::TypedData heap_subsegment;
  if (!heap_userdata_header_.GetNamedField(L"SubSegment", &subsegment) ||
      !subsegment.Dereference(&heap_subsegment)) {
    return false;
  }

  // TODO(siggi): The UserBlocks pointer should point back to the
  //     _HEAP_USERDATA_HEADER in the bin - validate this.
  uint64_t block_size = 0;
  if (!GetNamedValueUnsigned(heap_subsegment, L"BlockSize", &block_size))
    return false;

  // Compute the entry byte size.
  entry_byte_size_ = block_size * walker->curr_entry().type()->size();

  if (!heap_userdata_header_.OffsetAndCast(1, walker->curr_entry().type(),
                                           &curr_entry_)) {
    return false;
  }

  // Get the obfuscated subsegment pointer from the first entry in the bin.
  uint64_t subsegment_code = 0;
  if (!GetNamedValueUnsigned(curr_entry_, L"SubSegmentCode", &subsegment_code))
    return false;

  // The subsegment_code is
  // XOR(LFHKey, subsegment_code, self addr >> 3, heap_subsegment).
  // By XORing out all the others, we're left with the LFH key.
  lfh_key_ = subsegment_code;
  lfh_key_ ^= heap_;
  lfh_key_ ^= (curr_entry_.addr() >> 3);
  lfh_key_ ^= heap_subsegment.addr();

  return true;
}

bool LFHBinWalker::GetDecodedEntry(LFHEntry* entry) {
  DCHECK(entry);

  LFHEntry tmp = {};
  if (sizeof(tmp) != curr_entry_.type()->size())
    return false;

  if (!curr_entry_.bit_source()->GetAll(curr_entry_.GetRange(), &tmp))
    return false;

  // XOR the LFHKey, self address and heap in to de-obfuscate the subseg field.
  tmp.heap_subsegment ^= lfh_key_;
  tmp.heap_subsegment ^= curr_entry_.addr() >> 3;
  tmp.heap_subsegment ^= heap_;

  *entry = tmp;
  return true;
}

bool LFHBinWalker::Next() {
  curr_entry_ =
      refinery::TypedData(curr_entry_.bit_source(), curr_entry_.type(),
                          curr_entry_.addr() + entry_byte_size_);
  return true;
}

bool LFHBinWalker::AtEnd() const {
  if (curr_entry_.GetRange().end() >= bin_range_.end())
    return true;

  return false;
}
