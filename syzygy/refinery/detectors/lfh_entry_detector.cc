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

#include "syzygy/refinery/detectors/lfh_entry_detector.h"

#include "base/logging.h"
#include "base/containers/hash_tables.h"
#include "syzygy/common/align.h"
#include "syzygy/refinery/types/typed_data.h"

namespace refinery {

LFHEntryDetector::LFHEntryDetector() : bit_source_(nullptr) {
}

bool LFHEntryDetector::Init(TypeRepository* repo, BitSource* bit_source) {
  DCHECK(repo);
  DCHECK(bit_source);
  DCHECK(bit_source_ == nullptr);

  for (auto type : *repo) {
    if (type->GetName() == L"_HEAP_ENTRY") {
      if (!type->CastTo(&entry_type_))
        return false;
      break;
    }
  }

  if (!entry_type_)
    return false;

  bit_source_ = bit_source;

  return true;
}

bool LFHEntryDetector::Detect(const AddressRange& range,
                              LFHEntryRuns* found_runs) {
  DCHECK(range.IsValid());
  DCHECK(found_runs);
  DCHECK(bit_source_);
  DCHECK(entry_type_);

  found_runs->clear();

  // This will be 8 or 16 depending on bitness.
  // TODO(siggi): Fix this code for 64 bit.
  const size_t kEntrySize = entry_type_->size();
  const Address start = common::AlignUp(range.start(), kEntrySize);
  const Address end =
      common::AlignDown(range.end() - entry_type_->size(), kEntrySize);
  DCHECK_EQ(0, (end - start) % kEntrySize);

  // TODO(siggi): This is ~O(N^2) and so is wasteful for large ranges.
  //     A better approach might be to process the entire range, count up all
  //     the subsegment codes that occur, with the first occurrence of each.
  //     This will then allow processing the range in closer to O(N), as a
  //     search will only be done where a code occurs more than once, and then
  //     from the first occurrence of that code.
  SubsegmentSet used_subsegments;
  for (Address curr = start; curr < end; curr += kEntrySize) {
    LFHEntryRun found_run;

    if (ScanForEntryMatch(AddressRange(curr, end - curr), &used_subsegments,
                          &found_run)) {
      found_runs->push_back(found_run);
    }
  }

  return true;
}

bool LFHEntryDetector::GetDecodedLFHEntrySubsegment(
    const TypedData& lfh_heap_entry,
    uint64_t* decoded_subseg) {
  TypedData subseg_field;
  if (!lfh_heap_entry.GetNamedField(L"SubSegmentCode", &subseg_field)) {
    VLOG(1) << "Getting LFHEntry SubSegmentCode field failed.";
    return false;
  }
  uint64_t entry_subseg = 0;
  if (!subseg_field.GetUnsignedValue(&entry_subseg)) {
    VLOG(1) << "Getting LFHEntry SubSegmentCode value failed.";
    return false;
  }
  // Back out the XORed address of the entry itself.
  *decoded_subseg = entry_subseg ^ (lfh_heap_entry.addr() >> 3);

  return true;
}

bool LFHEntryDetector::ScanForEntryMatch(const AddressRange& range,
                                         SubsegmentSet* used_subsegments,
                                         LFHEntryRun* found_run) {
  DCHECK(range.IsValid());
  DCHECK(found_run);
  DCHECK(used_subsegments);
  DCHECK(bit_source_);
  DCHECK(entry_type_);

  // Cast the start of the range to a HEAP_ENTRY.
  TypedData lfh_heap_entry(bit_source_, entry_type_, range.start());
  uint64_t subseg = 0;
  if (!GetDecodedLFHEntrySubsegment(lfh_heap_entry, &subseg)) {
    VLOG(1) << "Failed to get subsegment from base entry.";
    return false;
  }

  // See whether we've already discovered this subsegment.
  if (used_subsegments->find(subseg) != used_subsegments->end())
    return false;

  // Validate the entry to the extent possible at this point.
  TypedData extended_block_signature_field;
  if (!lfh_heap_entry.GetNamedField(L"ExtendedBlockSignature",
                                    &extended_block_signature_field)) {
    LOG(ERROR) << "No ExtendedBlockSignature field in entry.";
    return false;
  }

  uint64_t extended_block_signature = 0;
  if (!extended_block_signature_field.GetUnsignedValue(
          &extended_block_signature)) {
    VLOG(1) << "Failed to get extended_block_signature from base entry.";
    return false;
  }

  // Check that the LFH flag is set on the entry.
  const uint16_t kLFHBlockFlag = 0x80;
  if ((extended_block_signature & kLFHBlockFlag) == 0)
    return false;

  // Check that the rest of the entry is sane. Free blocks have the remaining
  // bits set, whereas used blocks use the remaining bits to encode the number
  // of unused bytes in the block, plus 8.
  const uint16_t kLFHUnusedBytesMask = 0x7F;
  if ((extended_block_signature & kLFHUnusedBytesMask) != 0 &&
      (extended_block_signature & kLFHUnusedBytesMask) < 8) {
    return false;
  }

  // Now that the entry has passed initial validation, record that we're
  // processing this subsegment value.
  used_subsegments->insert(subseg);

  // The distance histogram is used to pick an entry size by simple majority
  // vote. This yields some resilience to corruption and false positive
  // matches.
  using DistanceHistogram = std::unordered_map<size_t, size_t>;
  DistanceHistogram distances;
  Address last_match = range.start();

  // Bound the search to the size of the range we're given.
  size_t end = range.size() / lfh_heap_entry.type()->size();
  for (size_t i = 2; i < end; ++i) {
    // Walk forward to the next candidate.
    TypedData candidate;
    if (!lfh_heap_entry.OffsetAndCast(i, lfh_heap_entry.type(), &candidate))
      break;

    uint64_t candidate_subseg = 0;
    if (!GetDecodedLFHEntrySubsegment(candidate, &candidate_subseg))
      break;

    // TODO(siggi): It may make sense to validate the entries to cut down on
    //     false positives.
    if (subseg == candidate_subseg) {
      const size_t kDistance = candidate.addr() - last_match;
      last_match = candidate.addr();

      // Record the distance from the last match.
      ++distances[kDistance];
    }
  }

  if (distances.size() == 0)
    return false;

  size_t voted_size = 0;
  size_t voted_count = 0;
  size_t num_votes = 0;
  for (const auto& entry : distances) {
    const auto& size = entry.first;
    const auto& count = entry.second;
    // Voting count ties are broken by the lowest size, as corruption in a run
    // of entries of size D will show as kD.
    if (count > voted_count || (count == voted_count && size < voted_size)) {
      voted_size = size;
      voted_count = count;
    }
    num_votes += count;
  }

  // Record the found run.
  found_run->first_entry = range.start();
  found_run->last_entry = last_match;
  found_run->entry_distance_bytes = voted_size;
  found_run->size_votes = voted_count;
  found_run->entries_found = num_votes + 1;
  found_run->subsegment_code = subseg;

  return true;
}

}  // namespace refinery
