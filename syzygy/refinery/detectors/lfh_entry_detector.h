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

#ifndef SYZYGY_REFINERY_DETECTORS_LFH_ENTRY_DETECTOR_H_
#define SYZYGY_REFINERY_DETECTORS_LFH_ENTRY_DETECTOR_H_

#include <set>
#include <vector>

#include "base/macros.h"

#include "syzygy/refinery/types/type.h"
#include "syzygy/refinery/types/type_repository.h"
#include "syzygy/refinery/types/typed_data.h"

namespace refinery {

// This class attempts to decode Windows low fragmentation heap (LFH) entries.
// See also LFHBinDetector for more context.
//
// This is done by heuristically searching for a run of equidistant heap
// entries (HEs).
// In an LFH user bin, each entry encodes a pointer to its associated
// Heap SubSegment (HSS). These pointers are obfuscated by XORing them with a
// mask comprised of the HE address (shifted down three), the heap handle
// (which is a pointer to the HEAP structure), and the per-process LFHKey.
//
// When an entry is XORed with (HE>>3), it should yield LFHKey ^ HEAP ^ HSS.
// While the value of this is unknown, all HEs in the same bin should yield
// the same value. So the search conceptually picks a starting point (modulo
// 8 or 16, depending on bitness) and a stride (multiple of 8 or 16 depending
// on bitness), then tries to find matches along the stride.
// The entry distance in a found run is picked by simple majority vote of the
// distances between the heap entries found, which gives the method a little
// bit of resilience to corrupt intermediate entries. A single - or a run - of
// corrupt entries in a run of otherwise valid entries, with distance D will
// manifest as a single vote of k*D against multiple votes for D.
//
// Note that a detection can result in false positives if the contents of
// memory are just so. Because of the way heap entries are obfuscated, this is
// fairly unlikely however.
class LFHEntryDetector {
 public:
  // Details on a discovered run of LFH heap entries. Note that a run of
  // entries may not be contiguous, as the discovery heuristic has a bit of
  // resilience to corrupted entries in a run.
  struct LFHEntryRun {
    // The address of the first and last heap entry in a discovered run of
    // heap entries.
    Address first_entry;
    Address last_entry;

    // The distance between discovered entries in a run.
    size_t entry_distance_bytes;

    // These reflect the strength of the finding, by reporting the number of
    // entry pairs that matched this size, against the total number of entries
    // found. If size_votes == entries_found - 1, then all entries found were
    // equidistant.
    size_t size_votes;
    size_t entries_found;

    // The subsegment code for the voted size.
    uint64_t subsegment_code;
  };
  using LFHEntryRuns = std::vector<LFHEntryRun>;

  LFHEntryDetector();

  // Initialize the detector with @p repo, which needs to contain types
  // associated with the heap used in the process to analyze.
  // @param repo the type repo containing heap types.
  // @param bit_source a bit source for the ranges we'll detect.
  // @returns true on success, when all necessary types are found.
  bool Init(TypeRepository* repo, BitSource* bit_source);

  // Inspects @p range for LFH entry runs, and returns findings in
  // @p found_runs.
  // @param range the range to run detcation agains.
  // @param found_runs returns the heap entry runs detected.
  // @returns true on success.
  // @note A success return doesn't imply that one or more entry runs were
  //     found - check the size of @p found_runs to see whether runs were
  //     found.
  bool Detect(const AddressRange& range, LFHEntryRuns* found_runs);

  // Convenience decoding function.
  static bool GetDecodedLFHEntrySubsegment(const TypedData& lfh_heap_entry,
                                           uint64_t* decoded_subseg);

  // Accessor.
  UserDefinedTypePtr entry_type() const { return entry_type_; }

 private:
  typedef std::set<uint64_t> SubsegmentSet;

  // Scans forward through @p range for a run of entries starting at
  // @p range.start().
  // @param range the address range to search.
  // @param used_subsegments a set of subsegment codes already discovered.
  // @param found_run contains the most recently discovered run on success.
  // @returns true if a run of two or more entries with a new subsegment
  //    code is found.
  bool ScanForEntryMatch(const AddressRange& range,
                         SubsegmentSet* used_subsegments,
                         LFHEntryRun* found_run);

  // Valid from Init().
  BitSource* bit_source_;
  UserDefinedTypePtr entry_type_;

  DISALLOW_COPY_AND_ASSIGN(LFHEntryDetector);
};

}  // namespace refinery

#endif  // SYZYGY_REFINERY_DETECTORS_LFH_ENTRY_DETECTOR_H_
