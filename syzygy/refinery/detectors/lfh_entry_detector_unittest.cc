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

#include "gtest/gtest.h"
#include "syzygy/refinery/detectors/unittest_util.h"

namespace refinery {

namespace {

class LFHEntryDetectorTest : public testing::LFHDetectorTest {};

}  // namespace

TEST_F(LFHEntryDetectorTest, Create) {
  LFHEntryDetector detector;

  ASSERT_TRUE(detector.Init(repo().get(), bit_source()));
}

TEST_F(LFHEntryDetectorTest, Detect) {
  LFHEntryDetector detector;

  ASSERT_TRUE(detector.Init(repo().get(), bit_source()));

  const size_t kBlockSize = 17;
  // Allocate blocks until we get an LFH bucket.
  Address bucket = AllocateLFHBucket(kBlockSize);
  if (bucket == 0) {
    LOG(ERROR) << "Couldn't find an LFH bucket - is AppVerifier enabled?";
    return;
  }

  // Form a range covering the LFH bucket start and perform detection on it.
  AddressRange range(bucket - 256, 1024);
  LFHEntryDetector::LFHEntryRuns found_runs;
  ASSERT_TRUE(detector.Detect(range, &found_runs));

  ASSERT_LE(1, found_runs.size());

  bool suitable_size_found = false;
  for (const auto& found_run : found_runs) {
    ASSERT_NE(0U, found_run.entries_found);
    ASSERT_LE(found_run.entry_distance_bytes * (found_run.entries_found - 1),
              found_run.last_entry - found_run.first_entry);
    ASSERT_LT(1, found_run.size_votes);
    ASSERT_GT(found_run.entries_found, found_run.size_votes);

    const size_t kEntrySize = 8;
    if (found_run.entry_distance_bytes > kBlockSize + kEntrySize)
      suitable_size_found = true;

    AddressRange found_span(found_run.first_entry,
                            found_run.last_entry - found_run.first_entry);
    ASSERT_TRUE(found_span.IsValid());
    // All found spans should be contained within the range we constrain the
    // search to.
    ASSERT_TRUE(range.Spans(found_span));
  }

  ASSERT_TRUE(suitable_size_found);
}

}  // namespace refinery
