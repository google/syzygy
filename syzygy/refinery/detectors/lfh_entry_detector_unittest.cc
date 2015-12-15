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

#include <vector>

#include "gtest/gtest.h"
#include "syzygy/refinery/unittest_util.h"
#include "syzygy/refinery/detectors/unittest_util.h"

namespace refinery {

namespace {

class LFHEntryDetectorTest : public testing::LFHDetectorTest {
 protected:
  // TODO(siggi): This code is 32 bit heap specific - amend this for 64 bit
  //     heap support.
  void ResetTestData(size_t byte_size) {
    // Set with 0x80 as that signals "lfh entry" at certain byte positions.
    test_data_.assign(byte_size, 0x80);
  }

  void WriteSubseg(size_t byte_offset, uintptr_t subseg_code) {
    ASSERT_LT(byte_offset + sizeof(subseg_code), test_data_.size());
    void* dst_addr = &test_data_.at(byte_offset);
    subseg_code ^= (testing::ToAddress(dst_addr) >> 3);

    ::memcpy(dst_addr, &subseg_code, sizeof(subseg_code));
  }

  void DetectTestData(LFHEntryDetector::LFHEntryRuns* found_runs) {
    ASSERT_TRUE(found_runs);

    LFHEntryDetector detector;
    ASSERT_TRUE(detector.Init(repo().get(), bit_source()));
    ASSERT_TRUE(detector.Detect(
        AddressRange(testing::ToAddress(&test_data_.at(0)), test_data_.size()),
        found_runs));
  }

 private:
  std::vector<uint8_t> test_data_;
};

}  // namespace

TEST_F(LFHEntryDetectorTest, InitSuccess) {
  LFHEntryDetector detector;

  ASSERT_TRUE(detector.Init(repo().get(), bit_source()));
  ASSERT_TRUE(detector.entry_type());
}

TEST_F(LFHEntryDetectorTest, FailsOnEmptyTypeRepo) {
  LFHEntryDetector detector;

  scoped_refptr<TypeRepository> empty_type_repo = new TypeRepository;
  ASSERT_FALSE(detector.Init(empty_type_repo.get(), bit_source()));
  ASSERT_FALSE(detector.entry_type());
}

TEST_F(LFHEntryDetectorTest, Detect) {
  if (testing::IsAppVerifierActive()) {
    LOG(WARNING) << "LFHEntryDetectorTest.Detect is incompatible with AV.";
    return;
  }

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
    ASSERT_NE(0U, found_run.size_votes);
    ASSERT_GT(found_run.entries_found, found_run.size_votes);

    // Technically it's possible for the subsegment mask to be zero, but this
    // at least tests that it's set with a 1/2^32 odds of flaking.
    ASSERT_NE(0ULL, found_run.subsegment_code);

    const size_t kEntrySize = 8;
    if (found_run.entry_distance_bytes > kBlockSize + kEntrySize)
      suitable_size_found = true;

    AddressRange found_span(found_run.first_entry,
                            found_run.last_entry - found_run.first_entry);
    ASSERT_TRUE(found_span.IsValid());
    // All found spans should be contained within the range we constrain the
    // search to.
    ASSERT_TRUE(range.Contains(found_span));
  }

  ASSERT_TRUE(suitable_size_found);
}

TEST_F(LFHEntryDetectorTest, VotingPicksMinimumDistance) {
  // Make some test data.
  ResetTestData(1024);

  const uintptr_t kSubsegCode = 0xCAFEBABE;
  WriteSubseg(16 * 1, kSubsegCode);
  WriteSubseg(16 * 2, kSubsegCode);
  WriteSubseg(16 * 4, kSubsegCode);

  LFHEntryDetector::LFHEntryRuns found_runs;
  ASSERT_NO_FATAL_FAILURE(DetectTestData(&found_runs));

  ASSERT_EQ(1U, found_runs.size());
  EXPECT_EQ(kSubsegCode, found_runs[0].subsegment_code);
  // The smaller size should have been selected.
  EXPECT_EQ(16, found_runs[0].entry_distance_bytes);

  ResetTestData(1024);

  // Now try starting with the larger span.
  WriteSubseg(16 * 1, kSubsegCode);
  WriteSubseg(16 * 3, kSubsegCode);
  WriteSubseg(16 * 4, kSubsegCode);

  ASSERT_NO_FATAL_FAILURE(DetectTestData(&found_runs));
  ASSERT_EQ(1U, found_runs.size());
  EXPECT_EQ(kSubsegCode, found_runs[0].subsegment_code);
  // The smaller size should have been selected.
  EXPECT_EQ(16, found_runs[0].entry_distance_bytes);
}

}  // namespace refinery
