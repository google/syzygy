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

#include "syzygy/refinery/process_state/process_state.h"

#include "base/strings/string_piece.h"
#include "gtest/gtest.h"

namespace refinery {

namespace {

using BytesRecordPtr = ProcessState::Layer<Bytes>::RecordPtr;

void ValidateSingleRecordMatch(
    Address addr,
    Size size,
    const std::vector<BytesRecordPtr>& matching_records,
    base::StringPiece testcase) {
  ASSERT_EQ(1, matching_records.size()) << testcase;
  ASSERT_EQ(addr, matching_records[0]->addr()) << testcase;
  ASSERT_EQ(size, matching_records[0]->size()) << testcase;
}

}  // namespace

TEST(ProcessStateTest, FindOrCreateLayer) {
  ProcessState report;

  scoped_refptr<ProcessState::Layer<Bytes>> bytes_layer;
  EXPECT_FALSE(report.FindLayer(&bytes_layer));
  EXPECT_TRUE(bytes_layer == nullptr);

  scoped_refptr<ProcessState::Layer<TypedBlock>> typed_layer;
  EXPECT_FALSE(report.FindLayer(&typed_layer));

  report.FindOrCreateLayer(&bytes_layer);
  EXPECT_TRUE(bytes_layer != nullptr);

  scoped_refptr<ProcessState::Layer<Bytes>> test_layer;
  EXPECT_TRUE(report.FindLayer(&test_layer));
  EXPECT_EQ(bytes_layer.get(), test_layer.get());

  EXPECT_FALSE(report.FindLayer(&typed_layer));
}

TEST(ProcessStateTest, CreateRecord) {
  ProcessState report;

  scoped_refptr<ProcessState::Layer<Bytes>> bytes_layer;
  report.FindOrCreateLayer(&bytes_layer);
  EXPECT_TRUE(bytes_layer != nullptr);
  ASSERT_EQ(0, bytes_layer->size());

  // Add a record for a range of memory.
  const Address kAddr = 0xCAFEBABEULL;
  const Size kSize = 0xBABE;
  scoped_refptr<ProcessState::Record<Bytes>> first_record;
  bytes_layer->CreateRecord(kAddr, kSize, &first_record);

  ASSERT_EQ(kAddr, first_record->addr());
  ASSERT_EQ(kSize, first_record->size());
  ASSERT_EQ(1, bytes_layer->size());

  // Add a second record for the same range.
  scoped_refptr<ProcessState::Record<Bytes>> second_record;
  bytes_layer->CreateRecord(kAddr, kSize, &second_record);

  ASSERT_EQ(kAddr, second_record->addr());
  ASSERT_EQ(kSize, second_record->size());
  ASSERT_EQ(2, bytes_layer->size());

  // Verify that this produced two distinct objects.
  ASSERT_NE(first_record.get(), second_record.get());
}

TEST(ProcessStateTest, GetRecordsSpanningSingleRecord) {
  using BytesLayerPtr = scoped_refptr<ProcessState::Layer<Bytes>>;
  using BytesRecordPtr = ProcessState::Layer<Bytes>::RecordPtr;

  // Create a report with a Bytes layer.
  ProcessState report;
  BytesLayerPtr bytes_layer;
  report.FindOrCreateLayer(&bytes_layer);
  EXPECT_TRUE(bytes_layer != nullptr);
  ASSERT_EQ(0, bytes_layer->size());

  // Add a single record for basic testing.
  const Address kAddress = 80ULL;
  const Size kSize = 16U;
  BytesRecordPtr record;
  bytes_layer->CreateRecord(kAddress, kSize, &record);

  // No match: requested region is outside.
  std::vector<BytesRecordPtr> matching_records;
  bytes_layer->GetRecordsSpanning(73ULL, 5U, &matching_records);
  ASSERT_EQ(0, matching_records.size());
  bytes_layer->GetRecordsSpanning(96ULL, 3U, &matching_records);
  ASSERT_EQ(0, matching_records.size());

  // No match: requested region straddles.
  bytes_layer->GetRecordsSpanning(75ULL, 10ULL, &matching_records);
  ASSERT_EQ(0, matching_records.size());

  // No match: requested region is a superset.
  bytes_layer->GetRecordsSpanning(75ULL, 32ULL, &matching_records);
  ASSERT_EQ(0, matching_records.size());

  // Match: requested region is a subset.
  bytes_layer->GetRecordsSpanning(84ULL, 4ULL, &matching_records);
  ValidateSingleRecordMatch(kAddress, kSize, matching_records,
                            "Case: Requested region is a subset");
  matching_records.clear();

  // Match: region is exact match.
  bytes_layer->GetRecordsSpanning(kAddress, kSize, &matching_records);
  ValidateSingleRecordMatch(kAddress, kSize, matching_records,
                            "Case: Requested region is exact match");
}

TEST(ProcessStateTest, GetRecordsSpanningMultipleRecords) {
  using BytesLayerPtr = scoped_refptr<ProcessState::Layer<Bytes>>;
  using BytesRecordPtr = ProcessState::Layer<Bytes>::RecordPtr;

  // Create a report with a Bytes layer.
  ProcessState report;
  BytesLayerPtr bytes_layer;
  report.FindOrCreateLayer(&bytes_layer);
  ASSERT_TRUE(bytes_layer != nullptr);

  // Add a few records.
  BytesRecordPtr record;
  bytes_layer->CreateRecord(80ULL, 16U, &record);
  bytes_layer->CreateRecord(75ULL, 25U, &record);
  bytes_layer->CreateRecord(80ULL, 16U, &record);  // Second record at location.

  // Match a subset.
  std::vector<BytesRecordPtr> matching_records;
  bytes_layer->GetRecordsSpanning(82ULL, 4U, &matching_records);
  ASSERT_EQ(3, matching_records.size());
}

TEST(ProcessStateTest, GetRecordsIntersectingSingleRecord) {
  using BytesLayerPtr = scoped_refptr<ProcessState::Layer<Bytes>>;
  using BytesRecordPtr = ProcessState::Layer<Bytes>::RecordPtr;

  // Create a report with a Bytes layer.
  ProcessState report;
  BytesLayerPtr bytes_layer;
  report.FindOrCreateLayer(&bytes_layer);
  EXPECT_TRUE(bytes_layer != nullptr);
  ASSERT_EQ(0, bytes_layer->size());

  // Add a single record for basic testing.
  const Address kAddress = 80ULL;
  const Size kSize = 16U;
  BytesRecordPtr record;
  bytes_layer->CreateRecord(kAddress, kSize, &record);

  // No match: requested region is outside.
  std::vector<BytesRecordPtr> matching_records;
  bytes_layer->GetRecordsIntersecting(73ULL, 5U, &matching_records);
  ASSERT_EQ(0, matching_records.size());
  bytes_layer->GetRecordsIntersecting(96ULL, 3U, &matching_records);
  ASSERT_EQ(0, matching_records.size());

  // No match: requested region is contiguous.
  bytes_layer->GetRecordsIntersecting(75ULL, 5U, &matching_records);
  ASSERT_EQ(0, matching_records.size());
  bytes_layer->GetRecordsIntersecting(96ULL, 3U, &matching_records);
  ASSERT_EQ(0, matching_records.size());

  // Match: requested region straddles.
  bytes_layer->GetRecordsIntersecting(75ULL, 10ULL, &matching_records);
  ValidateSingleRecordMatch(kAddress, kSize, matching_records,
                            "Case: Requested region straddles");
  matching_records.clear();

  // Match: requested region is a superset.
  bytes_layer->GetRecordsIntersecting(75ULL, 32ULL, &matching_records);
  ValidateSingleRecordMatch(kAddress, kSize, matching_records,
                            "Case: Requested region is a superset");
  matching_records.clear();

  // Match: requested region is a subset.
  bytes_layer->GetRecordsIntersecting(84ULL, 4ULL, &matching_records);
  ValidateSingleRecordMatch(kAddress, kSize, matching_records,
                            "Case: Requested region is a subset");
  matching_records.clear();

  // Match: region is exact match.
  bytes_layer->GetRecordsIntersecting(kAddress, kSize, &matching_records);
  ValidateSingleRecordMatch(kAddress, kSize, matching_records,
                            "Case: Requested region is an exact match");
  matching_records.clear();
}

TEST(ProcessStateTest, GetRecordsIntersectingMultipleRecords) {
  using BytesLayerPtr = scoped_refptr<ProcessState::Layer<Bytes>>;
  using BytesRecordPtr = ProcessState::Layer<Bytes>::RecordPtr;

  // Create a report with a Bytes layer.
  ProcessState report;
  BytesLayerPtr bytes_layer;
  report.FindOrCreateLayer(&bytes_layer);
  ASSERT_TRUE(bytes_layer != nullptr);

  // Add a few records.
  BytesRecordPtr record;
  bytes_layer->CreateRecord(80ULL, 16U, &record);
  bytes_layer->CreateRecord(75ULL, 25U, &record);
  bytes_layer->CreateRecord(80ULL, 16U, &record);  // Second record at location.

  // Match a subset straddling region.
  std::vector<BytesRecordPtr> matching_records;
  bytes_layer->GetRecordsIntersecting(78ULL, 4U, &matching_records);
  ASSERT_EQ(3, matching_records.size());
}

TEST(ProcessStateTest, RemoveRecord) {
  using BytesLayerPtr = scoped_refptr<ProcessState::Layer<Bytes>>;
  using BytesRecordPtr = ProcessState::Layer<Bytes>::RecordPtr;

  // Create a report that has a Bytes layer with a single record.
  ProcessState report;
  BytesLayerPtr bytes_layer;
  report.FindOrCreateLayer(&bytes_layer);
  ASSERT_TRUE(bytes_layer != nullptr);

  const Address kAddress = 80ULL;
  const Size kSize = 16U;
  BytesRecordPtr record;
  bytes_layer->CreateRecord(kAddress, kSize, &record);
  ASSERT_EQ(1, bytes_layer->size());

  // Remove record.
  ASSERT_TRUE(bytes_layer->RemoveRecord(record));
  ASSERT_EQ(0, bytes_layer->size());

  // Removing a second time fails.
  ASSERT_FALSE(bytes_layer->RemoveRecord(record));
}

TEST(ProcessStateTest, LayerIteration) {
  using BytesLayerPtr = scoped_refptr<ProcessState::Layer<Bytes>>;
  using BytesRecordPtr = ProcessState::Layer<Bytes>::RecordPtr;

  // Create a report that has a Bytes layer with few records.
  ProcessState report;
  BytesLayerPtr bytes_layer;
  report.FindOrCreateLayer(&bytes_layer);
  ASSERT_TRUE(bytes_layer != nullptr);

  BytesRecordPtr record;
  bytes_layer->CreateRecord(80ULL, 4U, &record);
  bytes_layer->CreateRecord(84ULL, 4U, &record);
  bytes_layer->CreateRecord(88ULL, 4U, &record);

  // Manual iteration.
  // Note: for ease of testing, this test relies on the iterator returning
  // records by ascending address. However, this is not in the contract.
  ProcessState::Layer<Bytes>::Iterator it = bytes_layer->begin();
  ASSERT_EQ(80ULL, (*it)->addr());
  ++it;
  ASSERT_EQ(84ULL, (*it)->addr());
  ++it;
  ASSERT_EQ(88ULL, (*it)->addr());
  ++it;
  ASSERT_EQ(bytes_layer->end(), it);

  // Range based for loop.
  int record_count = 0;
  for (BytesRecordPtr rec : *bytes_layer) {
    ++record_count;
  }
  ASSERT_EQ(3, record_count);
}

}  // namespace refinery
