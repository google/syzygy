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

#include <limits>
#include <memory>
#include <string>

#include "base/strings/string_piece.h"
#include "gtest/gtest.h"
#include "syzygy/refinery/process_state/process_state_util.h"
#include "syzygy/refinery/process_state/refinery.pb.h"

namespace refinery {

namespace {

void ValidateSingleRecordMatch(
    AddressRange range,
    const std::vector<BytesRecordPtr>& matching_records,
    base::StringPiece testcase) {
  ASSERT_EQ(1, matching_records.size()) << testcase;
  ASSERT_EQ(range, matching_records[0]->range()) << testcase;
}

// Adds a stack record to a process state.
void AddStackRecord(const AddressRange& range,
                    const size_t thread_id,
                    ProcessState* process_state,
                    StackRecordPtr* stack_record) {
  StackLayerPtr stack_layer;
  process_state->FindOrCreateLayer(&stack_layer);
  stack_layer->CreateRecord(range, stack_record);
  (*stack_record)
      ->mutable_data()
      ->mutable_thread_info()
      ->set_thread_id(thread_id);
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

TEST(ProcessStateTest, FindSingleRecord) {
  const size_t kThreadId = 42;
  const AddressRange kRecordAddressRange(80ULL, 10U);
  ProcessState report;
  StackRecordPtr retrieved;

  // Empty report: returns false.
  ASSERT_FALSE(report.FindSingleRecord(84ULL, &retrieved));

  // Add a stack record to the report.
  StackRecordPtr created;
  AddStackRecord(kRecordAddressRange, kThreadId, &report, &created);

  // Search for address outside record's range.
  ASSERT_FALSE(report.FindSingleRecord(79ULL, &retrieved));
  ASSERT_FALSE(report.FindSingleRecord(90ULL, &retrieved));

  // Search for address within record's range.
  ASSERT_TRUE(report.FindSingleRecord(84ULL, &retrieved));
  ASSERT_EQ(created.get(), retrieved.get());
}

TEST(ProcessStateTest, FindStackRecord) {
  const size_t kThreadId = 42;
  ProcessState report;
  StackRecordPtr retrieved;

  // Report doesn't have a stack layer.
  ASSERT_FALSE(report.FindStackRecord(kThreadId, &retrieved));

  // Report has an empty stack layer.
  StackLayerPtr stack_layer;
  report.FindOrCreateLayer(&stack_layer);
  ASSERT_FALSE(report.FindStackRecord(kThreadId, &retrieved));

  // Add a stack record to the report.
  StackRecordPtr created;
  AddStackRecord(AddressRange(8000ULL, 80U), kThreadId, &report, &created);

  // Search for a non-existing thread id.
  ASSERT_FALSE(report.FindStackRecord(kThreadId + 1, &retrieved));

  // Search for the existing thread id.
  ASSERT_TRUE(report.FindStackRecord(kThreadId, &retrieved));
  ASSERT_EQ(created.get(), retrieved.get());
}

TEST(ProcessStateTest, ExceptionBasics) {
  const int kExceptingThreadId = 1;
  const int kExceptionCode = 2;
  Exception exception;
  exception.set_thread_id(kExceptingThreadId);
  exception.set_exception_code(kExceptionCode);

  ProcessState state;
  size_t retrieved_thread_id = 0;

  // Retrieving excepting thread id on an empty state fails.
  ASSERT_FALSE(state.GetExceptingThreadId(&retrieved_thread_id));
  retrieved_thread_id = 0;

  // Setting an exception fails when thread isn't in the state.
  ASSERT_FALSE(state.SetException(exception));

  // Add a stack record to the report.
  StackRecordPtr stack_record;
  AddStackRecord(AddressRange(8000ULL, 80U), kExceptingThreadId, &state,
                 &stack_record);

  // Setting an exception succeeds.
  ASSERT_TRUE(state.SetException(exception));
  ASSERT_TRUE(stack_record->data().thread_info().has_exception());
  const Exception& retrieved_exception =
      stack_record->data().thread_info().exception();
  ASSERT_EQ(kExceptingThreadId, retrieved_exception.thread_id());
  ASSERT_EQ(kExceptionCode, retrieved_exception.exception_code());

  // Retrieving the excepting thread id succeeds.
  ASSERT_TRUE(state.GetExceptingThreadId(&retrieved_thread_id));
  ASSERT_EQ(kExceptingThreadId, retrieved_thread_id);

  // Setting a second exception fails.
  ASSERT_FALSE(state.SetException(exception));
}

TEST(ProcessStateTest, AddressRangeBasics) {
  const Address kAddr = 0xCAFE0000ULL;
  const Size kSize = 0xBABEU;

  AddressRange valid_range(kAddr, kSize);
  ASSERT_TRUE(valid_range.IsValid());
  ASSERT_EQ(kAddr, valid_range.start());
  ASSERT_EQ(kSize, valid_range.size());
  ASSERT_EQ(kAddr, valid_range.start());
  ASSERT_EQ(kAddr, valid_range.start());
  ASSERT_EQ(0xCAFEBABEULL, valid_range.end());

  AddressRange zero_range(kAddr, 0U);
  ASSERT_FALSE(zero_range.IsValid());

  AddressRange overflow_range(std::numeric_limits<Address>::max(), 1U);
  ASSERT_FALSE(overflow_range.IsValid());
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
  bytes_layer->CreateRecord(AddressRange(kAddr, kSize), &first_record);

  ASSERT_EQ(AddressRange(kAddr, kSize), first_record->range());
  ASSERT_EQ(1, bytes_layer->size());

  // Add a second record for the same range.
  scoped_refptr<ProcessState::Record<Bytes>> second_record;
  bytes_layer->CreateRecord(AddressRange(kAddr, kSize), &second_record);

  ASSERT_EQ(AddressRange(kAddr, kSize), second_record->range());
  ASSERT_EQ(2, bytes_layer->size());

  // Verify that this produced two distinct objects.
  ASSERT_NE(first_record.get(), second_record.get());
}

TEST(ProcessStateTest, GetRecordsAt) {
  // Create a report with a Bytes layer.
  ProcessState report;
  BytesLayerPtr bytes_layer;
  report.FindOrCreateLayer(&bytes_layer);
  EXPECT_TRUE(bytes_layer != nullptr);
  ASSERT_EQ(0, bytes_layer->size());

  // Add a single record for basic testing.
  BytesRecordPtr record;
  bytes_layer->CreateRecord(AddressRange(80ULL, 16U), &record);

  // Get right before and right after - no match.
  std::vector<BytesRecordPtr> matching_records;
  bytes_layer->GetRecordsAt(79ULL, &matching_records);
  ASSERT_EQ(0, matching_records.size());
  bytes_layer->GetRecordsAt(81ULL, &matching_records);
  ASSERT_EQ(0, matching_records.size());

  // Match.
  bytes_layer->GetRecordsAt(80ULL, &matching_records);
  ASSERT_EQ(1, matching_records.size());
  ASSERT_EQ(record.get(), matching_records[0].get());

  // Add a second record. Match both.
  matching_records.clear();
  bytes_layer->CreateRecord(AddressRange(80ULL, 4U), &record);
  bytes_layer->GetRecordsAt(80ULL, &matching_records);
  ASSERT_EQ(2, matching_records.size());
}

TEST(ProcessStateTest, GetRecordsSpanningSingleRecord) {
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
  bytes_layer->CreateRecord(AddressRange(kAddress, kSize), &record);

  // No match: requested region is outside.
  std::vector<BytesRecordPtr> matching_records;
  bytes_layer->GetRecordsSpanning(AddressRange(73ULL, 5U),
                                  &matching_records);
  ASSERT_EQ(0, matching_records.size());
  bytes_layer->GetRecordsSpanning(AddressRange(96ULL, 3U),
                                  &matching_records);
  ASSERT_EQ(0, matching_records.size());

  // No match: requested region straddles.
  bytes_layer->GetRecordsSpanning(AddressRange(75ULL, 10U),
                                  &matching_records);
  ASSERT_EQ(0, matching_records.size());

  // No match: requested region is a superset.
  bytes_layer->GetRecordsSpanning(AddressRange(75ULL, 32U),
                                  &matching_records);
  ASSERT_EQ(0, matching_records.size());

  // Match: requested region is a subset.
  bytes_layer->GetRecordsSpanning(AddressRange(84ULL, 4U),
                                  &matching_records);
  ValidateSingleRecordMatch(AddressRange(kAddress, kSize), matching_records,
                            "Case: Requested region is a subset");
  matching_records.clear();

  // Match: region is exact match.
  bytes_layer->GetRecordsSpanning(AddressRange(kAddress, kSize),
                                  &matching_records);
  ValidateSingleRecordMatch(AddressRange(kAddress, kSize), matching_records,
                            "Case: Requested region is exact match");
}

TEST(ProcessStateTest, GetRecordsSpanningMultipleRecords) {
  // Create a report with a Bytes layer.
  ProcessState report;
  BytesLayerPtr bytes_layer;
  report.FindOrCreateLayer(&bytes_layer);
  ASSERT_TRUE(bytes_layer != nullptr);

  // Add a few records (note the 2 records at the same address).
  BytesRecordPtr record;
  bytes_layer->CreateRecord(AddressRange(80ULL, 16U), &record);
  bytes_layer->CreateRecord(AddressRange(75ULL, 25U), &record);
  bytes_layer->CreateRecord(AddressRange(80ULL, 16U), &record);

  // Match a subset.
  std::vector<BytesRecordPtr> matching_records;
  bytes_layer->GetRecordsSpanning(AddressRange(82ULL, 4U),
                                  &matching_records);
  ASSERT_EQ(3, matching_records.size());
}

TEST(ProcessStateTest, GetRecordsIntersectingSingleRecord) {
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
  bytes_layer->CreateRecord(AddressRange(kAddress, kSize), &record);

  // No match: requested region is outside.
  std::vector<BytesRecordPtr> matching_records;
  bytes_layer->GetRecordsIntersecting(AddressRange(73ULL, 5U),
                                      &matching_records);
  ASSERT_EQ(0, matching_records.size());
  bytes_layer->GetRecordsIntersecting(AddressRange(96ULL, 3U),
                                      &matching_records);
  ASSERT_EQ(0, matching_records.size());

  // No match: requested region is contiguous.
  bytes_layer->GetRecordsIntersecting(AddressRange(75ULL, 5U),
                                      &matching_records);
  ASSERT_EQ(0, matching_records.size());
  bytes_layer->GetRecordsIntersecting(AddressRange(96ULL, 3U),
                                      &matching_records);
  ASSERT_EQ(0, matching_records.size());

  // Match: requested region straddles.
  bytes_layer->GetRecordsIntersecting(AddressRange(75ULL, 10U),
                                      &matching_records);
  ValidateSingleRecordMatch(AddressRange(kAddress, kSize), matching_records,
                            "Case: Requested region straddles");
  matching_records.clear();

  // Match: requested region is a superset.
  bytes_layer->GetRecordsIntersecting(AddressRange(75ULL, 32U),
                                      &matching_records);
  ValidateSingleRecordMatch(AddressRange(kAddress, kSize), matching_records,
                            "Case: Requested region is a superset");
  matching_records.clear();

  // Match: requested region is a subset.
  bytes_layer->GetRecordsIntersecting(AddressRange(84ULL, 4U),
                                      &matching_records);
  ValidateSingleRecordMatch(AddressRange(kAddress, kSize), matching_records,
                            "Case: Requested region is a subset");
  matching_records.clear();

  // Match: region is exact match.
  bytes_layer->GetRecordsIntersecting(AddressRange(kAddress, kSize),
                                      &matching_records);
  ValidateSingleRecordMatch(AddressRange(kAddress, kSize), matching_records,
                            "Case: Requested region is an exact match");
  matching_records.clear();
}

TEST(ProcessStateTest, GetRecordsIntersectingMultipleRecords) {
  // Create a report with a Bytes layer.
  ProcessState report;
  BytesLayerPtr bytes_layer;
  report.FindOrCreateLayer(&bytes_layer);
  ASSERT_TRUE(bytes_layer != nullptr);

  // Add a few records.
  BytesRecordPtr record;
  bytes_layer->CreateRecord(AddressRange(80ULL, 16U), &record);
  bytes_layer->CreateRecord(AddressRange(75ULL, 25U), &record);
  bytes_layer->CreateRecord(AddressRange(80ULL, 16U),
                            &record);  // Second record at location.

  // Match a subset straddling region.
  std::vector<BytesRecordPtr> matching_records;
  bytes_layer->GetRecordsIntersecting(AddressRange(78ULL, 4U),
                                      &matching_records);
  ASSERT_EQ(3, matching_records.size());
}

TEST(ProcessStateTest, RemoveRecord) {
  // Create a report that has a Bytes layer with a single record.
  ProcessState report;
  BytesLayerPtr bytes_layer;
  report.FindOrCreateLayer(&bytes_layer);
  ASSERT_TRUE(bytes_layer != nullptr);

  const Address kAddress = 80ULL;
  const Size kSize = 16U;
  BytesRecordPtr record;
  bytes_layer->CreateRecord(AddressRange(kAddress, kSize), &record);
  ASSERT_EQ(1, bytes_layer->size());

  // Remove record.
  ASSERT_TRUE(bytes_layer->RemoveRecord(record));
  ASSERT_EQ(0, bytes_layer->size());

  // Removing a second time fails.
  ASSERT_FALSE(bytes_layer->RemoveRecord(record));
}

TEST(ProcessStateTest, LayerIteration) {
  // Create a report that has a Bytes layer with few records.
  ProcessState report;
  BytesLayerPtr bytes_layer;
  report.FindOrCreateLayer(&bytes_layer);
  ASSERT_TRUE(bytes_layer != nullptr);

  BytesRecordPtr record;
  bytes_layer->CreateRecord(AddressRange(80ULL, 4U), &record);
  bytes_layer->CreateRecord(AddressRange(84ULL, 4U), &record);
  bytes_layer->CreateRecord(AddressRange(88ULL, 4U), &record);

  // Manual iteration.
  // Note: for ease of testing, this test relies on the iterator returning
  // records by ascending address. However, this is not in the contract.
  ProcessState::Layer<Bytes>::Iterator it = bytes_layer->begin();
  ASSERT_EQ(80ULL, (*it)->range().start());
  ++it;
  ASSERT_EQ(84ULL, (*it)->range().start());
  ++it;
  ASSERT_EQ(88ULL, (*it)->range().start());
  ++it;
  ASSERT_EQ(bytes_layer->end(), it);

  // Range based for loop.
  int record_count = 0;
  for (BytesRecordPtr rec : *bytes_layer) {
    ++record_count;
  }
  ASSERT_EQ(3, record_count);
}

class ProcessStateBitSourceTest : public testing::Test {
 protected:
  void SetUp() override {
    // Populate the process state with a single Bytes record at address_,
    // containing data_.

    address_ = 80ULL;
    data_ = "0123456789";

    // Note: range doesn't include trailing '\0'.
    AddressRange record_range(address_, data_.size());

    BytesLayerPtr bytes_layer;
    process_state_.FindOrCreateLayer(&bytes_layer);
    BytesRecordPtr bytes_record;
    bytes_layer->CreateRecord(record_range, &bytes_record);
    *bytes_record->mutable_data()->mutable_data() = data_;
  }

  Address address() { return address_; }
  const std::string& data() { return data_; }

  void PerformGetFromTest(AddressRange requested,
                          size_t expected_cnt,
                          bool bytes_requested,
                          const std::string& expected_bytes) {
    size_t retrieved_cnt = 0U;
    std::unique_ptr<char[]> buffer(new char[data().size()]);
    memset(buffer.get(), 0, data().size());

    ASSERT_TRUE(
        process_state_.GetFrom(requested, &retrieved_cnt, buffer.get()));

    ASSERT_EQ(expected_cnt, retrieved_cnt);
    if (bytes_requested)
      ASSERT_EQ(expected_bytes, std::string(buffer.get(), retrieved_cnt));
  }

  ProcessState process_state_;

 private:
  Address address_;
  std::string data_;
};

TEST_F(ProcessStateBitSourceTest, GetAll) {
  char retrieved = '-';

  // Fail to retrieve data that is not fully in the process state.
  AddressRange desired_range = AddressRange(address() - 1, data().size());
  ASSERT_FALSE(process_state_.GetAll(desired_range, &retrieved));

  // Successfully retrieve data that is in the process state.
  retrieved = '-';
  ASSERT_TRUE(process_state_.GetAll(AddressRange(address(), 1U), &retrieved));
  ASSERT_EQ(data()[0], retrieved);
}

TEST_F(ProcessStateBitSourceTest, GetFrom) {
  size_t retrieved_cnt = 0U;
  std::unique_ptr<char[]> buffer(new char[data().size()]);

  // Fail to retrieve when the head is outside existing data.
  AddressRange desired(address() - 1U, data().size());
  ASSERT_FALSE(process_state_.GetFrom(desired, &retrieved_cnt, nullptr));
  desired = AddressRange(address() + data().size(), 1U);
  ASSERT_FALSE(process_state_.GetFrom(desired, &retrieved_cnt, buffer.get()));

  // Successful full retrieval - not asking for data.
  desired = AddressRange(address() + 1, data().size() - 1);
  PerformGetFromTest(desired, data().size() - 1, false, "");

  // Successful partial retrieval - not asking for data.
  desired = AddressRange(address() + 1, data().size());
  PerformGetFromTest(desired, data().size() - 1, false, "");

  // Successful full retrieval - asking for data.
  std::string expected_bytes = data().substr(1, data().size() - 1);
  desired = AddressRange(address() + 1, data().size() - 1);
  PerformGetFromTest(desired, data().size() - 1, true, expected_bytes);

  // Successful partial retrieval - asking for data.
  desired = AddressRange(address() + 1, data().size());
  PerformGetFromTest(desired, data().size() - 1, true, expected_bytes);
}

}  // namespace refinery
