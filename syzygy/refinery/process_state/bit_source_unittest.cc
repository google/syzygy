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

#include "syzygy/refinery/process_state/bit_source.h"

#include "gtest/gtest.h"
#include "syzygy/refinery/core/address.h"
#include "syzygy/refinery/process_state/process_state.h"
#include "syzygy/refinery/process_state/process_state_util.h"

namespace refinery {

namespace {

const Address kAddress = 80ULL;
const char kData[] = "0123456789";

}  // namespace

class BitSourceTest : public testing::Test {
 protected:
  void SetUp() override {
    // Note: range doesn't include trailing '\0'.
    record_range_ = AddressRange(kAddress, sizeof(kData) - 1);

    // Populate the process state with a single Bytes record at kAddress,
    // containing kData.
    BytesLayerPtr bytes_layer;
    process_state_.FindOrCreateLayer(&bytes_layer);
    BytesRecordPtr bytes_record;
    bytes_layer->CreateRecord(record_range_, &bytes_record);
    *bytes_record->mutable_data()->mutable_data() = kData;
  }

  AddressRange record_range_;
  ProcessState process_state_;
};

TEST_F(BitSourceTest, GetAtTest) {
  BitSource bit_source(&process_state_);

  char retrieved;

  // Fail to retrieve data that is not fully in the process state.
  AddressRange desired_range = AddressRange(kAddress - 1, record_range_.size());
  ASSERT_FALSE(bit_source.GetAll(desired_range, &retrieved));

  // Successfully retrieve data that is in the process state.
  retrieved = '-';
  ASSERT_TRUE(bit_source.GetAll(AddressRange(kAddress, 1U), &retrieved));
  ASSERT_EQ('0', retrieved);
}

}  // namespace refinery
