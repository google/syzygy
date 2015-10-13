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

#include "syzygy/refinery/process_state/process_state_util.h"

#include <vector>

#include "gtest/gtest.h"
#include "syzygy/refinery/core/address.h"
#include "syzygy/refinery/process_state/process_state.h"
#include "syzygy/refinery/process_state/refinery.pb.h"

namespace refinery {

namespace {

const Address kAddress = 0xCAFECAFE;
const Size kSize = 42U;
const uint32 kChecksum = 11U;
const uint32 kTimestamp = 22U;
const char kPath[] = "c:\\path\\ModuleName";

}  // namespace

TEST(AddModuleRecord, BasicTest) {
  ProcessState state;
  AddModuleRecord(AddressRange(kAddress, kSize), kChecksum, kTimestamp, kPath,
                  &state);

  // Validate a record was added.
  ModuleLayerPtr module_layer;
  ASSERT_TRUE(state.FindLayer(&module_layer));
  std::vector<ModuleRecordPtr> matching_records;
  module_layer->GetRecordsAt(kAddress, &matching_records);
  ASSERT_EQ(1, matching_records.size());

  // Validate range.
  ModuleRecordPtr record = matching_records[0];
  ASSERT_EQ(AddressRange(kAddress, kSize), record->range());

  // Validate module proto.
  Module* proto = record->mutable_data();
  ASSERT_EQ(kChecksum, proto->checksum());
  ASSERT_EQ(kTimestamp, proto->timestamp());
  ASSERT_EQ(kPath, proto->name());
}

}  // namespace refinery
