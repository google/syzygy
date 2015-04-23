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

#include "gtest/gtest.h"

namespace refinery {

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

  // Add a record for a range of memory.
  const Address kAddr = 0xCAFEBABEULL;
  const Size kSize = 0xBABE;
  scoped_refptr<ProcessState::Record<Bytes>> first_record;
  bytes_layer->CreateRecord(kAddr, kSize, &first_record);

  ASSERT_EQ(kAddr, first_record->addr());
  ASSERT_EQ(kSize, first_record->size());

  // Add a second record for the same range.
  scoped_refptr<ProcessState::Record<Bytes>> second_record;
  bytes_layer->CreateRecord(kAddr, kSize, &second_record);

  ASSERT_EQ(kAddr, second_record->addr());
  ASSERT_EQ(kSize, second_record->size());

  // Verify that this produced two distinct objects.
  ASSERT_NE(first_record.get(), second_record.get());
}

}  // namespace refinery
