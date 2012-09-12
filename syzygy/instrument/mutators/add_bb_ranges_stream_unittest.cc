// Copyright 2012 Google Inc. All Rights Reserved.
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

#include "syzygy/instrument/mutators/add_bb_ranges_stream.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/common/basic_block_frequency_data.h"
#include "syzygy/pdb/pdb_byte_stream.h"
#include "syzygy/pdb/unittest_util.h"

namespace instrument {
namespace mutators {

namespace {

typedef AddBasicBlockRangesStreamPdbMutator::RelativeAddressRange
    RelativeAddressRange;
typedef AddBasicBlockRangesStreamPdbMutator::RelativeAddressRangeVector
    RelativeAddressRangeVector;

using core::RelativeAddress;
using common::kBasicBlockRangesStreamName;
using common::kConditionalRangesStreamName;

}  // namespace

TEST(AddBasicBlockRangesStreamPdbMutatorTest,
     FailsIfBasicBlockRangesStreamAlreadyExists) {
  RelativeAddressRangeVector bb_ranges;
  RelativeAddressRangeVector cond_ranges;
  AddBasicBlockRangesStreamPdbMutator mutator(bb_ranges, cond_ranges);

  bb_ranges.push_back(RelativeAddressRange(RelativeAddress(0x11111111), 4));
  bb_ranges.push_back(RelativeAddressRange(RelativeAddress(0x22222222), 4));
  cond_ranges.push_back(RelativeAddressRange(RelativeAddress(0x33333333), 4));
  cond_ranges.push_back(RelativeAddressRange(RelativeAddress(0x44444444), 4));

  pdb::PdbFile pdb_file;
  ASSERT_NO_FATAL_FAILURE(testing::InitMockPdbFile(&pdb_file));

  // Add a dummy stream with the same name as the one we want to add.
  pdb::PdbInfoHeader70 pdb_header = {};
  pdb::NameStreamMap name_stream_map;
  EXPECT_TRUE(pdb::ReadHeaderInfoStream(pdb_file, &pdb_header,
                                        &name_stream_map));
  scoped_refptr<pdb::PdbStream> stream(new pdb::PdbByteStream);
  size_t stream_id = pdb_file.AppendStream(stream.get());
  name_stream_map[kBasicBlockRangesStreamName] = stream_id;
  EXPECT_TRUE(pdb::WriteHeaderInfoStream(pdb_header, name_stream_map,
                                         &pdb_file));

  EXPECT_FALSE(mutator.MutatePdb(&pdb_file));
}

TEST(AddBasicBlockRangesStreamPdbMutatorTest,
     FailsIfConditionalRangesStreamAlreadyExists) {
  RelativeAddressRangeVector bb_ranges;
  RelativeAddressRangeVector cond_ranges;
  AddBasicBlockRangesStreamPdbMutator mutator(bb_ranges, cond_ranges);

  bb_ranges.push_back(RelativeAddressRange(RelativeAddress(0x11111111), 4));
  bb_ranges.push_back(RelativeAddressRange(RelativeAddress(0x22222222), 4));
  cond_ranges.push_back(RelativeAddressRange(RelativeAddress(0x33333333), 4));
  cond_ranges.push_back(RelativeAddressRange(RelativeAddress(0x44444444), 4));

  pdb::PdbFile pdb_file;
  ASSERT_NO_FATAL_FAILURE(testing::InitMockPdbFile(&pdb_file));

  // Add a dummy stream with the same name as the one we want to add.
  pdb::PdbInfoHeader70 pdb_header = {};
  pdb::NameStreamMap name_stream_map;
  EXPECT_TRUE(pdb::ReadHeaderInfoStream(pdb_file, &pdb_header,
                                        &name_stream_map));
  scoped_refptr<pdb::PdbStream> stream(new pdb::PdbByteStream);
  size_t stream_id = pdb_file.AppendStream(stream.get());
  name_stream_map[kConditionalRangesStreamName] = stream_id;
  EXPECT_TRUE(pdb::WriteHeaderInfoStream(pdb_header, name_stream_map,
                                         &pdb_file));

  EXPECT_FALSE(mutator.MutatePdb(&pdb_file));
}

TEST(AddBasicBlockRangesStreamPdbMutatorTest, AddsStreams) {
  RelativeAddressRangeVector bb_ranges;
  RelativeAddressRangeVector cond_ranges;
  AddBasicBlockRangesStreamPdbMutator mutator(bb_ranges, cond_ranges);

  bb_ranges.push_back(RelativeAddressRange(RelativeAddress(0x11111111), 4));
  bb_ranges.push_back(RelativeAddressRange(RelativeAddress(0x22222222), 4));
  cond_ranges.push_back(RelativeAddressRange(RelativeAddress(0x33333333), 4));
  cond_ranges.push_back(RelativeAddressRange(RelativeAddress(0x44444444), 4));

  pdb::PdbFile pdb_file;
  ASSERT_NO_FATAL_FAILURE(testing::InitMockPdbFile(&pdb_file));

  EXPECT_TRUE(mutator.MutatePdb(&pdb_file));

  pdb::PdbInfoHeader70 pdb_header = {};
  pdb::NameStreamMap name_stream_map;
  EXPECT_TRUE(pdb::ReadHeaderInfoStream(pdb_file, &pdb_header,
                                        &name_stream_map));

  // We expect the named stream to have been added.
  EXPECT_EQ(1u, name_stream_map.count(kBasicBlockRangesStreamName));

  // Get the stream.
  size_t bb_stream_id = name_stream_map[kBasicBlockRangesStreamName];
  size_t cond_stream_id = name_stream_map[kConditionalRangesStreamName];
  scoped_refptr<pdb::PdbStream> bb_stream = pdb_file.GetStream(bb_stream_id);
  scoped_refptr<pdb::PdbStream> cond_stream =
      pdb_file.GetStream(cond_stream_id);
  EXPECT_TRUE(bb_stream.get() != NULL);
  EXPECT_TRUE(cond_stream.get() != NULL);

  // Validate the basic block ranges stream contents.
  RelativeAddressRangeVector bb_ranges2;
  EXPECT_TRUE(bb_stream->Seek(0));
  EXPECT_TRUE(bb_stream->Read(&bb_ranges2));
  EXPECT_THAT(bb_ranges, testing::ContainerEq(bb_ranges2));

  // Validate the conditional ranges stream contents.
  RelativeAddressRangeVector cond_ranges2;
  EXPECT_TRUE(cond_stream->Seek(0));
  EXPECT_TRUE(cond_stream->Read(&cond_ranges2));
  EXPECT_THAT(cond_ranges, testing::ContainerEq(cond_ranges2));
}

}  // namespace mutators
}  // namespace instrument
