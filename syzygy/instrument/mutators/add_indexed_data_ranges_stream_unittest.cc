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

#include "syzygy/instrument/mutators/add_indexed_data_ranges_stream.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/common/indexed_frequency_data.h"
#include "syzygy/pdb/pdb_byte_stream.h"
#include "syzygy/pdb/unittest_util.h"

namespace instrument {
namespace mutators {

namespace {

typedef AddIndexedDataRangesStreamPdbMutator::RelativeAddressRange
    RelativeAddressRange;
typedef AddIndexedDataRangesStreamPdbMutator::RelativeAddressRangeVector
    RelativeAddressRangeVector;

using core::RelativeAddress;

const char stream_name[] = "IndexedDataStream";

}  // namespace

TEST(AddIndexedDataRangesStreamPdbMutatorTest, FailsIfStreamAlreadyExists) {
  RelativeAddressRangeVector indexed_data;
  AddIndexedDataRangesStreamPdbMutator mutator(indexed_data, stream_name);

  indexed_data.push_back(RelativeAddressRange(RelativeAddress(0x11111111), 4));
  indexed_data.push_back(RelativeAddressRange(RelativeAddress(0x22222222), 4));

  pdb::PdbFile pdb_file;
  ASSERT_NO_FATAL_FAILURE(testing::InitMockPdbFile(&pdb_file));

  // Add a dummy stream with the same name as the one we want to add.
  pdb::PdbInfoHeader70 pdb_header = {};
  pdb::NameStreamMap name_stream_map;
  EXPECT_TRUE(pdb::ReadHeaderInfoStream(pdb_file, &pdb_header,
                                        &name_stream_map));
  scoped_refptr<pdb::PdbStream> stream(new pdb::PdbByteStream);
  size_t stream_id = pdb_file.AppendStream(stream.get());
  name_stream_map[stream_name] = stream_id;
  EXPECT_TRUE(pdb::WriteHeaderInfoStream(pdb_header, name_stream_map,
                                         &pdb_file));

  EXPECT_FALSE(mutator.MutatePdb(&pdb_file));
}

TEST(AddIndexedDataRangesStreamPdbMutatorTest, DoesNotAddEmptyStream) {
  RelativeAddressRangeVector indexed_data;
  AddIndexedDataRangesStreamPdbMutator mutator(indexed_data, stream_name);

  pdb::PdbFile pdb_file;
  ASSERT_NO_FATAL_FAILURE(testing::InitMockPdbFile(&pdb_file));

  EXPECT_TRUE(mutator.MutatePdb(&pdb_file));

  pdb::PdbInfoHeader70 pdb_header = {};
  pdb::NameStreamMap name_stream_map;
  EXPECT_TRUE(pdb::ReadHeaderInfoStream(pdb_file, &pdb_header,
                                        &name_stream_map));

  // We expect no named stream to have been added.
  EXPECT_EQ(0u, name_stream_map.count(stream_name));
}

TEST(AddIndexedDataRangesStreamPdbMutatorTest, AddsStream) {
  RelativeAddressRangeVector indexed_data;
  AddIndexedDataRangesStreamPdbMutator mutator(indexed_data, stream_name);

  indexed_data.push_back(RelativeAddressRange(RelativeAddress(0x11111111), 4));
  indexed_data.push_back(RelativeAddressRange(RelativeAddress(0x22222222), 4));

  pdb::PdbFile pdb_file;
  ASSERT_NO_FATAL_FAILURE(testing::InitMockPdbFile(&pdb_file));

  EXPECT_TRUE(mutator.MutatePdb(&pdb_file));

  pdb::PdbInfoHeader70 pdb_header = {};
  pdb::NameStreamMap name_stream_map;
  EXPECT_TRUE(pdb::ReadHeaderInfoStream(pdb_file, &pdb_header,
                                        &name_stream_map));

  // We expect the named stream to have been added.
  EXPECT_EQ(1u, name_stream_map.count(stream_name));

  // Get the stream.
  size_t stream_id = name_stream_map[stream_name];
  scoped_refptr<pdb::PdbStream> stream = pdb_file.GetStream(stream_id);
  EXPECT_TRUE(stream.get() != NULL);

  // Validate the stream contents.
  RelativeAddressRangeVector bb_addresses2(indexed_data.size());
  EXPECT_EQ(sizeof(RelativeAddressRange) * bb_addresses2.size(),
            stream->length());
  EXPECT_TRUE(stream->ReadBytesAt(
      0, sizeof(RelativeAddressRange) * bb_addresses2.size(),
      &bb_addresses2.at(0)));
  EXPECT_THAT(indexed_data, testing::ContainerEq(bb_addresses2));
}

}  // namespace mutators
}  // namespace instrument
