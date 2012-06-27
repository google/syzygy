// Copyright 2012 Google Inc.
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

#include "syzygy/block_graph/block_graph_serializer.h"

#include "base/bind.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/unittest_util.h"
#include "syzygy/core/serialization.h"

namespace block_graph {

namespace {

class TestBlockGraphSerializer : public BlockGraphSerializer {
 public:
  using BlockGraphSerializer::SaveUint30;
  using BlockGraphSerializer::LoadUint30;
  using BlockGraphSerializer::SaveInt30;
  using BlockGraphSerializer::LoadInt30;
};

class BlockGraphSerializerTest : public ::testing::Test {
 public:
  BlockGraphSerializerTest() : block_data_callback_count_(0) { }

  virtual void SetUp() OVERRIDE {
  }

  void InitOutArchive() {
    v_.clear();
    os_.reset(core::CreateByteOutStream(std::back_inserter(v_)));
    oa_.reset(new core::NativeBinaryOutArchive(
        os_.get()));
  }

  void InitInArchive() {
    is_.reset(core::CreateByteInStream(v_.begin(), v_.end()));
    ia_.reset(new core::NativeBinaryInArchive(
        is_.get()));
  }

  void InitBlockGraph() {
    BlockGraph::Section* text = bg_.AddSection(".text", 1 | 4);
    BlockGraph::Section* data = bg_.AddSection(".data", 2);
    BlockGraph::Section* rdata = bg_.AddSection(".rdata", 2 | 4);

    BlockGraph::Block* c1 = bg_.AddBlock(BlockGraph::CODE_BLOCK, 20, "code1");
    BlockGraph::Block* c2 = bg_.AddBlock(BlockGraph::CODE_BLOCK, 16, "code2");
    BlockGraph::Block* d1 = bg_.AddBlock(BlockGraph::DATA_BLOCK, 20, "data1");
    BlockGraph::Block* rd1 = bg_.AddBlock(BlockGraph::DATA_BLOCK, 16, "rdata1");
    BlockGraph::Block* rd2 = bg_.AddBlock(BlockGraph::DATA_BLOCK, 16, "rdata2");

    c1->set_section(text->id());
    c2->set_section(text->id());
    d1->set_section(data->id());
    rd1->set_section(rdata->id());
    rd2->set_section(rdata->id());

    // Set up alignments.
    d1->set_alignment(16);
    rd1->set_alignment(16);
    rd1->set_alignment(16);

    // Some of the blocks own their own data, some don't. One has no data at
    // all.
    c1->SetData(kCode1Data, sizeof(kCode1Data));
    c2->CopyData(sizeof(kCode2Data), kCode2Data);
    d1->SetData(kData1Data, sizeof(kData1Data));
    rd1->CopyData(sizeof(kRdata1Data), kRdata1Data);

    // Given them all source ranges.
    c1->source_ranges().Push(BlockGraph::Block::DataRange(0, 20),
        BlockGraph::Block::SourceRange(core::RelativeAddress(0), 20));
    c2->source_ranges().Push(BlockGraph::Block::DataRange(0, 16),
        BlockGraph::Block::SourceRange(core::RelativeAddress(32), 48));
    d1->source_ranges().Push(BlockGraph::Block::DataRange(0, 20),
        BlockGraph::Block::SourceRange(core::RelativeAddress(512), 532));
    rd1->source_ranges().Push(BlockGraph::Block::DataRange(0, 16),
        BlockGraph::Block::SourceRange(core::RelativeAddress(1024), 1040));
    rd2->source_ranges().Push(BlockGraph::Block::DataRange(0, 16),
        BlockGraph::Block::SourceRange(core::RelativeAddress(1040), 1056));

    // Set up labels.
    c1->SetLabel(0, BlockGraph::Label("code1",
        BlockGraph::CODE_LABEL | BlockGraph::DEBUG_START_LABEL));
    c1->SetLabel(8, BlockGraph::Label("label", BlockGraph::CODE_LABEL));
    c1->SetLabel(11, BlockGraph::Label("debug", BlockGraph::DEBUG_END_LABEL));
    c1->SetLabel(12, BlockGraph::Label("jump",
        BlockGraph::DATA_LABEL | BlockGraph::JUMP_TABLE_LABEL));
    c2->SetLabel(0, BlockGraph::Label("code1", BlockGraph::CODE_LABEL));
    c2->SetLabel(8, BlockGraph::Label("jump",
        BlockGraph::DATA_LABEL | BlockGraph::JUMP_TABLE_LABEL));
    c2->SetLabel(12, BlockGraph::Label("case",
        BlockGraph::DATA_LABEL | BlockGraph::CASE_TABLE_LABEL));
    d1->SetLabel(0, BlockGraph::Label("data", BlockGraph::DATA_LABEL));

    // Set up some references.
    c1->SetReference(4, BlockGraph::Reference(
        BlockGraph::ABSOLUTE_REF, 4, d1, 0, 0));
    c1->SetReference(12, BlockGraph::Reference(
        BlockGraph::ABSOLUTE_REF, 4, c2, 0, 0));
    c2->SetReference(8, BlockGraph::Reference(
        BlockGraph::ABSOLUTE_REF, 4, c1, 0, 0));
    d1->SetReference(0, BlockGraph::Reference(
        BlockGraph::ABSOLUTE_REF, 4, rd1, 0, 0));
    rd1->SetReference(0, BlockGraph::Reference(
        BlockGraph::ABSOLUTE_REF, 4, rd2, 0, 0));
  }

  void InitBlockDataCallback() {
    s_.set_block_data_callback(
        base::Bind(&BlockGraphSerializerTest::BlockDataCallback,
                   base::Unretained(this)));
  }

  bool BlockDataCallback(size_t size, BlockGraph::Block* block) {
    // We use the source range to determine which block gets which data, as the
    // name is not always present.
    ++block_data_callback_count_;

    EXPECT_LT(0u, size);
    if (size == 0)
      return false;

    EXPECT_EQ(1u, block->source_ranges().size());
    if (block->source_ranges().size() != 1)
      return false;

    size_t data_size = 0;
    const uint8* data = NULL;
    switch (block->source_ranges().range_pairs()[0].second.start().value()) {
      case 0:
        data = kCode1Data;
        data_size = sizeof(kCode1Data);
        break;

      case 32:
        data = kCode2Data;
        data_size = sizeof(kCode2Data);
        break;

      case 512:
        data = kData1Data;
        data_size = sizeof(kData1Data);
        break;

      case 1024:
        data = kRdata1Data;
        data_size = sizeof(kRdata1Data);
        break;

      default:
        break;
    }

    EXPECT_TRUE(data != NULL);
    EXPECT_EQ(data_size, size);
    if (data == NULL || data_size != size)
      return false;

    block->SetData(data, data_size);
    return true;
  }

  void TestRoundTrip(BlockGraphSerializer::DataMode data_mode,
                     BlockGraphSerializer::Attributes attributes,
                     bool init_callback,
                     size_t expected_block_data_callback_count) {
    InitBlockGraph();
    InitOutArchive();

    s_.set_data_mode(data_mode);
    s_.set_attributes(attributes);

    ASSERT_TRUE(s_.Save(bg_, oa_.get()));
    ASSERT_LT(0u, v_.size());

    InitInArchive();
    if (init_callback)
      InitBlockDataCallback();

    BlockGraph bg;
    ASSERT_TRUE(s_.Load(&bg, ia_.get()));
    ASSERT_EQ(data_mode, s_.data_mode());
    ASSERT_EQ(attributes, s_.attributes());
    ASSERT_EQ(expected_block_data_callback_count, block_data_callback_count_);

    ASSERT_TRUE(testing::BlockGraphsEqual(bg_, bg, s_));
  }

  TestBlockGraphSerializer s_;

  // A block-graph.
  BlockGraph bg_;

  // Streams and archives.
  std::vector<uint8> v_;
  scoped_ptr<core::OutStream> os_;
  scoped_ptr<core::InStream> is_;
  scoped_ptr<core::OutArchive> oa_;
  scoped_ptr<core::InArchive> ia_;

  static const uint8 kCode1Data[16];
  static const uint8 kCode2Data[16];
  static const uint8 kData1Data[16];
  static const uint8 kRdata1Data[16];

  size_t block_data_callback_count_;
};

const uint8 BlockGraphSerializerTest::kCode1Data[16] = {
     1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16 };
const uint8 BlockGraphSerializerTest::kCode2Data[16] = {
    20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10,  9,  8,  7,  6,  5 };
const uint8 BlockGraphSerializerTest::kData1Data[16] = {
    10, 30, 45, 63, 20, 23, 67, 20, 32, 40, 50, 10, 15, 10, 18, 19 };
const uint8 BlockGraphSerializerTest::kRdata1Data[16] = {
    28, 28, 29, 30, 56, 28, 23, 78, 19, 99, 10, 10, 23, 54, 54, 12 };

}  // namespace

TEST_F(BlockGraphSerializerTest, Construction) {
  ASSERT_EQ(BlockGraphSerializer::DEFAULT_DATA_MODE, s_.data_mode());
  ASSERT_EQ(BlockGraphSerializer::DEFAULT_ATTRIBUTES, s_.data_mode());
}

TEST_F(BlockGraphSerializerTest, SetDataMode) {
  ASSERT_EQ(BlockGraphSerializer::DEFAULT_DATA_MODE, s_.data_mode());

  s_.set_data_mode(BlockGraphSerializer::OUTPUT_NO_DATA);
  ASSERT_EQ(BlockGraphSerializer::OUTPUT_NO_DATA, s_.data_mode());

  s_.set_data_mode(BlockGraphSerializer::OUTPUT_ALL_DATA);
  ASSERT_EQ(BlockGraphSerializer::OUTPUT_ALL_DATA, s_.data_mode());
}

TEST_F(BlockGraphSerializerTest, AddAttributes) {
  ASSERT_EQ(0u, s_.attributes());

  s_.add_attributes(1);
  ASSERT_EQ(1u, s_.attributes());

  s_.add_attributes(2 | 4);
  ASSERT_EQ(1u | 2u | 4u, s_.attributes());
}

TEST_F(BlockGraphSerializerTest, ClearAttributes) {
  ASSERT_EQ(0u, s_.attributes());

  s_.add_attributes(1 | 2);
  ASSERT_EQ(1u | 2u, s_.attributes());

  s_.clear_attributes(2);
  ASSERT_EQ(1u, s_.attributes());
}

TEST_F(BlockGraphSerializerTest, SetAttributes) {
  ASSERT_EQ(0u, s_.attributes());

  s_.set_attributes(1 | 2);
  ASSERT_EQ(1u | 2u, s_.attributes());

  s_.set_attributes(4 | 8);
  ASSERT_EQ(4u | 8u, s_.attributes());
}

TEST_F(BlockGraphSerializerTest, HasAttributes) {
  ASSERT_EQ(0u, s_.attributes());

  s_.set_attributes(1 | 2);
  ASSERT_EQ(1u | 2u, s_.attributes());

  ASSERT_TRUE(s_.has_attributes(1));
  ASSERT_TRUE(s_.has_attributes(2));
  ASSERT_TRUE(s_.has_attributes(1 | 2));
  ASSERT_FALSE(s_.has_attributes(1 | 2 | 4));
}

TEST_F(BlockGraphSerializerTest, HasAnyAttributes) {
  ASSERT_EQ(0u, s_.attributes());

  s_.set_attributes(1 | 2);
  ASSERT_EQ(1u | 2u, s_.attributes());

  ASSERT_TRUE(s_.has_any_attributes(1));
  ASSERT_TRUE(s_.has_any_attributes(2));
  ASSERT_TRUE(s_.has_any_attributes(1 | 2 | 4));
  ASSERT_FALSE(s_.has_any_attributes(4 | 8));
}

TEST_F(BlockGraphSerializerTest, VariableLengthUint30Encoding) {
  const uint32 kTestValues[] = {
      // 6-bit values (< 64) that map to 1 byte.
      1, 27, 63,
      // 14-bit values (< 16,384) that map to 2 bytes.
      64, 1034, 16383,
      // 22-bit values (< 4,194,304) that map to 3 bytes.
      16384, 1023847, 4194303,
      // 30-bit values (< 1,073,741,824) that map to 4 bytes.
      4194304, 933985928, 1073741823 };

  for (size_t i = 0; i < arraysize(kTestValues); ++i) {
    InitOutArchive();
    ASSERT_TRUE(s_.SaveUint30(kTestValues[i], oa_.get()));
    ASSERT_EQ((i / 3) + 1, v_.size());

    InitInArchive();
    uint32 value = 0;
    ASSERT_TRUE(s_.LoadUint30(&value, ia_.get()));

    ASSERT_EQ(kTestValues[i], value);
  }
}

TEST_F(BlockGraphSerializerTest, VariableLengthInt30Encoding) {
  const int32 kTestValues[] = {
      // 5-bit values (< 32) that map to 1 byte.
      1, 27, 31,
      // 13-bit values (< 8,192) that map to 2 bytes.
      64, 1034, 8191,
      // 21-bit values (< 2,097,152) that map to 3 bytes.
      16384, 1023847, 2097151,
      // 29-bit values (< 536,870,912) that map to 4 bytes.
      4194304, 38274285, 536870911 };

  for (size_t i = 0; i < arraysize(kTestValues); ++i) {
    // We try the value in a negative and positive format.
    for (int32 j = -1; j <= 1; j += 2) {
      int32 expected_value = kTestValues[i] * j;

      InitOutArchive();
      ASSERT_TRUE(s_.SaveInt30(expected_value, oa_.get()));
      ASSERT_EQ((i / 3) + 1, v_.size());

      InitInArchive();
      int32 value = 0;
      ASSERT_TRUE(s_.LoadInt30(&value, ia_.get()));

      ASSERT_EQ(expected_value, value);
    }
  }
}

TEST_F(BlockGraphSerializerTest, FailsToLoadWrongVersion) {
  // Serialize an empty block-graph.
  InitOutArchive();
  ASSERT_TRUE(s_.Save(bg_, oa_.get()));

  // The first 4 bytes of the stream are the version. We change it so it is
  // invalid.
  v_[0] += 1;

  // Deserialization should fail.
  InitInArchive();
  ASSERT_FALSE(s_.Load(&bg_, ia_.get()));
}

TEST_F(BlockGraphSerializerTest, RoundTripNoData) {
  ASSERT_NO_FATAL_FAILURE(TestRoundTrip(
      BlockGraphSerializer::OUTPUT_NO_DATA,
      BlockGraphSerializer::DEFAULT_ATTRIBUTES,
      true,
      4));
}

TEST_F(BlockGraphSerializerTest, RoundTripOwnedData) {
  ASSERT_NO_FATAL_FAILURE(TestRoundTrip(
      BlockGraphSerializer::OUTPUT_OWNED_DATA,
      BlockGraphSerializer::DEFAULT_ATTRIBUTES,
      true,
      2));
}

TEST_F(BlockGraphSerializerTest, RoundTripAllData) {
  ASSERT_NO_FATAL_FAILURE(TestRoundTrip(
      BlockGraphSerializer::OUTPUT_ALL_DATA,
      BlockGraphSerializer::DEFAULT_ATTRIBUTES,
      true,
      0));
}

// TODO(chrisha): Do a heck of a lot more testing of protected member functions.

}  // namespace block_graph
