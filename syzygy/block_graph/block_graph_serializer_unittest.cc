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

#include "syzygy/block_graph/block_graph_serializer.h"

#include "base/bind.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/unittest_util.h"
#include "syzygy/core/serialization.h"

namespace block_graph {

namespace {

class TestBlockGraphSerializer : public BlockGraphSerializer {
 public:
  using BlockGraphSerializer::SaveUint32;
  using BlockGraphSerializer::LoadUint32;
  using BlockGraphSerializer::SaveInt32;
  using BlockGraphSerializer::LoadInt32;
};

class BlockGraphSerializerTest : public ::testing::Test {
 public:
  BlockGraphSerializerTest() : block_data_loaded_by_callback_(0) { }

  virtual void SetUp() override {}

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

    // Set compiland name.
    c1->set_compiland_name("c.o");
    c2->set_compiland_name("c.o");
    d1->set_compiland_name("d.o");
    rd1->set_compiland_name("d.o");
    rd2->set_compiland_name("d.o");

    // Set up alignments and paddings.
    c2->set_alignment(16);
    c2->set_alignment_offset(-4);
    c2->set_padding_before(1);
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
        BlockGraph::Block::SourceRange(core::RelativeAddress(36), 48));
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

  void InitBlockDataCallbacks1() {
    s_.set_load_block_data_callback(
        base::Bind(&BlockGraphSerializerTest::LoadBlockDataCallback1,
                   base::Unretained(this)));
  }

  void InitBlockDataCallbacks2() {
    s_.set_save_block_data_callback(
        base::Bind(&BlockGraphSerializerTest::SaveBlockDataCallback2,
                   base::Unretained(this)));
    s_.set_load_block_data_callback(
        base::Bind(&BlockGraphSerializerTest::LoadBlockDataCallback2,
                   base::Unretained(this)));
  }

  bool LoadBlockDataCallback1(bool need_to_set_data,
                              size_t size,
                              BlockGraph::Block* block,
                              core::InArchive* in_archive) {
    DCHECK(block != NULL);
    DCHECK(in_archive != NULL);

    // We only have work to do if the data is not explicitly saved.
    if (!need_to_set_data)
      return true;

    block_data_loaded_by_callback_++;

    EXPECT_LT(0u, size);
    if (size == 0)
      return false;

    EXPECT_EQ(1u, block->source_ranges().size());
    if (block->source_ranges().size() != 1)
      return false;

    // We use the source range to determine which block gets which data, as the
    // name is not always present.
    size_t data_size = 0;
    const uint8_t* data = NULL;
    switch (block->source_ranges().range_pairs()[0].second.start().value()) {
      case 0:
        data = kCode1Data;
        data_size = sizeof(kCode1Data);
        break;

      case 36:
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

  bool SaveBlockDataCallback2(bool data_already_saved,
                              const BlockGraph::Block& block,
                              core::OutArchive* out_archive) {
    DCHECK(out_archive != NULL);

    // If the data is already saved, do nothing.
    if (data_already_saved)
      return true;

    EXPECT_LT(0u, block.data_size());
    if (block.data_size() == 0)
      return false;

    // Determine which data buffer the block holds, and save an index value
    // representing it.
    char data_index = -1;
    if (memcmp(kCode1Data, block.data(), block.data_size()) == 0)
      data_index = 0;
    else if (memcmp(kCode2Data, block.data(), block.data_size()) == 0)
      data_index = 1;
    else if (memcmp(kData1Data, block.data(), block.data_size()) == 0)
      data_index = 2;
    else if (memcmp(kRdata1Data, block.data(), block.data_size()) == 0)
      data_index = 3;

    EXPECT_NE(-1, data_index);
    if (data_index == -1)
      return false;

    if (!out_archive->Save(data_index))
      return false;

    return true;
  }

  bool LoadBlockDataCallback2(bool need_to_set_data,
                              size_t size,
                              BlockGraph::Block* block,
                              core::InArchive* in_archive) {
    DCHECK(block != NULL);
    DCHECK(in_archive != NULL);

    // We only have work to do if the data is not explicitly saved.
    if (!need_to_set_data)
      return true;

    block_data_loaded_by_callback_++;

    EXPECT_LT(0u, size);
    if (size == 0)
      return false;

    char data_index = -1;
    if (!in_archive->Load(&data_index))
      return false;

    EXPECT_LE(0, data_index);
    EXPECT_GT(4, data_index);

    static const uint8_t* kData[] = {
        kCode1Data, kCode2Data, kData1Data, kRdata1Data};
    block->SetData(kData[data_index], size);

    return true;
  }

  enum InitCallbacksType {
    eNoBlockDataCallbacks,
    eInitBlockDataCallbacks1,
    eInitBlockDataCallbacks2
  };

  void TestRoundTrip(BlockGraphSerializer::DataMode data_mode,
                     BlockGraphSerializer::Attributes attributes,
                     InitCallbacksType init_callback,
                     size_t expected_block_data_loaded_by_callback) {
    InitBlockGraph();
    InitOutArchive();

    s_.set_data_mode(data_mode);
    s_.set_attributes(attributes);

    // Initialize the callbacks.
    switch (init_callback) {
      case eInitBlockDataCallbacks1: {
        InitBlockDataCallbacks1();
        break;
      }

      case eInitBlockDataCallbacks2: {
        InitBlockDataCallbacks2();
        break;
      }

      case eNoBlockDataCallbacks:
      default:
        // Do nothing.
        break;
    }

    ASSERT_TRUE(s_.Save(bg_, oa_.get()));
    ASSERT_LT(0u, v_.size());

    InitInArchive();

    BlockGraph bg;
    ASSERT_TRUE(s_.Load(&bg, ia_.get()));
    ASSERT_EQ(data_mode, s_.data_mode());
    ASSERT_EQ(attributes, s_.attributes());
    ASSERT_EQ(expected_block_data_loaded_by_callback,
              block_data_loaded_by_callback_);

    ASSERT_TRUE(testing::BlockGraphsEqual(bg_, bg, s_));
  }

  TestBlockGraphSerializer s_;

  // A block-graph.
  BlockGraph bg_;

  // Streams and archives.
  std::vector<uint8_t> v_;
  std::unique_ptr<core::OutStream> os_;
  std::unique_ptr<core::InStream> is_;
  std::unique_ptr<core::OutArchive> oa_;
  std::unique_ptr<core::InArchive> ia_;

  static const uint8_t kCode1Data[16];
  static const uint8_t kCode2Data[16];
  static const uint8_t kData1Data[16];
  static const uint8_t kRdata1Data[16];

  size_t block_data_loaded_by_callback_;
};

const uint8_t BlockGraphSerializerTest::kCode1Data[16] =
    {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
const uint8_t BlockGraphSerializerTest::kCode2Data[16] =
    {20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5};
const uint8_t BlockGraphSerializerTest::kData1Data[16] =
    {10, 30, 45, 63, 20, 23, 67, 20, 32, 40, 50, 10, 15, 10, 18, 19};
const uint8_t BlockGraphSerializerTest::kRdata1Data[16] =
    {28, 28, 29, 30, 56, 28, 23, 78, 19, 99, 10, 10, 23, 54, 54, 12};

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

TEST_F(BlockGraphSerializerTest, VariableLengthUint32Encoding) {
  const uint32_t kTestValues[] = {
      // 5-bit values (< 32) that map to 1 byte.
      1,
      27,
      31,
      // 13-bit values (< 8,192) that map to 2 bytes.
      32,
      1034,
      8191,
      // 21-bit values (< 2,097,152) that map to 3 bytes.
      8192,
      1023847,
      2097151,
      // 29-bit values (< 536,870,912) that map to 4 bytes.
      2097152,
      38274285,
      536870911,
      // 32-bit values (< 4,294,967,296) that map to 5 bytes.
      536870912,
      1610612736,
      4294967295};

  for (size_t i = 0; i < arraysize(kTestValues); ++i) {
    InitOutArchive();
    ASSERT_TRUE(s_.SaveUint32(kTestValues[i], oa_.get()));
    ASSERT_EQ((i / 3) + 1, v_.size());

    InitInArchive();
    uint32_t value = 0;
    ASSERT_TRUE(s_.LoadUint32(&value, ia_.get()));

    ASSERT_EQ(kTestValues[i], value);
  }
}

TEST_F(BlockGraphSerializerTest, VariableLengthInt32Encoding) {
  const int32_t kTestValues[] = {
      // 4-bit values (< 16) that map to 1 byte.
      1,
      9,
      15,
      // 12-bit values (< 4,096) that map to 2 bytes.
      16,
      1034,
      4095,
      // 20-bit values (< 1,048,576) that map to 3 bytes.
      4096,
      815632,
      1048575,
      // 28-bit values (< 268,435,456) that map to 4 bytes.
      1048576,
      38274285,
      268435455,
      // 31-bit values (< 2,147,483,648) that map to 5 bytes.
      268435456,
      805306368,
      2147483647};

  for (size_t i = 0; i < arraysize(kTestValues); ++i) {
    // We try the value in a negative and positive format.
    for (int32_t j = -1; j <= 1; j += 2) {
      int32_t expected_value = kTestValues[i] * j;

      InitOutArchive();
      ASSERT_TRUE(s_.SaveInt32(expected_value, oa_.get()));
      ASSERT_EQ((i / 3) + 1, v_.size());

      InitInArchive();
      int32_t value = 0;
      ASSERT_TRUE(s_.LoadInt32(&value, ia_.get()));

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
      eInitBlockDataCallbacks1, 4));
}

TEST_F(BlockGraphSerializerTest, RoundTripNoDataCustomRepresentation) {
  ASSERT_NO_FATAL_FAILURE(TestRoundTrip(
      BlockGraphSerializer::OUTPUT_NO_DATA,
      BlockGraphSerializer::DEFAULT_ATTRIBUTES,
      eInitBlockDataCallbacks2, 4));
}

TEST_F(BlockGraphSerializerTest, RoundTripOwnedData) {
  ASSERT_NO_FATAL_FAILURE(TestRoundTrip(
      BlockGraphSerializer::OUTPUT_OWNED_DATA,
      BlockGraphSerializer::DEFAULT_ATTRIBUTES,
      eInitBlockDataCallbacks1, 2));
}

TEST_F(BlockGraphSerializerTest, RoundTripOwnedDataCustomRepresentation) {
  ASSERT_NO_FATAL_FAILURE(TestRoundTrip(
      BlockGraphSerializer::OUTPUT_OWNED_DATA,
      BlockGraphSerializer::DEFAULT_ATTRIBUTES,
      eInitBlockDataCallbacks2, 2));
}

TEST_F(BlockGraphSerializerTest, RoundTripAllData) {
  ASSERT_NO_FATAL_FAILURE(TestRoundTrip(
      BlockGraphSerializer::OUTPUT_ALL_DATA,
      BlockGraphSerializer::DEFAULT_ATTRIBUTES,
      eNoBlockDataCallbacks, 0));
}

// TODO(chrisha): Do a heck of a lot more testing of protected member functions.

}  // namespace block_graph
