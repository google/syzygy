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

#include "syzygy/pe/serialization.h"

#include "gtest/gtest.h"
#include "syzygy/block_graph/unittest_util.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/image_layout.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/pe/unittest_util.h"

namespace pe {

namespace {

using block_graph::BlockGraph;
using block_graph::BlockGraphSerializer;

// Compares two image-layouts for equality.
bool ImageLayoutsEqual(const ImageLayout& il1, const ImageLayout& il2) {
  if (il1.sections != il2.sections)
    return false;

  if (il1.blocks.size() != il2.blocks.size())
    return false;

  typedef block_graph::BlockGraph::AddressSpace::RangeMapConstIter ConstIt;
  ConstIt it1 = il1.blocks.begin();
  ConstIt it2 = il2.blocks.begin();
  for (; it1 != il1.blocks.end(); ++it1, ++it2) {
    if (it1->first != it2->first)
      return false;
    if (it1->second->id() != it2->second->id())
      return false;
  }

  return true;
}

class SerializationTest : public testing::PELibUnitTest {
 public:
  SerializationTest() : image_layout_(&block_graph_) { }
  virtual void SetUp() override {}

  void InitPEFile() {
    base::FilePath image_path(
        testing::GetExeRelativePath(testing::kTestDllName));
    ASSERT_TRUE(pe_file_.Init(image_path));
  }

  void InitDecomposition() {
    ASSERT_NO_FATAL_FAILURE(InitPEFile());
    Decomposer decomposer(pe_file_);
    ASSERT_TRUE(decomposer.Decompose(&image_layout_));
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

  void Serialize(BlockGraphSerializer::Attributes attributes) {
    ASSERT_TRUE(SaveBlockGraphAndImageLayout(pe_file_,
                                             attributes,
                                             image_layout_,
                                             oa_.get()));
  }

  void TestRoundTrip(BlockGraphSerializer::Attributes attributes,
                     bool search_for_pe_file) {
    ASSERT_NO_FATAL_FAILURE(InitDecomposition());
    ASSERT_NO_FATAL_FAILURE(InitOutArchive());
    ASSERT_NO_FATAL_FAILURE(Serialize(attributes));

    ASSERT_NO_FATAL_FAILURE(InitInArchive());
    BlockGraphSerializer::Attributes attributes2;
    PEFile pe_file;
    BlockGraph block_graph;
    ImageLayout image_layout(&block_graph);

    if (search_for_pe_file) {
      ASSERT_TRUE(LoadBlockGraphAndImageLayout(&pe_file,
                                               &attributes2,
                                               &image_layout,
                                               ia_.get()));
    } else {
      ASSERT_TRUE(LoadBlockGraphAndImageLayout(pe_file_,
                                               &attributes2,
                                               &image_layout,
                                               ia_.get()));
    }

    ASSERT_EQ(attributes, attributes2);

    BlockGraphSerializer bgs;
    bgs.set_data_mode(BlockGraphSerializer::OUTPUT_NO_DATA);
    bgs.set_attributes(attributes);
    ASSERT_TRUE(testing::BlockGraphsEqual(block_graph_, block_graph, bgs));
    ASSERT_TRUE(ImageLayoutsEqual(image_layout_, image_layout));
  }

  // Decomposition information.
  PEFile pe_file_;
  BlockGraph block_graph_;
  ImageLayout image_layout_;

  // Streams and archives.
  std::vector<uint8_t> v_;
  std::unique_ptr<core::OutStream> os_;
  std::unique_ptr<core::InStream> is_;
  std::unique_ptr<core::OutArchive> oa_;
  std::unique_ptr<core::InArchive> ia_;
};

}  // namespace

TEST_F(SerializationTest, TestDllRoundTripFull) {
  ASSERT_NO_FATAL_FAILURE(
      TestRoundTrip(BlockGraphSerializer::DEFAULT_ATTRIBUTES, true));
}

TEST_F(SerializationTest, TestDllRoundTripNoStrings) {
  ASSERT_NO_FATAL_FAILURE(
      TestRoundTrip(BlockGraphSerializer::OMIT_STRINGS, false));
}

TEST_F(SerializationTest, FailsForInvalidVersion) {
  ASSERT_NO_FATAL_FAILURE(InitOutArchive());
  ASSERT_NO_FATAL_FAILURE(InitDecomposition());
  ASSERT_NO_FATAL_FAILURE(Serialize(0));
  ASSERT_NO_FATAL_FAILURE(InitInArchive());

  // Change the version.
  v_[0] += 1;

  PEFile pe_file;
  BlockGraph block_graph;
  ImageLayout image_layout(&block_graph);
  ASSERT_FALSE(LoadBlockGraphAndImageLayout(
      &pe_file, NULL, &image_layout, ia_.get()));
}

// TODO(chrisha): Check in a serialized stream, and ensure that it can still be
//     deserialized. As we evolve stream versions, keep doing this. This will be
//     done once decompose.exe has been updated to use the new serialization
//     engine.

}  // namespace pe
