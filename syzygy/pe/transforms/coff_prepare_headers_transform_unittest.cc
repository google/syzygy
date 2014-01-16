// Copyright 2013 Google Inc. All Rights Reserved.
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

#include "syzygy/pe/transforms/coff_prepare_headers_transform.h"

#include "base/stringprintf.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/block_graph/unittest_util.h"
#include "syzygy/pe/pe_utils.h"

namespace pe {
namespace transforms {

using block_graph::BlockGraph;
using block_graph::ConstTypedBlock;
using block_graph::TypedBlock;

namespace {

class CoffPrepareHeadersTransformTest : public testing::Test {
 public:
  CoffPrepareHeadersTransformTest()
      : expected_coff_headers_size_(0),
        file_header_block_(NULL) {
  }

  virtual void SetUp() OVERRIDE {
    block_graph_.set_image_format(BlockGraph::COFF_IMAGE);
    block_graph_.AddSection(kCodeSectionName, kCodeCharacteristics);
    block_graph_.AddSection(kReadOnlyDataSectionName,
                            kReadOnlyDataCharacteristics);
    block_graph_.AddSection(kReadWriteDataSectionName,
                            kReadWriteDataCharacteristics);
    block_graph_.AddSection(kTlsSectionName, kReadOnlyDataCharacteristics);
    block_graph_.AddSection(kResourceSectionName, kReadOnlyDataCharacteristics);
    block_graph_.AddSection(kRelocSectionName, kRelocCharacteristics);

    expected_coff_headers_size_ = sizeof(IMAGE_FILE_HEADER) +
        block_graph_.sections().size() * sizeof(IMAGE_SECTION_HEADER);
  }

  // Build a set of dummy COFF headers.
  //
  // @param num_sections the number of sections.
  void BuildCoffHeaders(size_t num_sections) {
    size_t headers_size = sizeof(IMAGE_FILE_HEADER) +
                          num_sections * sizeof(IMAGE_SECTION_HEADER);
    file_header_block_ = block_graph_.AddBlock(BlockGraph::DATA_BLOCK,
                                               headers_size, "COFF Headers");
    ASSERT_TRUE(file_header_block_ != NULL);
    file_header_block_->AllocateData(file_header_block_->size());

    // Add dummy reference that should be removed by the transform.
    BlockGraph::Reference ref(BlockGraph::RELATIVE_REF, 4,
                              file_header_block_, 0, 0);
    file_header_block_->SetReference(10, ref);
  }

  size_t expected_coff_headers_size_;

  testing::DummyTransformPolicy policy_;
  BlockGraph block_graph_;
  BlockGraph::Block* file_header_block_;
};

}  // namespace

TEST_F(CoffPrepareHeadersTransformTest, ShrinkCoffHeaders) {
  BuildCoffHeaders(block_graph_.sections().size() + 2);
  ASSERT_TRUE(file_header_block_ != NULL);

  CoffPrepareHeadersTransform tx;
  EXPECT_TRUE(tx.TransformBlockGraph(
      &policy_, &block_graph_, file_header_block_));

  ConstTypedBlock<IMAGE_FILE_HEADER> file_header;
  ASSERT_TRUE(file_header.Init(0, file_header_block_));

  EXPECT_FALSE(IsValidDosHeaderBlock(file_header_block_));
  EXPECT_EQ(expected_coff_headers_size_, file_header_block_->size());
  EXPECT_EQ(block_graph_.sections().size(), file_header->NumberOfSections);
}

TEST_F(CoffPrepareHeadersTransformTest, GrowCoffHeaders) {
  size_t num_sections = block_graph_.sections().size() - 2;
  ASSERT_LT(num_sections, block_graph_.sections().size());
  BuildCoffHeaders(num_sections);
  ASSERT_TRUE(file_header_block_ != NULL);

  CoffPrepareHeadersTransform tx;
  EXPECT_TRUE(tx.TransformBlockGraph(
      &policy_, &block_graph_, file_header_block_));

  ConstTypedBlock<IMAGE_FILE_HEADER> file_header;
  ASSERT_TRUE(file_header.Init(0, file_header_block_));

  EXPECT_FALSE(IsValidDosHeaderBlock(file_header_block_));
  EXPECT_EQ(0, file_header_block_->references().size());
  EXPECT_EQ(expected_coff_headers_size_, file_header_block_->size());
  EXPECT_EQ(block_graph_.sections().size(), file_header->NumberOfSections);
}

}  // namespace transforms
}  // namespace pe
