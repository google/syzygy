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

#include "syzygy/pe/transforms/pe_prepare_headers_transform.h"

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

class PEPrepareHeadersTransformTest : public testing::Test {
 public:
  PEPrepareHeadersTransformTest()
      : expected_dos_header_size_(0),
        expected_nt_headers_size_(0),
        dos_header_block_(NULL),
        nt_headers_block_(NULL) {
  }

  virtual void SetUp() {
    block_graph_.set_image_format(BlockGraph::PE_IMAGE);
    block_graph_.AddSection(kCodeSectionName, kCodeCharacteristics);
    block_graph_.AddSection(kReadOnlyDataSectionName,
                             kReadOnlyDataCharacteristics);
    block_graph_.AddSection(kReadWriteDataSectionName,
                             kReadWriteDataCharacteristics);
    block_graph_.AddSection(kTlsSectionName, kReadOnlyDataCharacteristics);
    block_graph_.AddSection(kResourceSectionName,
                             kReadOnlyDataCharacteristics);
    block_graph_.AddSection(kRelocSectionName, kRelocCharacteristics);

    expected_dos_header_size_ = sizeof(IMAGE_DOS_HEADER);
    expected_nt_headers_size_ = sizeof(IMAGE_NT_HEADERS) +
        block_graph_.sections().size() * sizeof(IMAGE_SECTION_HEADER);
  }

  // Builds a set of dummy DOS and NT headers.
  void BuildHeaders(size_t extra_dos_header_bytes, size_t section_count) {
    dos_header_block_ = block_graph_.AddBlock(BlockGraph::DATA_BLOCK,
        sizeof(IMAGE_DOS_HEADER) + extra_dos_header_bytes,
        "Dos Header");
    ASSERT_TRUE(dos_header_block_ != NULL);
    dos_header_block_->AllocateData(dos_header_block_->size());

    nt_headers_block_ = block_graph_.AddBlock(BlockGraph::DATA_BLOCK,
        sizeof(IMAGE_NT_HEADERS) + section_count * sizeof(IMAGE_SECTION_HEADER),
        "Nt Headers");
    ASSERT_TRUE(nt_headers_block_ != NULL);
    nt_headers_block_->AllocateData(nt_headers_block_->size());

    TypedBlock<IMAGE_DOS_HEADER> dos_header;
    ASSERT_TRUE(dos_header.Init(0, dos_header_block_));
    dos_header.SetReference(BlockGraph::RELATIVE_REF,
                            dos_header->e_lfanew,
                            nt_headers_block_,
                            0, 0);

    TypedBlock<IMAGE_NT_HEADERS> nt_headers;
    ASSERT_TRUE(nt_headers.Init(0, nt_headers_block_));
    nt_headers->OptionalHeader.FileAlignment = 512;
  }

  size_t expected_dos_header_size_;
  size_t expected_nt_headers_size_;

  testing::DummyTransformPolicy policy_;
  BlockGraph block_graph_;
  BlockGraph::Block* dos_header_block_;
  BlockGraph::Block* nt_headers_block_;
};

}  // namespace

TEST_F(PEPrepareHeadersTransformTest, ShrinkHeaders) {
  BuildHeaders(100, block_graph_.sections().size() + 2);

  PEPrepareHeadersTransform tx;
  EXPECT_TRUE(tx.TransformBlockGraph(
      &policy_, &block_graph_, dos_header_block_));

  ConstTypedBlock<IMAGE_NT_HEADERS> nt_headers;
  ASSERT_TRUE(nt_headers.Init(0, nt_headers_block_));

  EXPECT_TRUE(IsValidDosHeaderBlock(dos_header_block_));
  EXPECT_EQ(expected_nt_headers_size_, nt_headers_block_->size());
  EXPECT_EQ(expected_nt_headers_size_, nt_headers_block_->data_size());
  EXPECT_EQ(block_graph_.sections().size(),
            nt_headers->FileHeader.NumberOfSections);
}

TEST_F(PEPrepareHeadersTransformTest, GrowHeaders) {
  size_t section_count = block_graph_.sections().size() - 2;
  ASSERT_LT(section_count, block_graph_.sections().size());
  BuildHeaders(0, section_count);

  PEPrepareHeadersTransform tx;
  EXPECT_TRUE(tx.TransformBlockGraph(
      &policy_, &block_graph_, dos_header_block_));

  ConstTypedBlock<IMAGE_NT_HEADERS> nt_headers;
  ASSERT_TRUE(nt_headers.Init(0, nt_headers_block_));

  EXPECT_TRUE(IsValidDosHeaderBlock(dos_header_block_));
  EXPECT_EQ(expected_nt_headers_size_, nt_headers_block_->size());
  EXPECT_EQ(expected_nt_headers_size_, nt_headers_block_->data_size());
  EXPECT_EQ(block_graph_.sections().size(),
            nt_headers->FileHeader.NumberOfSections);
}

}  // namespace transforms
}  // namespace pe
