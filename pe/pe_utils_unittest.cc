// Copyright 2011 Google Inc.
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
#include "syzygy/pe/pe_utils.h"

#include "gtest/gtest.h"
#include "gmock/gmock.h"

namespace pe {

using core::BlockGraph;
using core::RelativeAddress;

namespace {

class PEUtilsTest : public testing::Test {
 public:
  PEUtilsTest()
      : nt_headers_block_(NULL),
        dos_header_block_(NULL),
        nt_headers_(NULL),
        dos_header_(NULL) {
  }

  virtual void SetUp() {
    // Create the NT headers block.
    ASSERT_NO_FATAL_FAILURE(CreateNtHeadersBlock());
    // And the DOS header block.
    ASSERT_NO_FATAL_FAILURE(CreateDosHeaderBlock());
  }

 protected:
  void CreateDosHeaderBlock();
  void CreateNtHeadersBlock();

  BlockGraph block_graph_;

  BlockGraph::Block* nt_headers_block_;
  BlockGraph::Block* dos_header_block_;
  IMAGE_DOS_HEADER* dos_header_;
  IMAGE_NT_HEADERS* nt_headers_;
};

void PEUtilsTest::CreateNtHeadersBlock() {
  nt_headers_block_ = block_graph_.AddBlock(BlockGraph::DATA_BLOCK,
                                            sizeof(IMAGE_NT_HEADERS),
                                            "NT Headers");
  ASSERT_TRUE(nt_headers_block_ != NULL);

  nt_headers_ = reinterpret_cast<IMAGE_NT_HEADERS*>(
      nt_headers_block_->AllocateData(sizeof(IMAGE_NT_HEADERS)));
  ASSERT_TRUE(nt_headers_ != NULL);

  nt_headers_->Signature = IMAGE_NT_SIGNATURE;
  nt_headers_->FileHeader.SizeOfOptionalHeader =
      sizeof(nt_headers_->OptionalHeader);
  nt_headers_->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR_MAGIC;
}

void PEUtilsTest::CreateDosHeaderBlock() {
  dos_header_block_ = block_graph_.AddBlock(BlockGraph::DATA_BLOCK,
                                            sizeof(IMAGE_DOS_HEADER),
                                            "DOS Header");
  ASSERT_TRUE(dos_header_block_ != NULL);

  dos_header_ = reinterpret_cast<IMAGE_DOS_HEADER*>(
          dos_header_block_->AllocateData(dos_header_block_->size()));
  ASSERT_TRUE(dos_header_ != NULL);

  // Set the correct magic constants in the manufactured DOS header.
  dos_header_->e_magic = IMAGE_DOS_SIGNATURE;
  // Set the "DOS File Size" headers.
  dos_header_->e_cblp = dos_header_block_->size() % 512;
  dos_header_->e_cp = dos_header_block_->size() / 512;
  if (dos_header_->e_cblp != 0)
    dos_header_->e_cp++;
  // Set the header paragraph size.
  dos_header_->e_cparhdr = dos_header_block_->size() / 16;

  if (nt_headers_block_ != NULL) {
    // Set the NT headers reference.
    dos_header_block_->SetReference(
        offsetof(IMAGE_DOS_HEADER, e_lfanew),
        BlockGraph::Reference(BlockGraph::RELATIVE_REF,
                              sizeof(RelativeAddress),
                              nt_headers_block_,
                              0));
  }
}

}  // namespace

TEST_F(PEUtilsTest, IsValidDosHeaderBlockSuccess) {
  // This DOS header should test valid.
  EXPECT_TRUE(IsValidDosHeaderBlock(dos_header_block_));
}

TEST_F(PEUtilsTest, IsValidDosHeaderBlockNoDataFails) {
  dos_header_block_->SetData(NULL, 0);
  EXPECT_FALSE(IsValidDosHeaderBlock(dos_header_block_));
}

TEST_F(PEUtilsTest, IsValidDosHeaderBlockTooShortFails) {
  dos_header_block_->ResizeData(sizeof(IMAGE_DOS_HEADER) - 1);
  dos_header_block_->set_size(sizeof(IMAGE_DOS_HEADER) - 1);
  EXPECT_FALSE(IsValidDosHeaderBlock(dos_header_block_));
}

TEST_F(PEUtilsTest, IsValidDosHeaderBlockInvalidMagicFails) {
  ++dos_header_->e_magic;
  EXPECT_FALSE(IsValidDosHeaderBlock(dos_header_block_));
}

TEST_F(PEUtilsTest, IsValidDosHeaderBlockInvalidDosFileSizeFails) {
  dos_header_->e_cp = 0;
  dos_header_->e_cblp = 0;
  EXPECT_FALSE(IsValidDosHeaderBlock(dos_header_block_));

  // This is invalid, as there are zero pages, and thus no last page.
  dos_header_->e_cblp = 10;
  EXPECT_FALSE(IsValidDosHeaderBlock(dos_header_block_));
}

TEST_F(PEUtilsTest, IsValidDosHeaderBlockInvalidHeaderSizeFails) {
  --dos_header_->e_cparhdr;
  EXPECT_FALSE(IsValidDosHeaderBlock(dos_header_block_));
}

TEST_F(PEUtilsTest, IsValidDosHeaderBlockInvalidNTHeaderRefFails) {
  // Set the NT headers reference to a non-zero offset.
  dos_header_block_->SetReference(
      offsetof(IMAGE_DOS_HEADER, e_lfanew),
      BlockGraph::Reference(BlockGraph::RELATIVE_REF,
                            sizeof(RelativeAddress),
                            nt_headers_block_,
                            10));
  EXPECT_FALSE(IsValidDosHeaderBlock(dos_header_block_));
}

TEST_F(PEUtilsTest, IsValidDosHeaderBlockNoNTHeaderRefFails) {
  // Clear the NT headers reference.
  dos_header_block_->RemoveReference(offsetof(IMAGE_DOS_HEADER, e_lfanew));
  EXPECT_FALSE(IsValidDosHeaderBlock(dos_header_block_));
}

TEST_F(PEUtilsTest, IsValidNtHeaderBlockSuccess) {
  // The NT headers are valid.
  EXPECT_TRUE(IsValidNtHeadersBlock(nt_headers_block_));
}

TEST_F(PEUtilsTest, IsValidNtHeaderBlockInvalidSigFails) {
  ++nt_headers_->Signature;
  // Invalid signature.
  EXPECT_FALSE(IsValidNtHeadersBlock(nt_headers_block_));
}

TEST_F(PEUtilsTest, IsValidNtHeaderBlockInvalidOptionalSigFails) {
  ++nt_headers_->OptionalHeader.Magic;
  // Invalid signature.
  EXPECT_FALSE(IsValidNtHeadersBlock(nt_headers_block_));
}

TEST_F(PEUtilsTest, IsValidNtHeaderBlockInvalidOptionalSizeFails) {
  ++nt_headers_->FileHeader.SizeOfOptionalHeader;
  // Invalid signature.
  EXPECT_FALSE(IsValidNtHeadersBlock(nt_headers_block_));
}

TEST_F(PEUtilsTest, GetNtHeadersBlockFromDosHeaderBlock) {
  ASSERT_EQ(nt_headers_block_,
            GetNtHeadersBlockFromDosHeaderBlock(dos_header_block_));
}

TEST_F(PEUtilsTest, GetNtHeadersBlockFromDosHeaderBlockConst) {
  ASSERT_EQ(nt_headers_block_,
            GetNtHeadersBlockFromDosHeaderBlock(
                const_cast<const BlockGraph::Block*>(dos_header_block_)));
}

}  // namespace pe
