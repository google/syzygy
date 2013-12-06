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

#include "syzygy/pe/pe_relinker_util.h"

#include "base/file_util.h"
#include "base/utf_string_conversions.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/common/defs.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pdb/pdb_reader.h"
#include "syzygy/pdb/pdb_util.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/pe_data.h"
#include "syzygy/pe/unittest_util.h"

namespace pe {

namespace {

using block_graph::BlockGraph;
using block_graph::ConstTypedBlock;
using block_graph::OrderedBlockGraph;

typedef ConstTypedBlock<IMAGE_DATA_DIRECTORY> ImageDataDirectory;
typedef ConstTypedBlock<IMAGE_DEBUG_DIRECTORY> ImageDebugDirectory;
typedef ConstTypedBlock<IMAGE_DOS_HEADER> DosHeader;
typedef ConstTypedBlock<IMAGE_NT_HEADERS> NtHeaders;

class PERelinkerUtilTest : public testing::PELibUnitTest {
  typedef testing::PELibUnitTest Super;

 public:
  PERelinkerUtilTest() : image_layout_(&block_graph_) {
  }

  void SetUp() {
    Super::SetUp();

    input_dll_ = testing::GetExeRelativePath(testing::kTestDllName);
    input_pdb_ = testing::GetExeRelativePath(testing::kTestDllPdbName);

    ASSERT_NO_FATAL_FAILURE(CreateTemporaryDir(&temp_dir_));
    temp_dll_ = temp_dir_.Append(testing::kTestDllName);
    temp_pdb_ = temp_dir_.Append(testing::kTestDllPdbName);
  }

  void CreateFile(const base::FilePath& file) {
    file_util::ScopedFILE f(file_util::OpenFile(file, "wb"));
  }

  void DecomposeTestDll() {
    ASSERT_TRUE(pe_file_.Init(input_dll_));
    pe::Decomposer decomposer(pe_file_);
    ASSERT_TRUE(decomposer.Decompose(&image_layout_));
    dos_header_block_ = image_layout_.blocks.GetBlockByAddress(
        core::RelativeAddress(0));
    ASSERT_TRUE(dos_header_block_ != NULL);
  }

  bool BlockGraphHasSyzygyMetadataSection() const {
    BlockGraph::SectionMap::const_iterator it =
        block_graph_.sections().begin();
    for (; it != block_graph_.sections().end(); ++it) {
      if (it->second.name() == common::kSyzygyMetadataSectionName)
        return true;
    }
    return false;
  }

  void CheckPdbInfo(const base::FilePath& pdb_path,
                    const GUID& pdb_guid) {
    DosHeader dos_header;
    ASSERT_TRUE(dos_header.Init(0, dos_header_block_));

    NtHeaders nt_headers;
    ASSERT_TRUE(dos_header.Dereference(dos_header->e_lfanew, &nt_headers));

    const IMAGE_DATA_DIRECTORY* data_dir =
        nt_headers->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_DEBUG;
    ImageDebugDirectory debug_dir;
    ASSERT_TRUE(nt_headers.Dereference(data_dir->VirtualAddress, &debug_dir));

    bool seen_cv_record = false;
    for (size_t i = 0; i < debug_dir.ElementCount(); ++i) {
      if (debug_dir[i].Type != IMAGE_DEBUG_TYPE_CODEVIEW)
        continue;

      ASSERT_FALSE(seen_cv_record);
      seen_cv_record = true;

      ASSERT_LE(sizeof(CvInfoPdb70), debug_dir[i].SizeOfData);
      ConstTypedBlock<CvInfoPdb70> pdb_info;
      ASSERT_TRUE(debug_dir.Dereference(debug_dir[i].AddressOfRawData,
                                        &pdb_info));

      ASSERT_EQ(pdb_guid, pdb_info->signature);

      std::wstring pdb_file_name =  base::UTF8ToWide(pdb_info->pdb_file_name);
      ASSERT_EQ(pdb_path.value(), pdb_file_name);
    }
  }

  PETransformPolicy policy_;
  base::FilePath input_dll_;
  base::FilePath input_pdb_;
  base::FilePath temp_dir_;
  base::FilePath temp_dll_;
  base::FilePath temp_pdb_;

  pe::PEFile pe_file_;
  ImageLayout image_layout_;
  BlockGraph block_graph_;
  BlockGraph::Block* dos_header_block_;
};

}  // namespace

TEST_F(PERelinkerUtilTest, ValidateAndInferPathsInferPdbPaths) {
  base::FilePath input_pdb, output_pdb;

  EXPECT_TRUE(ValidateAndInferPaths(
      input_dll_, temp_dll_, false, &input_pdb, &output_pdb));
  EXPECT_FALSE(input_pdb.empty());
  EXPECT_FALSE(output_pdb.empty());

  input_pdb.clear();
  output_pdb.clear();
  EXPECT_TRUE(ValidateAndInferPaths(
      input_dll_, temp_dll_, true, &input_pdb, &output_pdb));
  EXPECT_FALSE(input_pdb.empty());
  EXPECT_FALSE(output_pdb.empty());
}

TEST_F(PERelinkerUtilTest, ValidateAndInferPathsAllSpecified) {
  EXPECT_TRUE(ValidateAndInferPaths(
      input_dll_, temp_dll_, false, &input_pdb_, &temp_pdb_));
}

TEST_F(PERelinkerUtilTest, ValidateAndInferPathsMissingInputPdb) {
  base::FilePath output_pdb;
  EXPECT_FALSE(ValidateAndInferPaths(
      input_dll_, temp_dll_, false, &temp_pdb_, &output_pdb));
}

TEST_F(PERelinkerUtilTest, ValidateAndInferPathsMismatchedInputPdb) {
  base::FilePath output_pdb;
  CreateFile(temp_pdb_);
  EXPECT_FALSE(ValidateAndInferPaths(
      input_dll_, temp_pdb_, false, &input_pdb_, &output_pdb));
}

TEST_F(PERelinkerUtilTest, ValidateAndInferPathsExistingModule) {
  CreateFile(temp_dll_);

  EXPECT_FALSE(ValidateAndInferPaths(
      input_dll_, temp_dll_, false, &input_pdb_, &temp_pdb_));

  EXPECT_TRUE(ValidateAndInferPaths(
      input_dll_, temp_dll_, true, &input_pdb_, &temp_pdb_));
}

TEST_F(PERelinkerUtilTest, ValidateAndInferPathsExistingPdb) {
  CreateFile(temp_pdb_);

  EXPECT_FALSE(ValidateAndInferPaths(
      input_dll_, temp_dll_, false, &input_pdb_, &temp_pdb_));

  EXPECT_TRUE(ValidateAndInferPaths(
      input_dll_, temp_dll_, true, &input_pdb_, &temp_pdb_));
}

TEST_F(PERelinkerUtilTest, ValidateAndInferPathsInPlaceModule) {
  base::FilePath output_dll = input_dll_;
  EXPECT_FALSE(ValidateAndInferPaths(
      input_dll_, output_dll, false, &input_pdb_, &temp_pdb_));
}

TEST_F(PERelinkerUtilTest, ValidateAndInferPathsInPlacePdb) {
  base::FilePath output_pdb = input_pdb_;
  EXPECT_FALSE(ValidateAndInferPaths(
      input_dll_, temp_dll_, false, &input_pdb_, &output_pdb));
}

TEST_F(PERelinkerUtilTest, ValidateAndInferPathsBothOutputsSame) {
  base::FilePath output_dll = temp_dll_;
  base::FilePath output_pdb = temp_dll_;
  EXPECT_FALSE(ValidateAndInferPaths(
      input_dll_, temp_dll_, false, &output_dll, &output_pdb));
}

TEST_F(PERelinkerUtilTest, FinalizeBlockGraphNoMetadata) {
  ASSERT_NO_FATAL_FAILURE(DecomposeTestDll());

  DosHeader dos_header;
  NtHeaders nt_headers;
  ASSERT_TRUE(dos_header.Init(0, dos_header_block_));
  ASSERT_TRUE(dos_header.Dereference(dos_header->e_lfanew, &nt_headers));
  size_t header_section_count = nt_headers->FileHeader.NumberOfSections;

  GUID guid = {};
  EXPECT_TRUE(FinalizeBlockGraph(input_dll_, temp_pdb_, guid, false,
                                 &policy_, &block_graph_, dos_header_block_));
  EXPECT_EQ(header_section_count, nt_headers->FileHeader.NumberOfSections);

  EXPECT_FALSE(BlockGraphHasSyzygyMetadataSection());
  ASSERT_NO_FATAL_FAILURE(CheckPdbInfo(temp_pdb_, guid));
}

TEST_F(PERelinkerUtilTest, FinalizeBlockGraphMetadata) {
  ASSERT_NO_FATAL_FAILURE(DecomposeTestDll());

  DosHeader dos_header;
  NtHeaders nt_headers;
  ASSERT_TRUE(dos_header.Init(0, dos_header_block_));
  ASSERT_TRUE(dos_header.Dereference(dos_header->e_lfanew, &nt_headers));
  size_t header_section_count = nt_headers->FileHeader.NumberOfSections;

  GUID guid = {};
  EXPECT_TRUE(FinalizeBlockGraph(input_dll_, temp_pdb_, guid, true,
                                 &policy_, &block_graph_, dos_header_block_));
  EXPECT_EQ(header_section_count + 1, nt_headers->FileHeader.NumberOfSections);

  EXPECT_TRUE(BlockGraphHasSyzygyMetadataSection());
  ASSERT_NO_FATAL_FAILURE(CheckPdbInfo(temp_pdb_, guid));
}

// This is more of an integration test, but the individual transforms and
// orderers are very thoroughly tested elsewhere.
TEST_F(PERelinkerUtilTest, FinalizeOrderedBlockGraphAndBuildImageLayout) {
  ASSERT_NO_FATAL_FAILURE(DecomposeTestDll());
  OrderedBlockGraph obg(&block_graph_);

  // Move the DOS header block out of place.
  BlockGraph::Section* section = block_graph_.FindSection(".text");
  obg.PlaceAtHead(section);
  obg.PlaceAtHead(section, dos_header_block_);
  ASSERT_EQ(dos_header_block_,
            obg.ordered_section(section).ordered_blocks().front());

  EXPECT_TRUE(FinalizeOrderedBlockGraph(&obg, dos_header_block_));

  // Ensure the DOS header block is no longer first. The section itself should
  // still be first.
  EXPECT_NE(dos_header_block_,
            obg.ordered_section(section).ordered_blocks().front());

  // Build the layout and ensure it is as expected.
  size_t kPadding = 8;
  size_t kCodeAlign = 16;
  ImageLayout image_layout(&block_graph_);
  EXPECT_TRUE(BuildImageLayout(kPadding, kCodeAlign, obg, dos_header_block_,
                               &image_layout));

  // Skip over header blocks.
  BlockGraph::AddressSpace::RangeMapConstIter it = image_layout.blocks.begin();
  while (it != image_layout.blocks.end() &&
         it->second->section() == BlockGraph::kInvalidSectionId) {
    ++it;
  }

  // We expect there to be blocks left.
  ASSERT_TRUE(it != image_layout.blocks.end());

  // Make sure the rest of all blocks respect the padding and alignment.
  BlockGraph::AddressSpace::RangeMapConstIter prev_it = it;
  ++it;
  while (it != image_layout.blocks.end()) {
    ASSERT_LE(prev_it->first.end() + kPadding, it->first.start());
    if (it->second->type() == BlockGraph::CODE_BLOCK)
      ASSERT_EQ(0u, it->first.start().value() % kCodeAlign);

    prev_it = it;
    ++it;
  }
}

// Again, this is more of an integration test as the individual PDB mutators
// are thoroughly tested elsewhere.
TEST_F(PERelinkerUtilTest, GetOmapRangeAndFinalizePdb) {
  ASSERT_NO_FATAL_FAILURE(DecomposeTestDll());

  RelativeAddressRange omap_range;
  GetOmapRange(image_layout_.sections, &omap_range);
  EXPECT_FALSE(omap_range.IsEmpty());

  ASSERT_TRUE(file_util::CopyFileW(input_dll_, temp_dll_));

  pdb::PdbFile pdb_file;
  pdb::PdbReader pdb_reader;
  ASSERT_TRUE(pdb_reader.Read(input_pdb_, &pdb_file));

  GUID guid = {};
  EXPECT_TRUE(FinalizePdbFile(input_dll_,
                              temp_dll_,
                              omap_range,
                              image_layout_,
                              guid,
                              true,   // augment_pdb.
                              false,  // strip_strings.
                              true,   // compress_pdb.
                              &pdb_file));

  pdb::PdbInfoHeader70 pdb_header;
  pdb::NameStreamMap pdb_name_stream_map;
  ASSERT_TRUE(pdb::ReadHeaderInfoStream(
      pdb_file, &pdb_header, &pdb_name_stream_map));

  EXPECT_EQ(guid, pdb_header.signature);
}

}  // namespace pe
