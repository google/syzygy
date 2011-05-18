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

#include "syzygy/relink/relinker.h"
#include "base/file_util.h"
#include "gtest/gtest.h"
#include "syzygy/pdb/pdb_util.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/pe/unittest_util.h"

namespace {

const size_t kPageSize = 4096;

class OffsetRelinker : public Relinker {
 public:
  OffsetRelinker() {
    DCHECK_GE(max_padding_length(), kPageSize);
  }

  bool WriteOffsetPdbFile(const FilePath& input_path,
                          const FilePath& output_path,
                          int num_offsets) {
    // This creates a simple Omap offset. We know that the order of the blocks
    // hasn't changed, so we only need one Omap entry in each direction to show
    // where the blocks have moved to/from. The first code block starts at
    // 0x1000 in the original DLL, so we need one Omap entry offset by the
    // the number of offsets times the size of the offset (a page size). When we
    // decompose the new DLL, this also tests that the Decomposer/DIA are
    // reading the OMAP information properly.
    OMAP omap_to_entry = { 0x1000 + num_offsets * kPageSize, 0x1000 };
    std::vector<OMAP> omap_to;
    omap_to.push_back(omap_to_entry);

    OMAP omap_from_entry = { 0x1000, 0x1000 + num_offsets * kPageSize };
    std::vector<OMAP> omap_from;
    omap_from.push_back(omap_from_entry);

    return pdb::AddOmapStreamToPdbFile(input_path,
                                       output_path,
                                       new_image_guid(),
                                       omap_to,
                                       omap_from);
  }

 private:
  bool ReorderSection(const IMAGE_SECTION_HEADER& section) {
    // Create a dummy section to offset the original section.
    std::string section_name("o");
    section_name.append(GetSectionName(section));
    RelativeAddress start = builder().AddSegment(
        section_name.c_str(), kPageSize, kPageSize,
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ);
    BlockGraph::Block* block = builder().address_space().AddBlock(
        BlockGraph::CODE_BLOCK, start, kPageSize, "offset");
    block->set_data(padding_data());
    block->set_data_size(kPageSize);
    block->set_owns_data(false);

    // Copy the code section.
    if (!CopySection(section)) {
      LOG(ERROR) << "Unable to copy section";
      return false;
    }

    return true;
  }
};

}  // namespace

class RelinkerTest : public testing::PELibUnitTest {
  // Put any specializations here
};

TEST_F(RelinkerTest, OffsetCode) {
  // In this test, we add an additional code section of one page size in front
  // of the original code sections, offsetting each block by one page, write the
  // new image and pdb file, and then make sure that we can decompose the
  // relinked image. We then do this over multiple iterations.
  FilePath input_dll_path = GetExeRelativePath(kDllName);
  FilePath input_pdb_path = GetExeRelativePath(kDllPdbName);

  for (int i = 1; i <= 5; ++i) {
    FilePath temp_dir;
    ASSERT_NO_FATAL_FAILURE(CreateTemporaryDir(&temp_dir));
    FilePath output_dll_path = temp_dir.Append(kDllName);
    FilePath output_pdb_path = temp_dir.Append(kDllPdbName);

    OffsetRelinker relinker;
    ASSERT_TRUE(relinker.Relink(input_dll_path,
                                input_pdb_path,
                                output_dll_path,
                                output_pdb_path));
    ASSERT_TRUE(relinker.WriteOffsetPdbFile(input_pdb_path,
                                            output_pdb_path,
                                            i));

    ASSERT_NO_FATAL_FAILURE(CheckTestDll(output_dll_path));

    input_dll_path = output_dll_path;
    input_pdb_path = output_pdb_path;
  }
}
