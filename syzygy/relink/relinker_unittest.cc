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

const int kPageSize = 4096;

class RelinkerTest : public testing::Test {
 public:
  void CreateTemporaryDir(FilePath* temp_dir) {
    ASSERT_TRUE(file_util::CreateNewTempDirectory(L"", temp_dir));
    temp_dirs_.push_back(*temp_dir);
  }

  void TearDown() {
    for (uint32 i = 0; i < temp_dirs_.size(); ++i) {
      file_util::Delete(temp_dirs_[i], true);
    }
  }

 protected:
  std::vector<const FilePath> temp_dirs_;
};

class OffsetRelinker : public Relinker {
 public:
  OffsetRelinker(const BlockGraph::AddressSpace& original_addr_space,
                 BlockGraph* block_graph)
      : Relinker(original_addr_space, block_graph) {
  }

  static void Relink(const FilePath& input_dll_path,
                     const FilePath& input_pdb_path,
                     const FilePath& output_dll_path,
                     const FilePath& output_pdb_path,
                     uint32 num_offsets) {
    // Decompose.
    pe::PEFile input_dll;
    ASSERT_TRUE(input_dll.Init(input_dll_path));

    pe::Decomposer decomposer(input_dll, input_dll_path);
    pe::Decomposer::DecomposedImage decomposed;
    ASSERT_TRUE(
        decomposer.Decompose(&decomposed, NULL,
                             pe::Decomposer::STANDARD_DECOMPOSITION));

    // Build the image.
    OffsetRelinker relinker(decomposed.address_space, &decomposed.image);
    ASSERT_TRUE(relinker.Initialize(decomposed.header.nt_headers));
    ASSERT_TRUE(relinker.CopySectionsAndOffsetCode());
    ASSERT_TRUE(relinker.UpdateDebugInformation(
        decomposed.header.data_directory[IMAGE_DIRECTORY_ENTRY_DEBUG]));
    ASSERT_TRUE(relinker.CopyDataDirectory(decomposed.header));
    ASSERT_TRUE(relinker.FinalizeImageHeaders(decomposed.header));

    // Write the image and pdb.
    ASSERT_TRUE(relinker.WriteImage(output_dll_path));
    ASSERT_TRUE(relinker.WriteOffsetPDBFile(input_pdb_path, output_pdb_path,
                                            num_offsets));
  }

 private:
  bool CopySectionsAndOffsetCode() {
    // Copy the sections from the decomposed image to the new one, save for the
    // .relocs section. Add a section before any code section to create an
    // offset.
    for (size_t i = 0; i < original_num_sections() - 1; ++i) {
      const IMAGE_SECTION_HEADER& section = original_sections()[i];
      if (section.Characteristics & IMAGE_SCN_CNT_CODE) {
        const char* name = reinterpret_cast<const char*>(section.Name);
        std::string name_str(name, strnlen(name, arraysize(section.Name)));
        name_str.append("_offset");
        builder().AddSegment(name_str.c_str(), kPageSize, kPageSize, 0);
      }
      if (!CopySection(section)) {
        LOG(ERROR) << "Unable to copy section";
        return false;
      }
    }

    return true;
  }

  bool WriteOffsetPDBFile(const FilePath& input_path,
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
};

}  // namespace

TEST_F(RelinkerTest, Relink) {
  FilePath temp_dir;
  ASSERT_NO_FATAL_FAILURE(CreateTemporaryDir(&temp_dir));
  FilePath output_dll_path = temp_dir.Append(testing::kDllName);
  FilePath output_pdb_path = temp_dir.Append(testing::kDllPdbName);

  ASSERT_TRUE(
      Relinker::Relink(testing::GetExeRelativePath(testing::kDllName),
                       testing::GetExeRelativePath(testing::kDllPdbName),
                       output_dll_path,
                       output_pdb_path,
                       0));

  ASSERT_NO_FATAL_FAILURE(testing::CheckTestDll(output_dll_path));
}

TEST_F(RelinkerTest, CodeOffset) {
  // In this test, we add an additional code section of one page size in front
  // of the original code sections, offsetting each block by one page, write the
  // new image and pdb file, and then make sure that we can decompose the
  // relinked image. We then do this over multiple iterations.
  FilePath input_dll_path = testing::GetExeRelativePath(testing::kDllName);
  FilePath input_pdb_path = testing::GetExeRelativePath(testing::kDllPdbName);

  for (uint32 i = 0; i < 5; ++i) {
    FilePath temp_dir;
    ASSERT_NO_FATAL_FAILURE(CreateTemporaryDir(&temp_dir));
    FilePath output_dll_path = temp_dir.Append(testing::kDllName);
    FilePath output_pdb_path = temp_dir.Append(testing::kDllPdbName);

    OffsetRelinker::Relink(input_dll_path,
                           input_pdb_path,
                           output_dll_path,
                           output_pdb_path,
                           i + 1);

    ASSERT_NO_FATAL_FAILURE(testing::CheckTestDll(output_dll_path));

    input_dll_path = output_dll_path;
    input_pdb_path = output_pdb_path;
  }
}
