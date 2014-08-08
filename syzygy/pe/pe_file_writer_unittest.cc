// Copyright 2011 Google Inc. All Rights Reserved.
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

#include "syzygy/pe/pe_file_writer.h"

#include "base/file_util.h"
#include "base/path_service.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/unittest_util.h"

namespace pe {

namespace {

using block_graph::BlockGraph;
using core::RelativeAddress;

class PEFileWriterTest: public testing::PELibUnitTest {
  // Add customizations here.
};

}  // namespace

TEST_F(PEFileWriterTest, LoadOriginalImage) {
  // This test baselines the other test(s) that operate on mutated, copied
  // versions of the DLLs.
  base::FilePath image_path(testing::GetExeRelativePath(testing::kTestDllName));
  ASSERT_NO_FATAL_FAILURE(CheckTestDll(image_path));
}

TEST_F(PEFileWriterTest, RewriteAndLoadImage) {
  // Create a temporary file we can write the new image to.
  base::FilePath temp_dir;
  ASSERT_NO_FATAL_FAILURE(CreateTemporaryDir(&temp_dir));
  base::FilePath temp_file = temp_dir.Append(testing::kTestDllName);

  // Decompose the original test image.
  PEFile image_file;
  base::FilePath image_path(testing::GetExeRelativePath(testing::kTestDllName));
  ASSERT_TRUE(image_file.Init(image_path));

  Decomposer decomposer(image_file);
  block_graph::BlockGraph block_graph;
  pe::ImageLayout image_layout(&block_graph);
  ASSERT_TRUE(decomposer.Decompose(&image_layout));

  PEFileWriter writer(image_layout);

  ASSERT_TRUE(writer.WriteImage(temp_file));
  ASSERT_NO_FATAL_FAILURE(CheckTestDll(temp_file));
}

TEST_F(PEFileWriterTest, UpdateFileChecksum) {
  base::FilePath temp_dir;
  ASSERT_NO_FATAL_FAILURE(CreateTemporaryDir(&temp_dir));

  // Verify that the function fails on non-existent paths.
  base::FilePath executable = temp_dir.Append(L"executable_file.exe");
  EXPECT_FALSE(PEFileWriter::UpdateFileChecksum(executable));

  // Verify that the function fails for non-image files.
  base::ScopedFILE file(base::OpenFile(executable, "wb"));
  // Grow the file to 16K.
  ASSERT_EQ(0, fseek(file.get(), 16 * 1024, SEEK_SET));
  file.reset();
  EXPECT_FALSE(PEFileWriter::UpdateFileChecksum(executable));

  // Make a copy of our test DLL and check that we work on that.
  base::FilePath input_path(testing::GetExeRelativePath(testing::kTestDllName));
  base::FilePath image_path(temp_dir.Append(testing::kTestDllName));
  EXPECT_TRUE(base::CopyFile(input_path, image_path));
  EXPECT_TRUE(PEFileWriter::UpdateFileChecksum(image_path));
}

namespace {

bool WriteImageLayout(const ImageLayout& image_layout,
                      const base::FilePath& path) {
  PEFileWriter pe_file_writer(image_layout);
  return pe_file_writer.WriteImage(path);
}

}  // namespace

TEST_F(PEFileWriterTest, FailsForInconsistentImage) {
  base::FilePath temp_dir;
  ASSERT_NO_FATAL_FAILURE(CreateTemporaryDir(&temp_dir));
  base::FilePath temp_file = temp_dir.Append(L"foo.dll");

  PEFile image_file;
  base::FilePath image_path(testing::GetExeRelativePath(testing::kTestDllName));
  ASSERT_TRUE(image_file.Init(image_path));

  Decomposer decomposer(image_file);
  block_graph::BlockGraph block_graph;
  pe::ImageLayout image_layout(&block_graph);
  ASSERT_TRUE(decomposer.Decompose(&image_layout));

  BlockGraph::Block* dos_header_block =
      image_layout.blocks.GetBlockByAddress(RelativeAddress(0));
  BlockGraph::Block* nt_headers_block =
      GetNtHeadersBlockFromDosHeaderBlock(dos_header_block);
  ASSERT_TRUE(nt_headers_block != NULL);

  IMAGE_DOS_HEADER* dos_header =
      reinterpret_cast<IMAGE_DOS_HEADER*>(dos_header_block->GetMutableData());
  IMAGE_NT_HEADERS* nt_headers =
      reinterpret_cast<IMAGE_NT_HEADERS*>(nt_headers_block->GetMutableData());
  IMAGE_SECTION_HEADER* section_headers = IMAGE_FIRST_SECTION(nt_headers);

  ASSERT_TRUE(nt_headers != NULL);

  // To start with, the image should be perfectly writable.
  EXPECT_TRUE(WriteImageLayout(image_layout, temp_file));

  // Invalid DOS header.
  dos_header->e_magic ^= 0xF00D;
  EXPECT_FALSE(WriteImageLayout(image_layout, temp_file));
  dos_header->e_magic ^= 0xF00D;

  // Section count mismatch.
  --nt_headers->FileHeader.NumberOfSections;
  EXPECT_FALSE(WriteImageLayout(image_layout, temp_file));
  ++nt_headers->FileHeader.NumberOfSections;

  // Inconsistent section headers and image layout.
  section_headers[0].SizeOfRawData += 10 * 1024;
  EXPECT_FALSE(WriteImageLayout(image_layout, temp_file));

  // Make the section headers and image layout consistent again, while making
  // the first section overlap the second on disk.
  image_layout.sections[0].data_size += 10 * 1024;

  // Overlapping sections on disk.
  EXPECT_FALSE(WriteImageLayout(image_layout, temp_file));
  section_headers[0].SizeOfRawData -= 10 * 1024;
  image_layout.sections[0].data_size -= 10 * 1024;

  // Overlapping sections in memory.
  section_headers[0].Misc.VirtualSize += 10 * 1024;
  image_layout.sections[0].size += 10 * 1024;
  EXPECT_FALSE(WriteImageLayout(image_layout, temp_file));
  section_headers[0].Misc.VirtualSize -= 10 * 1024;
  image_layout.sections[0].size -= 10 * 1024;

  // Unaligned section start on disk.
  section_headers[0].PointerToRawData++;
  EXPECT_FALSE(WriteImageLayout(image_layout, temp_file));
  section_headers[0].PointerToRawData--;

  // Unaligned section start in memory.
  section_headers[0].VirtualAddress++;
  image_layout.sections[0].addr += 1;
  EXPECT_FALSE(WriteImageLayout(image_layout, temp_file));
  section_headers[0].VirtualAddress--;
  image_layout.sections[0].addr -= 1;

  size_t last_section_id = nt_headers->FileHeader.NumberOfSections - 1;
  size_t file_alignment = nt_headers->OptionalHeader.FileAlignment;
  RelativeAddress last_section_start(
      section_headers[last_section_id].VirtualAddress);
  RelativeAddress last_section_end = last_section_start +
      section_headers[last_section_id].Misc.VirtualSize;
  RelativeAddress new_block_addr = last_section_end.AlignUp(file_alignment);

  BlockGraph::Block* new_block = block_graph.AddBlock(
      BlockGraph::DATA_BLOCK, 2 * file_alignment, "new block");
  new_block->set_section(last_section_id);

  // Block that is outside its section entirely.
  ASSERT_TRUE(image_layout.blocks.InsertBlock(new_block_addr, new_block));
  EXPECT_FALSE(WriteImageLayout(image_layout, temp_file));

  // Block in virtual portion of section with explicit data.
  section_headers[last_section_id].SizeOfRawData =
      new_block_addr - last_section_start;
  section_headers[last_section_id].Misc.VirtualSize =
      new_block_addr + new_block->size() - last_section_start;
  image_layout.sections.back().data_size =
      section_headers[last_section_id].SizeOfRawData;
  image_layout.sections.back().size =
      section_headers[last_section_id].Misc.VirtualSize;
  ASSERT_TRUE(new_block->AllocateData(file_alignment) != NULL);
  ::memset(new_block->GetMutableData(), 0xCC, new_block->data_size());
  EXPECT_FALSE(WriteImageLayout(image_layout, temp_file));

  // Extending the initialized data size of the section to cover the initialized
  // portion of the block should allow it to be written, even though half of it
  // is implicit.
  section_headers[last_section_id].SizeOfRawData += file_alignment;
  image_layout.sections.back().data_size += file_alignment;
  EXPECT_TRUE(WriteImageLayout(image_layout, temp_file));

  // Finally, having a FileOffsetAddress reference to a location in implicit
  // data should fail.
  ASSERT_TRUE(new_block->SetReference(
      0,
      BlockGraph::Reference(BlockGraph::FILE_OFFSET_REF,
                            4,
                            new_block,
                            file_alignment,
                            file_alignment)));
  EXPECT_FALSE(WriteImageLayout(image_layout, temp_file));
}

}  // namespace pe
