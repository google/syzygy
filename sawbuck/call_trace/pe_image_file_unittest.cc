// Copyright 2010 Google Inc.
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
#include "sawbuck/call_trace/pe_image_file.h"
#include "base/file_path.h"
#include "base/file_util.h"
#include "base/path_service.h"
#include "gtest/gtest.h"

namespace {

FilePath GetTestImagePath(const wchar_t* image_name) {
  FilePath exe_dir;
  PathService::Get(base::DIR_EXE, &exe_dir);

  return exe_dir.Append(image_name);
}

const wchar_t kTestImage1[] = L"test_image1.dll";
const wchar_t kTestImage2[] = L"test_image2.dll";

const size_t kPageSize = 4096;
const size_t kSectionGrowBy = 10240;

class PEImageFileTest: public testing::Test {
 public:
  virtual void SetUp() {
    ASSERT_TRUE(file_util::CreateNewTempDirectory(L"", &temp_dir_));
  }

  virtual void TearDown() {
    if (!temp_dir_.empty())
      file_util::Delete(temp_dir_, true);
  }

  const FilePath& temp_dir() const { return temp_dir_; }

 private:
  FilePath temp_dir_;
};

}  // namespace

TEST(AddressTransformerTest, Creation) {
  PEImageFile::AddressTransformer transformer;

  ASSERT_FALSE(transformer.initialized());
}

TEST(AddressTransformerTest, Transform) {
  PEImageFile image;
  ASSERT_TRUE(image.Read(GetTestImagePath(kTestImage1)));

  PEImageFile::AddressTransformer transformer;
  transformer.SetOriginalImageFile(image);

  // Grow the first section by 10K.
  IMAGE_SECTION_HEADER hdr = image.section_headers()[0];
  size_t section_size = hdr.Misc.VirtualSize;
  ASSERT_TRUE(image.ResizeSection(0, section_size + kSectionGrowBy));
  ASSERT_TRUE(transformer.SetNewImageFile(image));

  // Should now be fully initialized.
  EXPECT_TRUE(transformer.initialized());

  // Test relative addresses.
  {
    // The zero address should never translate.
    PEImageFile::RelativeAddress rel;
    EXPECT_FALSE(transformer.Transform(&rel));

    // The first image section has not moved.
    rel.set_value(hdr.VirtualAddress);
    EXPECT_FALSE(transformer.Transform(&rel));

    // Now try an address a page beyond the original image section.
    rel.set_value(hdr.VirtualAddress + hdr.Misc.VirtualSize + kPageSize);
    PEImageFile::RelativeAddress orig(rel);
    EXPECT_TRUE(transformer.Transform(&rel));
    // In current implementation, the sections grow by page size increments.
    // For 10K, that means the image section must grow by two pages min.
    EXPECT_GE(rel - orig, (kSectionGrowBy / kPageSize) * kPageSize);
    EXPECT_LE(rel - orig, kSectionGrowBy + kPageSize);
  }

  // Test absolute addresses.
  {
    size_t image_base = image.nt_headers()->OptionalHeader.ImageBase;

    // The base address should never translate.
    PEImageFile::AbsoluteAddress abs(image_base);
    EXPECT_FALSE(transformer.Transform(&abs));

    // The first image section has not moved.
    abs.set_value(image_base + hdr.VirtualAddress);
    EXPECT_FALSE(transformer.Transform(&abs));

    // Now try an address a page beyond the original image section.
    abs.set_value(image_base + hdr.VirtualAddress +
        hdr.Misc.VirtualSize + kPageSize);
    PEImageFile::AbsoluteAddress orig(abs);
    EXPECT_TRUE(transformer.Transform(&abs));
    EXPECT_GE(abs - orig, kSectionGrowBy);
    EXPECT_LE(abs - orig, kSectionGrowBy + kPageSize);
  }

  // TODO(siggi): test disk addresses.
}

TEST_F(PEImageFileTest, ResizeSection) {
  PEImageFile image;
  ASSERT_TRUE(image.Read(GetTestImagePath(kTestImage1)));

  // Grow the first section by just over a page.
  IMAGE_SECTION_HEADER& hdr = image.section_headers()[0];
  size_t new_size = hdr.Misc.VirtualSize + 4097;
  EXPECT_TRUE(image.ResizeSection(0, new_size));

  // Check that it grew as expected.
  EXPECT_EQ(new_size, hdr.Misc.VirtualSize);

  // Write the image back to disk.
  FilePath output_path(temp_dir().Append(kTestImage1));
  ASSERT_TRUE(image.Write(output_path));

  // Try to load it and assert we're successful. This excercises the
  // CRT entry point, the image load configuration, and the DLL
  // entry point. If the image load configuration directory is corrupted,
  // this will fail to load the DLL and may crash.
  HMODULE test_image = ::LoadLibrary(output_path.value().c_str());
  ASSERT_TRUE(test_image != NULL);
  ::FreeLibrary(test_image);
}

// TODO(siggi): more tests
