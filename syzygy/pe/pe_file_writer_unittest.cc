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
#include "syzygy/pe/pe_file_writer.h"

#include "base/file_util.h"
#include "base/path_service.h"
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/pe/unittest_util.h"

namespace {

using pe::Decomposer;
using pe::PEFile;

class PEFileWriterTest: public testing::Test {
 public:
  PEFileWriterTest() : nt_headers_(NULL), section_headers_(NULL) {
  }

  void SetUp() {
    // Create a temporary file we can write the new image to.
    ASSERT_TRUE(file_util::CreateTemporaryFile(&temp_file_));

    // Decompose the original test image.
    FilePath image_path(testing::GetExeRelativePath(testing::kDllName));
    ASSERT_TRUE(image_file_.Init(image_path));

    Decomposer decomposer(image_file_, image_path);
    ASSERT_TRUE(decomposer.Decompose(&decomposed_image_));

    ASSERT_GE(decomposed_image_.header.nt_headers->data_size(),
              sizeof(IMAGE_NT_HEADERS));
    nt_headers_ = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        decomposed_image_.header.nt_headers->data());

    ASSERT_EQ(sizeof(*nt_headers_) + sizeof(IMAGE_SECTION_HEADER) *
        nt_headers_->FileHeader.NumberOfSections,
            decomposed_image_.header.nt_headers->data_size());
    section_headers_ = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
        nt_headers_ + 1);
  }

  void TearDown() {
    // Scrap our temp file.
    file_util::Delete(temp_file_, false);
  }

 protected:
  FilePath temp_file_;
  PEFile image_file_;
  Decomposer::DecomposedImage decomposed_image_;
  const IMAGE_NT_HEADERS* nt_headers_;
  const IMAGE_SECTION_HEADER* section_headers_;
};

}  // namespace

namespace pe {

TEST_F(PEFileWriterTest, LoadOriginalImage) {
  // This test baselines the other test(s) that operate on mutated, copied
  // versions of the DLLs.
  FilePath image_path(testing::GetExeRelativePath(testing::kDllName));
  ASSERT_NO_FATAL_FAILURE(testing::CheckTestDll(image_path));
}

TEST_F(PEFileWriterTest, RewriteAndLoadImage) {
  PEFileWriter writer(decomposed_image_.address_space,
                      nt_headers_,
                      section_headers_);
  ASSERT_TRUE(writer.WriteImage(temp_file_));
  ASSERT_NO_FATAL_FAILURE(testing::CheckTestDll(temp_file_));
}

}  // namespace pe
