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
#include "sawbuck/image_util/pe_file_writer.h"

#include "base/file_util.h"
#include "base/path_service.h"
#include "base/native_library.h"
#include "gtest/gtest.h"
#include "sawbuck/image_util/decomposer.h"
#include <algorithm>
#include <map>
#include <set>
#include <vector>

namespace {

using image_util::RelativeAddress;
using image_util::Decomposer;
using image_util::BlockGraph;
using image_util::PEFile;
typedef std::vector<uint8> SectionBuffer;

FilePath GetExeRelativePath(const wchar_t* image_name) {
  FilePath exe_dir;
  PathService::Get(base::DIR_EXE, &exe_dir);

  return exe_dir.Append(image_name);
}

const wchar_t kDllName[] = L"test_dll.dll";

class PEFileWriterTest: public testing::Test {
 public:
  PEFileWriterTest() {
  }

  void SetUp() {
    // Create a temporary file we can write the new image to.
    ASSERT_TRUE(file_util::CreateTemporaryFile(&temp_file_));

    // Decompose the original test image.
    FilePath image_path(GetExeRelativePath(kDllName));
    ASSERT_TRUE(image_file_.Init(image_path));

    Decomposer decomposer(image_file_, image_path);
    ASSERT_TRUE(decomposer.Decompose(&decomposed_image_));
  }

  void TearDown() {
    // Scrap our temp file.
    file_util::Delete(temp_file_, false);
  }

 protected:
  FilePath temp_file_;
  PEFile image_file_;
  Decomposer::DecomposedImage decomposed_image_;
};

}  // namespace

namespace image_util {

TEST_F(PEFileWriterTest, LoadOriginalImage) {
  // This test baselines the other test(s) that operate on mutated, copied
  // versions of the DLLs.
  FilePath image_path(GetExeRelativePath(kDllName));
  HMODULE loaded = ::LoadLibrary(image_path.value().c_str());
  ASSERT_TRUE(loaded != NULL);
  ::FreeLibrary(loaded);
}

TEST_F(PEFileWriterTest, RewriteAndLoadImage) {
  PEFileWriter writer(decomposed_image_.address_space,
                      decomposed_image_.header);
  ASSERT_TRUE(writer.WriteImage(temp_file_));

  HMODULE loaded = ::LoadLibrary(temp_file_.value().c_str());
  ASSERT_TRUE(loaded != NULL);
  ::FreeLibrary(loaded);

  // TODO(siggi): Excercise the exports etc.
}

}  // namespace image_util
