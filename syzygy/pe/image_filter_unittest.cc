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

#include "syzygy/pe/image_filter.h"

#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/unittest_util.h"

namespace pe {

namespace {

class ImageFilterTest : public testing::PELibUnitTest {
 public:
  ImageFilterTest() : dummy_path(L"C:\\this\\path\\does-not-exist.exe") {
  }

  virtual void SetUp() OVERRIDE {
    test_dll_path = testing::GetExeRelativePath(testing::kTestDllName);
  }

  void InitPeFileAndSignature() {
    EXPECT_TRUE(pe_file.Init(test_dll_path));
    pe_file.GetSignature(&pe_signature);
  }

  const base::FilePath dummy_path;
  base::FilePath test_dll_path;

  PEFile pe_file;
  PEFile::Signature pe_signature;
};

}  // namespace

TEST_F(ImageFilterTest, Init) {
  ImageFilter f1;
  EXPECT_FALSE(f1.Init(dummy_path));
  EXPECT_TRUE(f1.Init(test_dll_path));

  InitPeFileAndSignature();

  ImageFilter f2;
  f2.Init(pe_file);
  EXPECT_EQ(f1.signature, f2.signature);
  EXPECT_EQ(f1.filter, f2.filter);

  ImageFilter f3;
  f3.Init(pe_signature);
  EXPECT_EQ(f1.signature, f3.signature);
  EXPECT_EQ(f1.filter, f3.filter);
}

TEST_F(ImageFilterTest, IsForModule) {
  ImageFilter f1;
  EXPECT_TRUE(f1.Init(test_dll_path));

  ImageFilter f2;
  f2.signature.base_address.set_value(0x01000000);
  f2.signature.module_checksum = 0x12345678;
  f2.signature.module_size = 8374832;
  f2.signature.module_time_date_stamp = 0xBAADF00D;
  f2.signature.path = dummy_path.value();

  EXPECT_FALSE(f1.IsForModule(dummy_path));
  EXPECT_TRUE(f1.IsForModule(test_dll_path));
  EXPECT_FALSE(f2.IsForModule(test_dll_path));

  InitPeFileAndSignature();

  EXPECT_TRUE(f1.IsForModule(pe_file));
  EXPECT_FALSE(f2.IsForModule(pe_file));

  EXPECT_TRUE(f1.IsForModule(pe_signature));
  EXPECT_FALSE(f2.IsForModule(pe_signature));
}

TEST_F(ImageFilterTest, SaveToAndLoadFromJSON) {
  ImageFilter f1;
  EXPECT_TRUE(f1.Init(test_dll_path));

  // Mark some ranges so that the filter isn't empty.
  f1.filter.Mark(ImageFilter::Range(
      ImageFilter::RelativeAddress(0), 1024));
  f1.filter.Mark(ImageFilter::Range(
      ImageFilter::RelativeAddress(4096), 4096));
  f1.filter.Mark(ImageFilter::Range(
      ImageFilter::RelativeAddress(10240), 256));

  base::FilePath temp_dir;
  CreateTemporaryDir(&temp_dir);
  base::FilePath pretty_json_path = temp_dir.Append(L"test_dll_pretty.json");
  base::FilePath ugly_json_path = temp_dir.Append(L"test_dll_ugly.json");

  EXPECT_TRUE(f1.SaveToJSON(true, pretty_json_path));
  EXPECT_TRUE(f1.SaveToJSON(false, ugly_json_path));

  std::string pretty_json, ugly_json;
  base::ReadFileToString(pretty_json_path, &pretty_json);
  base::ReadFileToString(ugly_json_path, &ugly_json);
  EXPECT_LT(ugly_json.size(), pretty_json.size());

  ImageFilter f2;
  EXPECT_FALSE(f2.LoadFromJSON(dummy_path));
  EXPECT_TRUE(f2.LoadFromJSON(pretty_json_path));
  EXPECT_EQ(f1.signature, f2.signature);
  EXPECT_EQ(f1.filter, f2.filter);

  ImageFilter f3;
  EXPECT_TRUE(f3.LoadFromJSON(ugly_json_path));
  EXPECT_EQ(f1.signature, f3.signature);
  EXPECT_EQ(f1.filter, f3.filter);
}

}  // namespace pe
