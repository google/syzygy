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
#include "sawbuck/image_util/pe_file.h"
#include "base/file_path.h"
#include "base/native_library.h"
#include "base/path_service.h"
#include "base/string_util.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace {

FilePath GetExeRelativePath(const wchar_t* image_name) {
  FilePath exe_dir;
  PathService::Get(base::DIR_EXE, &exe_dir);

  return exe_dir.Append(image_name);
}

const wchar_t kDllName[] = L"test_dll.dll";

class PEFileTest: public testing::Test {
 public:
  PEFileTest() : test_dll_(NULL) {
  }

  virtual void SetUp() {
    FilePath test_dll = GetExeRelativePath(kDllName);
    test_dll_ = base::LoadNativeLibrary(GetExeRelativePath(kDllName));

    ASSERT_TRUE(image_file_.Init(test_dll));
  }

  virtual void TearDown() {
    base::UnloadNativeLibrary(test_dll_);
  }

 protected:
  image_util::PEFile image_file_;
  base::NativeLibrary test_dll_;
};

}  // namespace

namespace image_util {

using core::AbsoluteAddress;
using core::RelativeAddress;

TEST_F(PEFileTest, Create) {
  PEFile image_file;

  ASSERT_EQ(NULL, image_file.dos_header());
  ASSERT_EQ(NULL, image_file.nt_headers());
  ASSERT_EQ(NULL, image_file.section_headers());
}

TEST_F(PEFileTest, Init) {
  EXPECT_TRUE(image_file_.dos_header() != NULL);
  EXPECT_TRUE(image_file_.nt_headers() != NULL);
  EXPECT_TRUE(image_file_.section_headers() != NULL);
}

TEST_F(PEFileTest, GetImageData) {
  const IMAGE_NT_HEADERS* nt_headers = image_file_.nt_headers();
  ASSERT_TRUE(nt_headers != NULL);
  const IMAGE_DATA_DIRECTORY* exports =
      &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

  // We should be able to read the export directory.
  ASSERT_TRUE(image_file_.GetImageData(RelativeAddress(exports->VirtualAddress),
                                      exports->Size) != NULL);

  // But there ought to be a gap in the image data past the header size.
  ASSERT_TRUE(image_file_.GetImageData(
      RelativeAddress(nt_headers->OptionalHeader.SizeOfHeaders), 1) == NULL);
}

TEST_F(PEFileTest, ReadImage) {
  const IMAGE_NT_HEADERS* nt_headers = image_file_.nt_headers();
  ASSERT_TRUE(nt_headers != NULL);
  const IMAGE_DATA_DIRECTORY* exports =
      &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

  // We should be able to read the export directory.
  IMAGE_EXPORT_DIRECTORY export_dir = {};
  ASSERT_TRUE(image_file_.ReadImage(RelativeAddress(exports->VirtualAddress),
                                    &export_dir,
                                    sizeof(export_dir)));

  // Check that we actually read something.
  IMAGE_EXPORT_DIRECTORY zero_export_dir = {};
  ASSERT_NE(0, memcmp(&export_dir, &zero_export_dir, sizeof(export_dir)));

  // Now test the ReadImageString function.
  std::vector<RelativeAddress> names(export_dir.NumberOfNames);
  ASSERT_TRUE(image_file_.ReadImage(RelativeAddress(export_dir.AddressOfNames),
                                    &names.at(0),
                                    sizeof(names[0]) * names.size()));

  // Read all the export name strings.
  for (size_t i = 0; i < names.size(); ++i) {
    std::string name;
    ASSERT_TRUE(image_file_.ReadImageString(names[i], &name));
    ASSERT_TRUE(name == "function1" ||
                name == "function3" ||
                name == "DllMain" ||
                name == "CreateFileW" ||
                name == "TestExport");
  }
}

TEST_F(PEFileTest, Contains) {
  RelativeAddress relative_base(0);
  AbsoluteAddress absolute_base;
  size_t image_size = image_file_.nt_headers()->OptionalHeader.SizeOfImage;
  RelativeAddress relative_end(image_size);
  AbsoluteAddress absolute_end;

  ASSERT_TRUE(image_file_.Translate(relative_base, &absolute_base));
  ASSERT_TRUE(image_file_.Contains(relative_base, 1));
  ASSERT_TRUE(image_file_.Contains(absolute_base, 1));
  ASSERT_FALSE(image_file_.Contains(absolute_base - 1, 1));
  ASSERT_TRUE(image_file_.Translate(relative_end, &absolute_end));
  ASSERT_EQ(absolute_end, absolute_base + image_size);
  ASSERT_FALSE(image_file_.Contains(absolute_end, 1));
  ASSERT_FALSE(image_file_.Contains(relative_end, 1));

  // TODO(rogerm): test for inclusion at the end of the address space
  //    The way the address space is built only captures the ranges
  //    specified as sections in the headers, not the overall image size.
  //    Either the test needs to be more invasive or the data structure
  //    needs to be more broadly representative.  Note sure which, but
  //    it's not critical.

  // ASSERT_TRUE(image_file_.Contains(absolute_end - 1, 1));
}

TEST_F(PEFileTest, Translate) {
  // TODO(siggi): Writeme!
}

TEST_F(PEFileTest, DecodeRelocs) {
  PEFile::RelocSet relocs;
  ASSERT_TRUE(image_file_.DecodeRelocs(&relocs));

  PEFile::RelocMap reloc_values;
  ASSERT_TRUE(image_file_.ReadRelocs(relocs, &reloc_values));

  // We expect to have some relocs to validate and we expect that
  // all relocation table entries and their corresponding values
  // fall within the image's address space
  ASSERT_TRUE(!reloc_values.empty());
  PEFile::RelocMap::const_iterator i = reloc_values.begin();
  for (;i != reloc_values.end(); ++i) {
    // Note:
    //  i->first is a relative pointer yielded by the relocation table
    //  i->second is the absolute value of that pointer (i.e., the relocation)

    const RelativeAddress &pointer_location(i->first);
    const AbsoluteAddress &pointer_value(i->second);

    ASSERT_TRUE(image_file_.Contains(pointer_location, sizeof(pointer_value)));
    ASSERT_TRUE(image_file_.Contains(pointer_value, 1));
  }
}

TEST_F(PEFileTest, DecodeExports) {
  PEFile::ExportInfoVector exports;
  ASSERT_TRUE(image_file_.DecodeExports(&exports));
  ASSERT_EQ(6, exports.size());

  // This must match the information in the test_dll.def file.
  PEFile::ExportInfo expected[] = {
    { RelativeAddress(0), "", "",  1 },
    { RelativeAddress(0), "TestExport", "", 2 },
    { RelativeAddress(0), "DllMain", "", 7 },
    { RelativeAddress(0), "function3", "", 9 },
    { RelativeAddress(0), "CreateFileW", "kernel32.CreateFileW", 13 },
    { RelativeAddress(0), "function1", "", 17 },
  };

  const uint8* module_base = reinterpret_cast<const uint8*>(test_dll_);

  // Resolve the exports and compare.
  for (size_t i = 0; i < arraysize(expected); ++i) {
    if (expected[i].forward.empty()) {
      // Look up the functions by ordinal.
      const uint8* function = reinterpret_cast<const uint8*>(
          base::GetFunctionPointerFromNativeLibrary(
              test_dll_, reinterpret_cast<const char*>(expected[i].ordinal)));
      ASSERT_TRUE(function != NULL);

      expected[i].function = RelativeAddress(function - module_base);
    }
    ASSERT_TRUE(expected[i].function == exports.at(i).function);
    ASSERT_EQ(expected[i].name, exports.at(i).name);
    ASSERT_EQ(expected[i].forward, exports.at(i).forward);
    ASSERT_EQ(expected[i].ordinal, exports.at(i).ordinal);
  }
}

TEST_F(PEFileTest, DecodeImports) {
  PEFile::ImportDllVector imports;
  ASSERT_TRUE(image_file_.DecodeImports(&imports));

  // Validation the read imports section.
  // The test image imports at least kernel32 and the export_dll.
  ASSERT_LE(2U, imports.size());

  for (size_t i = 0; i < imports.size(); ++i) {
    PEFile::ImportDll& dll = imports[i];
    if (0 == base::strcasecmp("export_dll.dll", dll.name.c_str())) {
      ASSERT_EQ(3, dll.functions.size());
      ASSERT_THAT(dll.functions,
                  testing::Contains(PEFile::ImportInfo(0, 0, "function1")));
      ASSERT_THAT(dll.functions,
                  testing::Contains(PEFile::ImportInfo(1, 0, "function3")));
      ASSERT_THAT(dll.functions,
                  testing::Contains(PEFile::ImportInfo(0, 7, "")));
    }
  }
}

}  // namespace image_util
