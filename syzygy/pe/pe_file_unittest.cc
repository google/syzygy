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

#include "syzygy/pe/pe_file.h"
#include "base/file_path.h"
#include "base/native_library.h"
#include "base/path_service.h"
#include "base/string_util.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/unittest_util.h"

namespace {

class PEFileTest: public testing::PELibUnitTest {
  typedef testing::PELibUnitTest Super;

public:
  PEFileTest() : test_dll_(NULL) {
  }

  virtual void SetUp() {
    Super::SetUp();

    FilePath test_dll = testing::GetExeRelativePath(kDllName);
    std::string error;
    test_dll_ = base::LoadNativeLibrary(test_dll, &error);

    ASSERT_TRUE(image_file_.Init(test_dll));
  }

  virtual void TearDown() {
    base::UnloadNativeLibrary(test_dll_);
    Super::TearDown();
  }

 protected:
  pe::PEFile image_file_;
  base::NativeLibrary test_dll_;
};

}  // namespace

namespace pe {

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
                name == "TestUnusedFuncs" ||
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
  ASSERT_EQ(7, exports.size());

  // This must match the information in the test_dll.def file.
  PEFile::ExportInfo expected[] = {
    { RelativeAddress(0), "", "",  1 },
    { RelativeAddress(0), "TestExport", "", 2 },
    { RelativeAddress(0), "TestUnusedFuncs", "", 3 },
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

TEST_F(PEFileTest, GetSectionIndexByRelativeAddress) {
  size_t num_sections = image_file_.nt_headers()->FileHeader.NumberOfSections;
  for (size_t i = 0; i < num_sections; ++i) {
    RelativeAddress section_start(
        image_file_.section_header(i)->VirtualAddress);
    EXPECT_EQ(i, image_file_.GetSectionIndex(section_start, 1));
  }

  RelativeAddress off_end(image_file_.nt_headers()->OptionalHeader.SizeOfImage +
      0x10000);
  EXPECT_EQ(kInvalidSection, image_file_.GetSectionIndex(off_end, 1));
}

TEST_F(PEFileTest, GetSectionIndexByAbsoluteAddress) {
  size_t image_base = image_file_.nt_headers()->OptionalHeader.ImageBase;
  size_t num_sections = image_file_.nt_headers()->FileHeader.NumberOfSections;
  for (size_t i = 0; i < num_sections; ++i) {
    AbsoluteAddress section_start(
        image_file_.section_header(i)->VirtualAddress + image_base);
    EXPECT_EQ(i, image_file_.GetSectionIndex(section_start, 1));
  }

  AbsoluteAddress off_end(image_file_.nt_headers()->OptionalHeader.SizeOfImage +
      0x10000 + image_base);
  EXPECT_EQ(kInvalidSection, image_file_.GetSectionIndex(off_end, 1));
}

TEST_F(PEFileTest, GetSectionIndexByName) {
  size_t num_sections = image_file_.nt_headers()->FileHeader.NumberOfSections;
  for (size_t i = 0; i < num_sections; ++i) {
    std::string name = image_file_.GetSectionName(i);
    EXPECT_EQ(i, image_file_.GetSectionIndex(name.c_str()));
  }

  EXPECT_EQ(kInvalidSection, image_file_.GetSectionIndex(".foobar"));
}

TEST_F(PEFileTest, GetSectionHeaderByRelativeAddress) {
  size_t num_sections = image_file_.nt_headers()->FileHeader.NumberOfSections;
  for (size_t i = 0; i < num_sections; ++i) {
    RelativeAddress section_start(
        image_file_.section_header(i)->VirtualAddress);
    EXPECT_EQ(image_file_.section_header(i),
              image_file_.GetSectionHeader(section_start, 1));
  }

  RelativeAddress off_end(image_file_.nt_headers()->OptionalHeader.SizeOfImage +
      0x10000);
  EXPECT_EQ(kInvalidSection, image_file_.GetSectionIndex(off_end, 1));
}

TEST_F(PEFileTest, GetSectionHeaderByAbsoluteAddress) {
  size_t image_base = image_file_.nt_headers()->OptionalHeader.ImageBase;
  size_t num_sections = image_file_.nt_headers()->FileHeader.NumberOfSections;
  for (size_t i = 0; i < num_sections; ++i) {
    AbsoluteAddress section_start(
        image_file_.section_header(i)->VirtualAddress + image_base);
    EXPECT_EQ(image_file_.section_header(i),
              image_file_.GetSectionHeader(section_start, 1));
  }

  AbsoluteAddress off_end(image_file_.nt_headers()->OptionalHeader.SizeOfImage +
      0x10000 + image_base);
  EXPECT_EQ(kInvalidSection, image_file_.GetSectionIndex(off_end, 1));
}

TEST(PEFileSignatureTest, Serialization) {
  PEFile::Signature sig;
  sig.path = L"C:\foo\bar.dll";
  sig.base_address = AbsoluteAddress(0x1000000);
  sig.module_size = 12345;
  sig.module_time_date_stamp = 9999999;
  sig.module_checksum = 0xbaadf00d;

  EXPECT_TRUE(testing::TestSerialization(sig));
}

TEST(PEFileSignatureTest, Consistency) {
  PEFile::Signature sig1;
  sig1.path = L"C:\foo\bar.dll";
  sig1.base_address = AbsoluteAddress(0x1000000);
  sig1.module_size = 12345;
  sig1.module_time_date_stamp = 9999999;
  sig1.module_checksum = 0xbaadf00d;

  // sig2 is the same, but with a different module path.
  PEFile::Signature sig2(sig1);
  sig2.path = L"C:\foo\bar.exe";

  EXPECT_FALSE(sig1 == sig2);
  EXPECT_TRUE(sig1.IsConsistent(sig2));
}

}  // namespace pe
