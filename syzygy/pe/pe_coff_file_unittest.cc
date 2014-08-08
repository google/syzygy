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

#include "syzygy/pe/pe_coff_file.h"

#include "base/native_library.h"
#include "base/path_service.h"
#include "base/files/file_path.h"
#include "base/strings/string_util.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/unittest_util.h"

namespace pe {

namespace {

using core::AbsoluteAddress;
using core::FileOffsetAddress;
using core::RelativeAddress;

template <typename AddressSpaceTraits>
class TestPECoffFile : public PECoffFile<AddressSpaceTraits> {
 public:
  // Partial initialization, for common parts.
  bool Init(const base::FilePath& path, bool has_pe_headers) {
    PECoffFile::Init(path);

    FILE* file = base::OpenFile(path, "rb");
    if (file == NULL) {
      LOG(ERROR) << "Failed to open file " << path.value() << ".";
      return false;
    }

    FileOffsetAddress file_header_start(0);
    if (has_pe_headers) {
      // Read NT header position at 0x3C according to the spec.
      uint32 nt_header_pos = 0;
      if (!ReadAt(file, 0x3C, &nt_header_pos, sizeof(nt_header_pos))) {
        LOG(ERROR) << "Unable to read NT header offset.";
        return false;
      }

      file_header_start.set_value(nt_header_pos +
                                  offsetof(IMAGE_NT_HEADERS, FileHeader));
    }

    bool success = ReadCommonHeaders(file, file_header_start);
    if (success)
      success = ReadSections(file);

    base::CloseFile(file);

    return success;
  }
};

template <typename AddressType, size_t shift_base, size_t header_base>
struct ShiftedAddressSpaceTraits {
  typedef typename AddressType AddressType;
  typedef unsigned int SizeType;

  static const size_t kShiftBase = shift_base;

  static const AddressType invalid_address() {
    return AddressType::kInvalidAddress;
  }

  static const AddressType header_address() {
    return AddressType(header_base);
  }

  static AddressType GetSectionAddress(const IMAGE_SECTION_HEADER& header) {
    // VirtualAddress is not necessarily 0 for object files, but it
    // should, and MSVC should produce 0; we use that info as
    // a heuristic to decide on the address.
    if (header.VirtualAddress == 0) {
      if ((header.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0 &&
          header.PointerToRawData == 0) {
        // Unmapped section.
        return invalid_address();
      } else {
        return AddressType(kShiftBase + header.PointerToRawData);
      }
    } else {
      return AddressType(kShiftBase + header.VirtualAddress);
    }
  }

  static SizeType GetSectionSize(const IMAGE_SECTION_HEADER& header) {
    return 1;
  }
};

typedef ShiftedAddressSpaceTraits<AbsoluteAddress, 0x10000, 0x4>
    ShiftedVirtualAddressTraits;
typedef ShiftedAddressSpaceTraits<FileOffsetAddress, 0x100, 0x100>
    ShiftedFileOffsetAddressTraits;

class PECoffFileTest : public testing::PELibUnitTest {
  typedef testing::PELibUnitTest Super;

 public:
  PECoffFileTest() {
  }

  virtual void SetUp() OVERRIDE {
    Super::SetUp();

    test_dll_path_ = testing::GetExeRelativePath(testing::kTestDllName);
    test_dll_coff_obj_path_ =
        testing::GetExeTestDataRelativePath(testing::kTestDllCoffObjName);
    test_dll_ltcg_obj_path_ =
        testing::GetExeTestDataRelativePath(testing::kTestDllLtcgObjName);
  }

 protected:
  bool InitImages() {
    return pe_image_file_.Init(test_dll_path_, true) &&
        coff_image_file_.Init(test_dll_coff_obj_path_, false);
  }

  base::FilePath test_dll_path_;
  base::FilePath test_dll_coff_obj_path_;
  base::FilePath test_dll_ltcg_obj_path_;

  TestPECoffFile<ShiftedVirtualAddressTraits> pe_image_file_;
  TestPECoffFile<ShiftedFileOffsetAddressTraits> coff_image_file_;

 private:
  DISALLOW_COPY_AND_ASSIGN(PECoffFileTest);
};

bool IsCoffSectionMapped(
    const TestPECoffFile<ShiftedFileOffsetAddressTraits>& image_file,
    size_t i) {
  const IMAGE_SECTION_HEADER* hdr = image_file.section_header(i);
  return hdr != NULL &&
      (ShiftedFileOffsetAddressTraits::GetSectionAddress(*hdr) !=
       ShiftedFileOffsetAddressTraits::invalid_address());
}

}  // namespace

TEST_F(PECoffFileTest, Init) {
  EXPECT_TRUE(pe_image_file_.file_header() == NULL);
  EXPECT_TRUE(pe_image_file_.section_headers() == NULL);
  EXPECT_TRUE(coff_image_file_.file_header() == NULL);
  EXPECT_TRUE(coff_image_file_.section_headers() == NULL);

  ASSERT_TRUE(pe_image_file_.Init(test_dll_path_, true));
  ASSERT_TRUE(coff_image_file_.Init(test_dll_coff_obj_path_, false));

  EXPECT_TRUE(pe_image_file_.file_header() != NULL);
  EXPECT_TRUE(pe_image_file_.section_headers() != NULL);
  EXPECT_TRUE(coff_image_file_.file_header() != NULL);
  EXPECT_TRUE(coff_image_file_.section_headers() != NULL);

  EXPECT_EQ(pe_image_file_.file_header()->Machine, IMAGE_FILE_MACHINE_I386);
  EXPECT_EQ(coff_image_file_.file_header()->Machine, IMAGE_FILE_MACHINE_I386);

  EXPECT_TRUE(pe_image_file_.file_header()->SizeOfOptionalHeader != 0);
  EXPECT_TRUE(coff_image_file_.file_header()->PointerToSymbolTable != 0);
}

TEST_F(PECoffFileTest, FailOnAnonymousObject) {
  ASSERT_FALSE(coff_image_file_.Init(test_dll_ltcg_obj_path_, false));
}

// Compare header data obtained from different methods.
TEST_F(PECoffFileTest, ReadFileHeader) {
  ASSERT_TRUE(InitImages());
  ASSERT_TRUE(coff_image_file_.file_header() != NULL);

  IMAGE_FILE_HEADER header = {};
  ASSERT_TRUE(coff_image_file_.ReadImage(coff_image_file_.header_address(),
                                         &header, sizeof(header)));
  EXPECT_TRUE(memcmp(static_cast<void*>(&header),
                     static_cast<const void*>(coff_image_file_.file_header()),
                     sizeof(header)) == 0);
  uint8* ptr = coff_image_file_.GetImageData(coff_image_file_.header_address(),
                                             sizeof(header));
  ASSERT_TRUE(ptr != NULL);
  EXPECT_TRUE(memcmp(static_cast<void*>(&header),
                     static_cast<void*>(ptr),
                     sizeof(header)) == 0);
}

TEST_F(PECoffFileTest, Contains) {
  ASSERT_TRUE(InitImages());
  EXPECT_TRUE(pe_image_file_.Contains(pe_image_file_.header_address(), 1));
  EXPECT_FALSE(pe_image_file_.Contains(pe_image_file_.header_address() - 1, 1));

  // Should be a gap in the address space before the big shift of
  // ShiftedVirtualAddressTraits::kShiftBase.
  EXPECT_FALSE(pe_image_file_.Contains(
      AbsoluteAddress(ShiftedVirtualAddressTraits::kShiftBase - 1), 1));

  EXPECT_TRUE(coff_image_file_.Contains(coff_image_file_.header_address(), 1));
  EXPECT_FALSE(coff_image_file_.Contains(
      coff_image_file_.header_address() - 1, 1));
}

TEST_F(PECoffFileTest, GetSectionIndex) {
  ASSERT_TRUE(InitImages());

  size_t num_sections = pe_image_file_.file_header()->NumberOfSections;
  for (size_t i = 0; i < num_sections; ++i) {
    AbsoluteAddress section_start(
        ShiftedVirtualAddressTraits::GetSectionAddress(
            *pe_image_file_.section_header(i)));
    EXPECT_EQ(i, pe_image_file_.GetSectionIndex(section_start, 1));
  }

  AbsoluteAddress off_by_one(ShiftedVirtualAddressTraits::kShiftBase - 1);
  EXPECT_EQ(kInvalidSection, pe_image_file_.GetSectionIndex(off_by_one, 1));

  num_sections = coff_image_file_.file_header()->NumberOfSections;
  for (size_t i = 0; i < num_sections; ++i) {
    if (IsCoffSectionMapped(coff_image_file_, i)) {
      FileOffsetAddress section_start(
          ShiftedFileOffsetAddressTraits::GetSectionAddress(
              *coff_image_file_.section_header(i)));
      EXPECT_EQ(i, coff_image_file_.GetSectionIndex(section_start, 1));
    }
  }
}

TEST_F(PECoffFileTest, GetSectionHeader) {
  ASSERT_TRUE(InitImages());

  size_t num_sections = pe_image_file_.file_header()->NumberOfSections;
  for (size_t i = 0; i < num_sections; ++i) {
    AbsoluteAddress section_start(
        ShiftedVirtualAddressTraits::GetSectionAddress(
            *pe_image_file_.section_header(i)));
    EXPECT_EQ(pe_image_file_.section_header(i),
              pe_image_file_.GetSectionHeader(section_start, 1));
  }

  num_sections = coff_image_file_.file_header()->NumberOfSections;
  for (size_t i = 0; i < num_sections; ++i) {
    if (IsCoffSectionMapped(coff_image_file_, i)) {
      FileOffsetAddress section_start(
          ShiftedFileOffsetAddressTraits::GetSectionAddress(
              *coff_image_file_.section_header(i)));
      EXPECT_EQ(coff_image_file_.section_header(i),
                coff_image_file_.GetSectionHeader(section_start, 1));
    }
  }
}

TEST_F(PECoffFileTest, GetImageData) {
  ASSERT_TRUE(InitImages());
  ASSERT_TRUE(pe_image_file_.file_header() != NULL);
  ASSERT_TRUE(coff_image_file_.file_header() != NULL);

  size_t num_sections = pe_image_file_.file_header()->NumberOfSections;
  for (size_t i = 0; i < num_sections; ++i) {
    AbsoluteAddress section_start(
        ShiftedVirtualAddressTraits::GetSectionAddress(
            *pe_image_file_.section_header(i)));
    EXPECT_TRUE(pe_image_file_.GetImageData(section_start, 1) != NULL);
  }

  num_sections = coff_image_file_.file_header()->NumberOfSections;
  for (size_t i = 0; i < num_sections; ++i) {
    if (IsCoffSectionMapped(coff_image_file_, i)) {
      FileOffsetAddress section_start(
          ShiftedFileOffsetAddressTraits::GetSectionAddress(
              *coff_image_file_.section_header(i)));
      EXPECT_TRUE(coff_image_file_.GetImageData(section_start, 1) != NULL);
    }
  }
}

}  // namespace pe
