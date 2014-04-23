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

#include "syzygy/pe/coff_file.h"

#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/unittest_util.h"

namespace pe {

namespace {

using core::AbsoluteAddress;
using core::FileOffsetAddress;
using core::RelativeAddress;

class CoffFileTest : public testing::PELibUnitTest {
  typedef testing::PELibUnitTest Super;

 public:
  CoffFileTest() {
  }

  virtual void SetUp() OVERRIDE {
    Super::SetUp();

    test_dll_obj_path_ =
        testing::GetExeTestDataRelativePath(testing::kTestDllCoffObjName);
  }

 protected:
  base::FilePath test_dll_obj_path_;
  CoffFile image_file_;

  DISALLOW_COPY_AND_ASSIGN(CoffFileTest);
};

const char kTestExportPrefix[] = "?TestExport@@";
const char kTestStaticPrefix[] = "?TestStatic@@";

}  // namespace

TEST_F(CoffFileTest, Init) {
  EXPECT_TRUE(image_file_.file_header() == NULL);
  EXPECT_TRUE(image_file_.section_headers() == NULL);
  EXPECT_TRUE(image_file_.symbols() == NULL);
  EXPECT_TRUE(image_file_.strings() == NULL);

  ASSERT_TRUE(image_file_.Init(test_dll_obj_path_));

  EXPECT_TRUE(image_file_.file_header() != NULL);
  EXPECT_TRUE(image_file_.section_headers() != NULL);
  EXPECT_TRUE(image_file_.symbols() != NULL);
  EXPECT_TRUE(image_file_.strings() != NULL);

  EXPECT_TRUE(image_file_.file_header()->PointerToSymbolTable != 0);

  // Technically, SizeOfOptionalHeader could be non-zero, but it is
  // deprecated and MSVC should not generate such a header.
  EXPECT_EQ(0u, image_file_.file_header()->SizeOfOptionalHeader);
}

TEST_F(CoffFileTest, TranslateSectionOffsets) {
  ASSERT_TRUE(image_file_.Init(test_dll_obj_path_));

  size_t num_sections = image_file_.file_header()->NumberOfSections;
  for (size_t i = 0; i < num_sections; ++i) {
    const IMAGE_SECTION_HEADER* header = image_file_.section_header(i);
    if (!image_file_.IsSectionMapped(i))
      continue;

    size_t offset = header->SizeOfRawData / 2;
    FileOffsetAddress addr(FileOffsetAddress::kInvalidAddress);
    ASSERT_TRUE(image_file_.SectionOffsetToFileOffset(i, offset, &addr));
    EXPECT_NE(addr, FileOffsetAddress::kInvalidAddress);

    size_t new_section_index = kInvalidSection;
    size_t new_offset = -1;
    ASSERT_TRUE(image_file_.FileOffsetToSectionOffset(
        addr, &new_section_index, &new_offset));
    EXPECT_EQ(i, new_section_index);
    EXPECT_EQ(offset, new_offset);
  }
}

TEST_F(CoffFileTest, GetSymbols) {
  ASSERT_TRUE(image_file_.Init(test_dll_obj_path_));

  size_t num_symbols = image_file_.file_header()->NumberOfSymbols;
  EXPECT_GT(num_symbols, 0u);
  for (size_t i = 0; i < num_symbols; ++i) {
    EXPECT_TRUE(image_file_.symbol(i) != NULL);
  }
}

TEST_F(CoffFileTest, DecodeRelocs) {
  ASSERT_TRUE(image_file_.Init(test_dll_obj_path_));

  CoffFile::RelocMap reloc_map;
  image_file_.DecodeRelocs(&reloc_map);
  EXPECT_FALSE(reloc_map.empty());

  // Validate relocations.
  CoffFile::RelocMap::const_iterator it = reloc_map.begin();
  for (; it != reloc_map.end(); ++it) {
    // Location to relocate must be mapped within the address space.
    EXPECT_TRUE(image_file_.Contains(it->first, sizeof(void*)));

    // Relocation must reference a valid symbol.
    EXPECT_TRUE(image_file_.symbol(it->second->SymbolTableIndex) != NULL);
  }
}

TEST_F(CoffFileTest, GetSymbolName) {
  ASSERT_TRUE(image_file_.Init(test_dll_obj_path_));

  size_t num_symbols = image_file_.file_header()->NumberOfSymbols;
  const IMAGE_SYMBOL* symbol = NULL;
  for (size_t i = 0; i < num_symbols; i += 1 + symbol->NumberOfAuxSymbols) {
    symbol = image_file_.symbol(i);
    EXPECT_TRUE(image_file_.GetSymbolName(i) != NULL);
  }
}

TEST_F(CoffFileTest, HaveTestSymbols) {
  ASSERT_TRUE(image_file_.Init(test_dll_obj_path_));

  bool have_dll_main = false;
  bool have_test_export = false;
  size_t num_symbols = image_file_.file_header()->NumberOfSymbols;
  const IMAGE_SYMBOL* symbol = NULL;
  for (size_t i = 0; i < num_symbols; i += 1 + symbol->NumberOfAuxSymbols) {
    symbol = image_file_.symbol(i);
    const char* symbol_name = image_file_.GetSymbolName(i);
    if (strcmp(symbol_name, "_DllMain@12") == 0)
      have_dll_main = true;
    if (strncmp(symbol_name, kTestExportPrefix,
                strlen(kTestExportPrefix)) == 0)
      have_test_export = true;
  }
  EXPECT_TRUE(have_dll_main);
  EXPECT_TRUE(have_test_export);
}

TEST_F(CoffFileTest, HaveStaticFunction) {
  ASSERT_TRUE(image_file_.Init(test_dll_obj_path_));

  const IMAGE_SYMBOL* test_static_symbol = NULL;
  size_t num_symbols = image_file_.file_header()->NumberOfSymbols;
  const IMAGE_SYMBOL* symbol = NULL;
  for (size_t i = 0; i < num_symbols; i += 1 + symbol->NumberOfAuxSymbols) {
    symbol = image_file_.symbol(i);
    const char* symbol_name = image_file_.GetSymbolName(i);
    if (strncmp(symbol_name, kTestStaticPrefix,
                strlen(kTestStaticPrefix)) == 0) {
      test_static_symbol = image_file_.symbol(i);
      break;
    }
  }
  ASSERT_TRUE(test_static_symbol != NULL);
  ASSERT_EQ(0u, test_static_symbol->NumberOfAuxSymbols);
}

TEST_F(CoffFileTest, HaveFunctionAndLabels) {
  ASSERT_TRUE(image_file_.Init(test_dll_obj_path_));

  size_t num_functions = 0;
  size_t num_labels = 0;
  size_t num_symbols = image_file_.file_header()->NumberOfSymbols;
  const IMAGE_SYMBOL* symbol = NULL;
  for (size_t i = 0; i < num_symbols; i += 1 + symbol->NumberOfAuxSymbols) {
    symbol = image_file_.symbol(i);
    const IMAGE_SYMBOL* symbol = image_file_.symbol(i);
    // Specifications say the DTYPE is in the MSB but it's really only
    // shifted by 4, not 8.
    num_functions += symbol->Type >> 4 == IMAGE_SYM_DTYPE_FUNCTION;
    num_labels += symbol->StorageClass == IMAGE_SYM_CLASS_LABEL;
  }
  ASSERT_LT(0u, num_functions);
  ASSERT_LT(0u, num_labels);
}

TEST(SimpleCoffFileTest, InitCodeView2Symbols) {
  base::FilePath path = testing::GetSrcRelativePath(testing::kCodeView2Name);
  CoffFile file;
  EXPECT_TRUE(file.Init(path));
}

}  // namespace pe
