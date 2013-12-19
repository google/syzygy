// Copyright 2012 Google Inc. All Rights Reserved.
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

#include "syzygy/pe/pe_file_parser.h"

#include "base/bind.h"
#include "base/native_library.h"
#include "base/path_service.h"
#include "base/string_util.h"
#include "base/files/file_path.h"
#include "base/memory/scoped_ptr.h"
#include "base/win/pe_image.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/unittest_util.h"

namespace pe {

using block_graph::BlockGraph;
using core::RelativeAddress;
using testing::ContainerEq;
using testing::Contains;

namespace {

// Exposes the protected methods for testing.
class TestPEFileParser: public PEFileParser {
 public:
  TestPEFileParser(const PEFile& image_file,
                   BlockGraph::AddressSpace* address_space,
                   AddReferenceCallback add_reference)
      : PEFileParser(image_file, address_space, add_reference) {
  }

  // Expose as public for testing.
  using PEFileParser::ParseArchitectureDir;
  using PEFileParser::ParseBoundImportDir;
  using PEFileParser::ParseComDescriptorDir;
  using PEFileParser::ParseDebugDir;
  using PEFileParser::ParseDelayImportDir;
  using PEFileParser::ParseExceptionDir;
  using PEFileParser::ParseExportDir;
  using PEFileParser::ParseGlobalDir;
  using PEFileParser::ParseIatDir;
  using PEFileParser::ParseImageHeader;
  using PEFileParser::ParseImportDir;
  using PEFileParser::ParseLoadConfigDir;
  using PEFileParser::ParseRelocDir;
  using PEFileParser::ParseResourceDir;
  using PEFileParser::ParseSecurityDir;
  using PEFileParser::ParseTlsDir;
};

class PEFileParserTest: public testing::PELibUnitTest {
  typedef testing::PELibUnitTest Super;

 public:
  PEFileParserTest() : address_space_(&image_), loaded_image_(NULL) {
  }

  virtual void SetUp() {
    Super::SetUp();

    add_reference_ = base::Bind(&PEFileParserTest::AddReference,
                                base::Unretained(this));
    on_import_thunk_ = base::Bind(&PEFileParserTest::OnImportThunk,
                                  base::Unretained(this));

    ASSERT_TRUE(image_file_.Init(testing::GetExeRelativePath(
        testing::kTestDllName)));
  }

  virtual void TearDown() {
    if (loaded_image_ != NULL)
      base::UnloadNativeLibrary(loaded_image_);
    loaded_image_ = NULL;

    Super::TearDown();
  }

  bool AddReference(RelativeAddress src,
                    BlockGraph::ReferenceType type,
                    BlockGraph::Size size,
                    RelativeAddress dst) {
    Reference ref = { type, size, dst };
    bool inserted = references_.insert(std::make_pair(src, ref)).second;
    EXPECT_TRUE(inserted);
    return inserted;
  }

  bool OnImportThunk(const char* module_name,
                     const char* symbol_name,
                     BlockGraph::Block* thunk) {
    EXPECT_TRUE(module_name != NULL);
    EXPECT_TRUE(symbol_name != NULL);
    EXPECT_TRUE(thunk != NULL);
    import_map_[module_name]++;
    EXPECT_TRUE(import_set_.insert(
        std::make_pair(std::string(module_name),
                       std::string(symbol_name))).second);
    return true;
  }

  // Assert that an exported function in the test_dll is referenced
  // in the image.
  bool ExportIsReferenced(const char* function_name_or_ordinal) {
    if (loaded_image_ == NULL) {
      std::string error;
      loaded_image_ = base::LoadNativeLibrary(
          testing::GetExeRelativePath(testing::kTestDllName), &error);
    }

    EXPECT_TRUE(loaded_image_ != NULL);
    if (loaded_image_ == NULL)
      return false;

    void* function = base::GetFunctionPointerFromNativeLibrary(
        loaded_image_, function_name_or_ordinal);

    RelativeAddress addr(reinterpret_cast<const char*>(function) -
                         reinterpret_cast<const char*>(loaded_image_));

    ReferenceMap::const_iterator it(references_.begin());
    for (; it != references_.end(); ++it) {
      if (it->second.dst == addr)
        return true;
    }

    return false;
  }

  void AssertDataDirectoryEntryValid(BlockGraph::Block* block) {
    ASSERT_TRUE(block != NULL);
    ASSERT_NE(0u, block->size());
    ASSERT_EQ(block->size(), block->data_size());
    ASSERT_TRUE(block->data() != NULL);
  }

  // Locate block pointed to by the reference at @p offset into @p block.
  // @returns the block in question, or NULL if no such block.
  BlockGraph::Block* FindReferencedBlock(BlockGraph::Block* block,
                                         BlockGraph::Offset offset) {
    ReferenceMap::const_iterator it(references_.find(block->addr() + offset));
    if (it == references_.end())
      return NULL;

    return address_space_.GetBlockByAddress(it->second.dst);
  }

 protected:
  struct Reference {
    BlockGraph::ReferenceType type;
    BlockGraph::Size size;
    RelativeAddress dst;
  };

  typedef std::map<RelativeAddress, Reference> ReferenceMap;
  ReferenceMap references_;

  // This is used to count the number of imported symbols per imported module,
  // and is populated by the OnImportThunk callback.
  typedef std::map<std::string, size_t> ImportMap;
  typedef std::set<std::pair<std::string, std::string>> ImportSet;
  ImportMap import_map_;
  ImportSet import_set_;

  PEFileParser::AddReferenceCallback add_reference_;
  PEFileParser::OnImportThunkCallback on_import_thunk_;
  PEFile image_file_;
  BlockGraph image_;
  BlockGraph::AddressSpace address_space_;

  base::NativeLibrary loaded_image_;
};

}  // namespace

TEST_F(PEFileParserTest, ParseImageHeader) {
  TestPEFileParser parser(image_file_, &address_space_, add_reference_);

  PEFileParser::PEHeader header;
  EXPECT_TRUE(parser.ParseImageHeader(&header));

  // Check that the DOS header was read successfully.
  ASSERT_TRUE(header.dos_header != NULL);
  ASSERT_GE(header.dos_header->size(), sizeof(IMAGE_DOS_HEADER));
  ASSERT_EQ(BlockGraph::DATA_BLOCK, header.dos_header->type());
  // Check the underlying data.
  ASSERT_GE(header.dos_header->data_size(), sizeof(IMAGE_DOS_HEADER));
  const IMAGE_DOS_HEADER* dos_header =
      reinterpret_cast<const IMAGE_DOS_HEADER*>(header.dos_header->data());
  ASSERT_TRUE(dos_header != NULL);
  ASSERT_EQ(IMAGE_DOS_SIGNATURE, dos_header->e_magic);

  // Check that the DOS header references the NT headers.
  ASSERT_EQ(header.nt_headers,
      FindReferencedBlock(header.dos_header,
                          offsetof(IMAGE_DOS_HEADER, e_lfanew)));

  // Check the NT headers.
  ASSERT_TRUE(header.nt_headers != NULL);
  ASSERT_GT(header.nt_headers->size(), sizeof(IMAGE_NT_HEADERS));
  ASSERT_EQ(header.nt_headers->data_size(), header.nt_headers->size());
  ASSERT_EQ(BlockGraph::DATA_BLOCK, header.nt_headers->type());
  const IMAGE_NT_HEADERS* nt_headers =
      reinterpret_cast<const IMAGE_NT_HEADERS*>(header.nt_headers->data());
  ASSERT_TRUE(nt_headers != NULL);
  ASSERT_EQ(IMAGE_NT_OPTIONAL_HDR32_MAGIC, nt_headers->OptionalHeader.Magic);

  const IMAGE_SECTION_HEADER* section_headers = NULL;
  // Check that the data accounts for the image section headers.
  ASSERT_EQ(nt_headers->FileHeader.NumberOfSections * sizeof(*section_headers) +
      sizeof(*nt_headers), header.nt_headers->data_size());
}

TEST_F(PEFileParserTest, ParseExportDir) {
  TestPEFileParser parser(image_file_, &address_space_, add_reference_);

  PEFileParser::PEHeader header;
  EXPECT_TRUE(parser.ParseImageHeader(&header));

  const IMAGE_NT_HEADERS* nt_headers =
      reinterpret_cast<const IMAGE_NT_HEADERS*>(header.nt_headers->data());

  const IMAGE_DATA_DIRECTORY& dir =
      nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  EXPECT_TRUE(parser.ParseExportDir(dir) != NULL);

  std::string error;
  loaded_image_ = base::LoadNativeLibrary(
      testing::GetExeRelativePath(testing::kTestDllName), &error);
  ASSERT_TRUE(loaded_image_ != NULL);

  ASSERT_TRUE(ExportIsReferenced("function1"));
  // function2 is exported by ordinal only.
  ASSERT_TRUE(ExportIsReferenced(reinterpret_cast<const char*>(7)));
  ASSERT_TRUE(ExportIsReferenced("function3"));
}

TEST_F(PEFileParserTest, ParseImportDir) {
  TestPEFileParser parser(image_file_, &address_space_, add_reference_);
  parser.set_on_import_thunk(on_import_thunk_);

  PEFileParser::PEHeader header;
  EXPECT_TRUE(parser.ParseImageHeader(&header));

  const IMAGE_NT_HEADERS* nt_headers =
      reinterpret_cast<const IMAGE_NT_HEADERS*>(header.nt_headers->data());

  const IMAGE_DATA_DIRECTORY& dir =
      nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  BlockGraph::Block* block = parser.ParseImportDir(dir);
  ASSERT_TRUE(block != NULL);

  // Test that we have the two import descriptors we expect, plus the sentinel.
  size_t num_descriptors = block->size() / sizeof(IMAGE_IMPORT_DESCRIPTOR);
  ASSERT_EQ(3, num_descriptors);
  ASSERT_TRUE(block->data() != NULL);
  ASSERT_EQ(block->size(), block->data_size());

  std::set<std::string> import_names;
  for (size_t i = 0; i < num_descriptors - 1; ++i) {
    size_t element_offset = sizeof(IMAGE_IMPORT_DESCRIPTOR) * i;
    BlockGraph::Block* name_block =
        FindReferencedBlock(block, element_offset +
            offsetof(IMAGE_IMPORT_DESCRIPTOR, Name));
    ASSERT_TRUE(name_block != NULL);

    const char* name =
        reinterpret_cast<const char*>(name_block->data());
    EXPECT_TRUE(import_names.insert(name).second);

    // Now retrieve the IAT and INT blocks.
    BlockGraph::Block* iat_block =
        FindReferencedBlock(block, element_offset +
            offsetof(IMAGE_IMPORT_DESCRIPTOR, FirstThunk));
    BlockGraph::Block* int_block =
        FindReferencedBlock(block, element_offset +
            offsetof(IMAGE_IMPORT_DESCRIPTOR, OriginalFirstThunk));

    ASSERT_TRUE(iat_block != NULL);
    ASSERT_TRUE(int_block != NULL);
    ASSERT_EQ(iat_block->size(), int_block->size());
    ASSERT_EQ(iat_block->data_size(), int_block->data_size());
    ASSERT_EQ(0,
        memcmp(iat_block->data(), int_block->data(), iat_block->data_size()));

    // Now check that each slot, save for the last one, in the IAT/INT
    // points to a name block or else is an ordinal.
    size_t num_thunks = iat_block->data_size() / sizeof(IMAGE_THUNK_DATA) - 1;
    const IMAGE_THUNK_DATA* iat =
        reinterpret_cast<const IMAGE_THUNK_DATA*>(iat_block->data());
    for (size_t i = 0; i < num_thunks; ++i) {
      if (!IMAGE_ORDINAL(iat[i].u1.Ordinal)) {
        size_t thunk_offset = sizeof(IMAGE_THUNK_DATA) * i;
        ASSERT_TRUE(FindReferencedBlock(iat_block, thunk_offset) != NULL);
        ASSERT_TRUE(FindReferencedBlock(int_block, thunk_offset) != NULL);
      }
    }
  }

  // Check that the sentinel is all zero.
  IMAGE_IMPORT_DESCRIPTOR zero = {};
  const IMAGE_IMPORT_DESCRIPTOR* sentinel =
      reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(block->data()) +
          num_descriptors - 1;
  EXPECT_EQ(0, memcmp(sentinel, &zero, sizeof(zero)));

  std::set<std::string> expected;
  expected.insert("KERNEL32.dll");
  expected.insert("export_dll.dll");
  EXPECT_THAT(import_names, ContainerEq(expected));

  // The number of expected symbols imported from kernel32.dll.
#if _MSC_VER == 1600  // MSVS 2010.
#if defined(NDEBUG)
  // VC++ 2010 Release Build.
  static size_t kNumKernel32Symbols = 68;
#else
  // VC++ 2010 Debug/Coverage build.
  static size_t kNumKernel32Symbols = 70;
#endif
#elif _MSC_VER == 1800  // MSVS 2013.
#if defined(NDEBUG)
  // VC++ 2013 Release Build.
  static size_t kNumKernel32Symbols = 63;
#else
  // VC++ 2013 Debug/Coverage build.
  static size_t kNumKernel32Symbols = 64;
#endif
#endif
  // The number of expected symbols imported from export_dll.dll.
  static const size_t kNumExportDllSymbols = 3;

  ImportMap expected_import_map;
  expected_import_map["KERNEL32.dll"] = kNumKernel32Symbols;
  expected_import_map["export_dll.dll"] = kNumExportDllSymbols;
  EXPECT_THAT(import_map_, ContainerEq(expected_import_map));

  EXPECT_EQ(kNumKernel32Symbols + kNumExportDllSymbols, import_set_.size());
  EXPECT_THAT(import_set_, Contains(std::make_pair(
      std::string("KERNEL32.dll"), std::string("ExitProcess"))));
  EXPECT_THAT(import_set_, Contains(std::make_pair(
      std::string("export_dll.dll"), std::string("function1"))));
}

TEST_F(PEFileParserTest, ParseDelayImportDir) {
  TestPEFileParser parser(image_file_, &address_space_, add_reference_);

  PEFileParser::PEHeader header;
  EXPECT_TRUE(parser.ParseImageHeader(&header));

  const IMAGE_NT_HEADERS* nt_headers =
      reinterpret_cast<const IMAGE_NT_HEADERS*>(header.nt_headers->data());

  const IMAGE_DATA_DIRECTORY& dir =
      nt_headers->OptionalHeader.DataDirectory[
          IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
  BlockGraph::Block* block = parser.ParseDelayImportDir(dir);
  ASSERT_TRUE(block != NULL);

  // Test that we have the import descriptors we expect - we expect
  // the one delay import, plus the sentinel import descriptor to be
  // chunked out.
  size_t num_descriptors = block->size() / sizeof(ImgDelayDescr);
  ASSERT_EQ(2, num_descriptors);
  ASSERT_TRUE(block->data() != NULL);
  ASSERT_EQ(block->size(), block->data_size());

  std::set<std::string> import_names;
  for (size_t i = 0; i < num_descriptors - 1; ++i) {
    size_t element_offset = sizeof(ImgDelayDescr) * i;
    BlockGraph::Block* name_block =
        FindReferencedBlock(block, element_offset +
            offsetof(ImgDelayDescr, rvaDLLName));
    ASSERT_TRUE(name_block != NULL);

    const char* name =
        reinterpret_cast<const char*>(name_block->data());
    EXPECT_TRUE(import_names.insert(name).second);

    // Now retrieve the IAT, INT and BoundIAT blocks.
    BlockGraph::Block* iat_block =
        FindReferencedBlock(block, element_offset +
            offsetof(ImgDelayDescr, rvaIAT));
    BlockGraph::Block* int_block =
        FindReferencedBlock(block, element_offset +
            offsetof(ImgDelayDescr, rvaINT));
    BlockGraph::Block* bound_iat_block =
        FindReferencedBlock(block, element_offset +
            offsetof(ImgDelayDescr, rvaBoundIAT));

    ASSERT_TRUE(iat_block != NULL);
    ASSERT_TRUE(int_block != NULL);
    ASSERT_TRUE(bound_iat_block != NULL);

    ASSERT_EQ(iat_block->size(), int_block->size());
    ASSERT_EQ(iat_block->size(), bound_iat_block->size());
    ASSERT_EQ(iat_block->data_size(), int_block->data_size());
    ASSERT_EQ(iat_block->data_size(), bound_iat_block->data_size());

    // Now check that each slot, save for the last one, in the INT
    // points to a name block or else is an ordinal.
    size_t num_thunks = iat_block->data_size() / sizeof(IMAGE_THUNK_DATA) - 1;
    const IMAGE_THUNK_DATA* iat =
        reinterpret_cast<const IMAGE_THUNK_DATA*>(int_block->data());
    for (size_t i = 0; i < num_thunks; ++i) {
      if (!IMAGE_ORDINAL(iat[i].u1.Ordinal)) {
        size_t thunk_offset = sizeof(IMAGE_THUNK_DATA) * i;
        ASSERT_TRUE(FindReferencedBlock(int_block, thunk_offset) != NULL);
      }
    }
  }

  // Check that the sentinel is all zero.
  ImgDelayDescr zero = {};
  const ImgDelayDescr* sentinel =
      reinterpret_cast<const ImgDelayDescr*>(block->data()) +
          num_descriptors - 1;
  EXPECT_EQ(0, memcmp(sentinel, &zero, sizeof(zero)));

  std::set<std::string> expected;
  expected.insert("ole32.dll");
  EXPECT_THAT(import_names, ContainerEq(expected));
}

TEST_F(PEFileParserTest, ParseImage) {
  TestPEFileParser parser(image_file_, &address_space_, add_reference_);

  PEFileParser::PEHeader header;
  EXPECT_TRUE(parser.ParseImage(&header));

  // Check that the DOS header was read successfully.
  ASSERT_TRUE(header.dos_header != NULL);
  ASSERT_GE(header.dos_header->size(), sizeof(IMAGE_DOS_HEADER));
  ASSERT_EQ(BlockGraph::DATA_BLOCK, header.dos_header->type());
  // Check the underlying data.
  ASSERT_GE(header.dos_header->data_size(), sizeof(IMAGE_DOS_HEADER));
  const IMAGE_DOS_HEADER* dos_header =
      reinterpret_cast<const IMAGE_DOS_HEADER*>(header.dos_header->data());
  ASSERT_TRUE(dos_header != NULL);
  ASSERT_EQ(IMAGE_DOS_SIGNATURE, dos_header->e_magic);

  // Check the NT headers.
  ASSERT_TRUE(header.nt_headers != NULL);
  ASSERT_GT(header.nt_headers->size(), sizeof(IMAGE_NT_HEADERS));
  ASSERT_EQ(header.nt_headers->data_size(), header.nt_headers->size());
  ASSERT_EQ(BlockGraph::DATA_BLOCK, header.nt_headers->type());
  const IMAGE_NT_HEADERS* nt_headers =
      reinterpret_cast<const IMAGE_NT_HEADERS*>(header.nt_headers->data());
  ASSERT_TRUE(nt_headers != NULL);
  ASSERT_EQ(IMAGE_NT_OPTIONAL_HDR32_MAGIC, nt_headers->OptionalHeader.Magic);

  const IMAGE_SECTION_HEADER* section_headers = NULL;
  // Check that the data accounts for the image section headers.
  ASSERT_EQ(nt_headers->FileHeader.NumberOfSections * sizeof(*section_headers) +
      sizeof(*nt_headers), header.nt_headers->data_size());

  section_headers =
      reinterpret_cast<const IMAGE_SECTION_HEADER*>(nt_headers + 1);

  // Now check the various data directory sections we expect to be non NULL.
  // We know the test dll has exports.
  EXPECT_NO_FATAL_FAILURE(AssertDataDirectoryEntryValid(
      header.data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT]));
  // And imports.
  EXPECT_NO_FATAL_FAILURE(AssertDataDirectoryEntryValid(
      header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT]));
  // And resources.
  EXPECT_NO_FATAL_FAILURE(AssertDataDirectoryEntryValid(
      header.data_directory[IMAGE_DIRECTORY_ENTRY_RESOURCE]));
  // And relocs.
  EXPECT_NO_FATAL_FAILURE(AssertDataDirectoryEntryValid(
      header.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC]));
  // And a debug directory.
  EXPECT_NO_FATAL_FAILURE(AssertDataDirectoryEntryValid(
      header.data_directory[IMAGE_DIRECTORY_ENTRY_DEBUG]));
  // And a tls directory?
  // TODO(siggi): add some TLS data to the test DLL.
  // EXPECT_NO_FATAL_FAILURE(AssertDataDirectoryEntryValid(
  //     header.data_directory[IMAGE_DIRECTORY_ENTRY_TLS]));
  // And a load configuration directory.
  EXPECT_NO_FATAL_FAILURE(AssertDataDirectoryEntryValid(
      header.data_directory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG]));
  // And a delay import directory.
  EXPECT_NO_FATAL_FAILURE(AssertDataDirectoryEntryValid(
      header.data_directory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT]));
}

}  // namespace pe
