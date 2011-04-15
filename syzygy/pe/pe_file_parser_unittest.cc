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
#include "syzygy/pe/pe_file_parser.h"

#include "base/file_path.h"
#include "base/native_library.h"
#include "base/path_service.h"
#include "base/scoped_ptr.h"
#include "base/string_util.h"
#include "base/win/pe_image.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace {

using testing::ContainerEq;

using core::BlockGraph;
using core::RelativeAddress;
using pe::PEFile;
using pe::PEFileParser;

FilePath GetExeRelativePath(const wchar_t* image_name) {
  FilePath exe_dir;
  PathService::Get(base::DIR_EXE, &exe_dir);

  return exe_dir.Append(image_name);
}

// Exposes the protected methods for testing.
class TestPEFileParser: public PEFileParser {
 public:
  TestPEFileParser(const PEFile& image_file,
                   BlockGraph::AddressSpace* address_space,
                   AddReferenceCallback* add_reference)
      : PEFileParser(image_file, address_space, add_reference) {
  }

  using PEFileParser::ParseImageHeader;
  using PEFileParser::ParseExportDir;
  using PEFileParser::ParseImportDir;
  using PEFileParser::ParseLoadConfigDir;
  using PEFileParser::ParseTlsDir;
  using PEFileParser::ParseDebugDir;
  using PEFileParser::ParseResourceDir;
};

const wchar_t kDllName[] = L"test_dll.dll";

class PEFileParserTest: public testing::Test {
 public:
  PEFileParserTest() : address_space_(&image_), loaded_image_(NULL) {
  }

  virtual void SetUp() {
    add_reference_.reset(NewCallback(this, &PEFileParserTest::AddReference));
    ASSERT_TRUE(add_reference_ != NULL);

    ASSERT_TRUE(image_file_.Init(GetExeRelativePath(kDllName)));
  }

  virtual void TearDown() {
    if (loaded_image_ != NULL)
      base::UnloadNativeLibrary(loaded_image_);
    loaded_image_ = NULL;
  }

  void AddReference(RelativeAddress src,
                    BlockGraph::ReferenceType type,
                    BlockGraph::Size size,
                    RelativeAddress dst,
                    const char* name) {
    Reference ref = { type, size, dst, name };
    bool inserted = references_.insert(std::make_pair(src, ref)).second;
    EXPECT_TRUE(inserted);
  }

  // Assert that an exported function in the test_dll is referenced
  // in the image.
  bool ExportIsReferenced(const char* function_name_or_ordinal) {
    if (loaded_image_ == NULL)
      loaded_image_ = base::LoadNativeLibrary(GetExeRelativePath(kDllName));

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
    std::string name;
  };

  typedef std::map<RelativeAddress, Reference> ReferenceMap;
  ReferenceMap references_;

  scoped_ptr<PEFileParser::AddReferenceCallback> add_reference_;
  PEFile image_file_;
  BlockGraph image_;
  BlockGraph::AddressSpace address_space_;

  base::NativeLibrary loaded_image_;
};

}  // namespace

namespace pe {

TEST_F(PEFileParserTest, ParseImageHeader) {
  TestPEFileParser parser(image_file_, &address_space_, add_reference_.get());

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
  TestPEFileParser parser(image_file_, &address_space_, add_reference_.get());

  PEFileParser::PEHeader header;
  EXPECT_TRUE(parser.ParseImageHeader(&header));

  const IMAGE_NT_HEADERS* nt_headers =
      reinterpret_cast<const IMAGE_NT_HEADERS*>(header.nt_headers->data());

  const IMAGE_DATA_DIRECTORY& dir =
      nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  EXPECT_TRUE(parser.ParseExportDir(dir) != NULL);

  loaded_image_ = base::LoadNativeLibrary(GetExeRelativePath(kDllName));
  ASSERT_TRUE(loaded_image_ != NULL);

  ASSERT_TRUE(ExportIsReferenced("function1"));
  // function2 is exported by ordinal only.
  ASSERT_TRUE(ExportIsReferenced(reinterpret_cast<const char*>(7)));
  ASSERT_TRUE(ExportIsReferenced("function3"));
}

TEST_F(PEFileParserTest, ParseImportDir) {
  TestPEFileParser parser(image_file_, &address_space_, add_reference_.get());

  PEFileParser::PEHeader header;
  EXPECT_TRUE(parser.ParseImageHeader(&header));

  const IMAGE_NT_HEADERS* nt_headers =
      reinterpret_cast<const IMAGE_NT_HEADERS*>(header.nt_headers->data());

  const IMAGE_DATA_DIRECTORY& dir =
      nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  BlockGraph::Block* block = parser.ParseImportDir(dir);
  ASSERT_TRUE(block != NULL);

  // Test that we have the import descriptors we expect.
  size_t num_descriptors = block->size() / sizeof(IMAGE_IMPORT_DESCRIPTOR);
  ASSERT_EQ(2, num_descriptors);
  ASSERT_TRUE(block->data() != NULL);
  ASSERT_EQ(block->size(), block->data_size());

  std::set<std::string> import_names;
  for (size_t i = 0; i < num_descriptors; ++i) {
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

  std::set<std::string> expected;
  expected.insert("export_dll.dll");
  expected.insert("KERNEL32.dll");
  EXPECT_THAT(import_names, ContainerEq(expected));
}

TEST_F(PEFileParserTest, ParseImage) {
  TestPEFileParser parser(image_file_, &address_space_, add_reference_.get());

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
  // TODO(siggi): add some delay import configuration to the test DLL.
  // EXPECT_NO_FATAL_FAILURE(AssertDataDirectoryEntryValid(
  //     header.data_directory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT]));
}

}  // namespace pe
