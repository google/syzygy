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
#include "syzygy/pdb/pdb_util.h"

#include <objbase.h>
#include "base/path_service.h"
#include "base/scoped_native_library.h"
#include "base/win/pe_image.h"
#include "gtest/gtest.h"
#include "syzygy/pdb/pdb_byte_stream.h"
#include "syzygy/pdb/pdb_reader.h"
#include "syzygy/pe/pe_data.h"

namespace {

const wchar_t* kTestPdbFilePath =
    L"syzygy\\pdb\\test_data\\test_dll.pdb";

const wchar_t* kTestDllFilePath =
    L"syzygy\\pdb\\test_data\\test_dll.dll";

const wchar_t* kOmappedTestPdbFilePath =
    L"syzygy\\pdb\\test_data\\omapped_test_dll.pdb";

const wchar_t* kTempPdbFileName = L"temp.pdb";
const wchar_t* kTempPdbFileName2 = L"temp2.pdb";

FilePath GetSrcRelativePath(const wchar_t* path) {
  FilePath src_dir;
  PathService::Get(base::DIR_SOURCE_ROOT, &src_dir);
  return src_dir.Append(path);
}

class PdbUtilTest : public testing::Test {
 public:
  PdbUtilTest() : ALLOW_THIS_IN_INITIALIZER_LIST(process_(this)) {
  }

  void SetUp() {
    ASSERT_TRUE(::SymInitialize(process_, NULL, FALSE));

    ASSERT_HRESULT_SUCCEEDED(::CoCreateGuid(&new_guid_));

    FilePath temp_dir;
    ASSERT_TRUE(file_util::GetTempDir(&temp_dir));
    temp_pdb_file_path_ = temp_dir.Append(kTempPdbFileName);
    temp_pdb_file_path2_ = temp_dir.Append(kTempPdbFileName2);
  }

  void TearDown() {
    ASSERT_TRUE(::SymCleanup(process_));

    file_util::Delete(temp_pdb_file_path_, false);
    file_util::Delete(temp_pdb_file_path2_, false);
  }

  void VerifyOmapData(const FilePath& pdb_path,
                      const std::vector<OMAP>& omap_to_list,
                      const std::vector<OMAP>& omap_from_list) {
    DWORD64 base_address =
        ::SymLoadModuleExW(process_,
                           NULL,
                           pdb_path.value().c_str(),
                           NULL,
                           1,
                           1,
                           NULL,
                           0);
    EXPECT_NE(0, base_address);

    // Get the module info to verify that the new PDB has the GUID we specified.
    IMAGEHLP_MODULEW64 module_info = { sizeof(module_info) };
    EXPECT_TRUE(::SymGetModuleInfoW64(process_, base_address, &module_info));
    EXPECT_EQ(new_guid_, module_info.PdbSig70);

    OMAP* omap_to = NULL;
    DWORD64 omap_to_length = 0;
    OMAP* omap_from = NULL;
    DWORD64 omap_from_length = 0;
    EXPECT_TRUE(::SymGetOmaps(process_,
                              base_address,
                              &omap_to,
                              &omap_to_length,
                              &omap_from,
                              &omap_from_length));

    ASSERT_EQ(omap_to_list.size(), omap_to_length);
    EXPECT_EQ(0, memcmp(&omap_to_list[0], omap_to,
                        omap_to_list.size() * sizeof(OMAP)));
    ASSERT_EQ(omap_from_list.size(), omap_from_length);
    EXPECT_EQ(0, memcmp(&omap_from_list[0], omap_from,
                        omap_from_list.size() * sizeof(OMAP)));

    EXPECT_TRUE(::SymUnloadModule64(process_, base_address));
  }

 protected:
  HANDLE process_;
  GUID new_guid_;
  FilePath temp_pdb_file_path_;
  FilePath temp_pdb_file_path2_;
};

}  // namespace

namespace pdb {

TEST_F(PdbUtilTest, GetDbiDbgHeaderOffsetTestDll) {
  // Test the test_dll.pdb doesn't have Omap information.
  PdbReader reader;
  std::vector<PdbStream*> streams;
  EXPECT_TRUE(reader.Read(GetSrcRelativePath(kTestPdbFilePath), &streams));

  PdbStream* dbi_stream = streams[kDbiStream];
  DbiHeader dbi_header;
  EXPECT_TRUE(dbi_stream->Read(&dbi_header, 1));

  uint32 offset = GetDbiDbgHeaderOffset(dbi_header);
  EXPECT_LE(offset, dbi_stream->length() - sizeof(DbiDbgHeader));

  EXPECT_TRUE(dbi_stream->Seek(offset));
  DbiDbgHeader dbi_dbg_header;
  EXPECT_TRUE(dbi_stream->Read(&dbi_dbg_header, 1));

  EXPECT_EQ(-1, dbi_dbg_header.omap_to_src);
  EXPECT_EQ(-1, dbi_dbg_header.omap_from_src);
}

TEST_F(PdbUtilTest, GetDbiDbgHeaderOffsetOmappedTestDll) {
  // Test that omapped_test_dll.pdb does have Omap information.
  PdbReader reader;
  std::vector<PdbStream*> streams;
  EXPECT_TRUE(reader.Read(GetSrcRelativePath(kOmappedTestPdbFilePath),
                          &streams));

  PdbStream* dbi_stream = streams[kDbiStream];
  DbiHeader dbi_header;
  EXPECT_TRUE(dbi_stream->Read(&dbi_header, 1));

  uint32 offset = GetDbiDbgHeaderOffset(dbi_header);
  EXPECT_LE(offset, dbi_stream->length() - sizeof(DbiDbgHeader));

  EXPECT_TRUE(dbi_stream->Seek(offset));
  DbiDbgHeader dbi_dbg_header;
  EXPECT_TRUE(dbi_stream->Read(&dbi_dbg_header, 1));

  EXPECT_NE(-1, dbi_dbg_header.omap_to_src);
  EXPECT_NE(-1, dbi_dbg_header.omap_from_src);
}

TEST_F(PdbUtilTest, TestDllHasNoOmap) {
  // Test that test_dll.pdb has no Omap information.
  FilePath test_pdb_file_path = GetSrcRelativePath(kTestPdbFilePath);
  DWORD64 base_address =
      ::SymLoadModuleExW(process_,
                         NULL,
                         test_pdb_file_path.value().c_str(),
                         NULL,
                         1,
                         1,
                         NULL,
                         0);
  EXPECT_NE(0, base_address);

  OMAP* omap_to = NULL;
  DWORD64 omap_to_length = 0;
  OMAP* omap_from = NULL;
  DWORD64 omap_from_length = 0;
  EXPECT_FALSE(::SymGetOmaps(process_,
                             base_address,
                             &omap_to,
                             &omap_to_length,
                             &omap_from,
                             &omap_from_length));

  EXPECT_TRUE(::SymUnloadModule64(process_, base_address));
}

TEST_F(PdbUtilTest, AddOmapStreamToPdbFile) {
  // Add Omap information to test_dll.pdb and test that the output file
  // has Omap information.
  OMAP omap_to_data[] = {
    {4096, 4096},
    {5012, 5012},
    {6064, 6064},
    {7048, 240504}
  };
  std::vector<OMAP> omap_to_list(omap_to_data,
                                 omap_to_data + arraysize(omap_to_data));
  OMAP omap_from_data[] = {
    {4096, 4096},
    {5012, 5012},
    {240504, 7048}
  };
  std::vector<OMAP> omap_from_list(omap_from_data,
                                   omap_from_data + arraysize(omap_from_data));

  FilePath test_pdb_file_path = GetSrcRelativePath(kTestPdbFilePath);
  EXPECT_TRUE(AddOmapStreamToPdbFile(test_pdb_file_path,
                                     temp_pdb_file_path_,
                                     new_guid_,
                                     omap_to_list,
                                     omap_from_list));

  VerifyOmapData(temp_pdb_file_path_,
                 omap_to_list,
                 omap_from_list);
}

TEST_F(PdbUtilTest, AddOmapStreamToPdbFileWithOmap) {
  // Add Omap information to test_dll.pdb and test that the output file
  // has Omap information.
  OMAP omap_to_data[] = {
    {4096, 4096},
    {5012, 5012},
    {6064, 6064},
    {7048, 240504}
  };
  std::vector<OMAP> omap_to_list(omap_to_data,
                                 omap_to_data + arraysize(omap_to_data));
  OMAP omap_from_data[] = {
    {4096, 4096},
    {5012, 5012},
    {240504, 7048}
  };
  std::vector<OMAP> omap_from_list(omap_from_data,
                                   omap_from_data + arraysize(omap_from_data));

  FilePath test_pdb_file_path = GetSrcRelativePath(kTestPdbFilePath);
  // Write Omap to and from in the opposite order to temp.pdb.
  EXPECT_TRUE(AddOmapStreamToPdbFile(test_pdb_file_path,
                                     temp_pdb_file_path_,
                                     new_guid_,
                                     omap_from_list,
                                     omap_to_list));
  // Overwrite the Omap info in temp.pdb with Omap from and to in the correct
  // order and save it in temp2.pdb.
  EXPECT_TRUE(AddOmapStreamToPdbFile(temp_pdb_file_path_,
                                     temp_pdb_file_path2_,
                                     new_guid_,
                                     omap_to_list,
                                     omap_from_list));

  VerifyOmapData(temp_pdb_file_path2_,
                 omap_to_list,
                 omap_from_list);

  // Make sure temp.pdb and temp2.pdb have the same number of streams.
  PdbReader reader;
  std::vector<PdbStream*> streams, streams2;
  EXPECT_TRUE(reader.Read(temp_pdb_file_path_, &streams));
  EXPECT_TRUE(reader.Read(temp_pdb_file_path2_, &streams2));
  EXPECT_EQ(streams.size(), streams2.size());
}

TEST_F(PdbUtilTest, PdbHeaderMatchesImageDebugDirectory) {
  PdbReader reader;
  std::vector<PdbStream*> streams;
  EXPECT_TRUE(reader.Read(GetSrcRelativePath(kTestPdbFilePath), &streams));

  PdbInfoHeader70 header = { 0 };
  ASSERT_GE(streams.size(), kPdbHeaderInfoStream);
  EXPECT_TRUE(streams[kPdbHeaderInfoStream]->Read(&header, 1));
  EXPECT_EQ(header.version, kPdbCurrentVersion);

  std::string error;
  base::NativeLibrary test_dll =
      base::LoadNativeLibrary(GetSrcRelativePath(kTestDllFilePath),
                              &error);
  ASSERT_TRUE(test_dll != NULL);

  // Make sure the DLL is unloaded on exit.
  base::ScopedNativeLibrary test_dll_keeper(test_dll);
  base::win::PEImage image(test_dll);

  // Retrieve the NT headers to make it easy to look at them in debugger.
  const IMAGE_NT_HEADERS* nt_headers = image.GetNTHeaders();

  ASSERT_EQ(sizeof(IMAGE_DEBUG_DIRECTORY),
            image.GetImageDirectoryEntrySize(IMAGE_DIRECTORY_ENTRY_DEBUG));
  const IMAGE_DEBUG_DIRECTORY* debug_directory =
      reinterpret_cast<const IMAGE_DEBUG_DIRECTORY*>(
          image.GetImageDirectoryEntryAddr(IMAGE_DIRECTORY_ENTRY_DEBUG));

  ASSERT_EQ(IMAGE_DEBUG_TYPE_CODEVIEW, debug_directory->Type);
  ASSERT_GE(debug_directory->SizeOfData, sizeof(pe::CvInfoPdb70));

  const pe::CvInfoPdb70* cv_info =
      reinterpret_cast<const pe::CvInfoPdb70*>(
          image.RVAToAddr(debug_directory->AddressOfRawData));

  ASSERT_EQ(pe::kPdb70Signature, cv_info->cv_signature);
  ASSERT_EQ(header.signature, cv_info->signature);
  ASSERT_EQ(header.pdb_age, cv_info->pdb_age);
}

TEST_F(PdbUtilTest, ReadPdbHeader) {
  const FilePath pdb_path = GetSrcRelativePath(kTestPdbFilePath);
  PdbInfoHeader70 pdb_header;
  EXPECT_TRUE(ReadPdbHeader(pdb_path, &pdb_header));
}

}  // namespace pdb
