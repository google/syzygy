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
#include "sawbuck/image_util/pdb_util.h"
#include "base/path_service.h"
#include "gtest/gtest.h"
#include "sawbuck/image_util/pdb_byte_stream.h"
#include "sawbuck/image_util/pdb_reader.h"

namespace {

const wchar_t* kTestDllPdbFilePath =
    L"sawbuck\\image_util\\test_data\\test_dll.pdb";

const wchar_t* kKernel32PdbFilePath =
    L"sawbuck\\image_util\\test_data\\kernel32.pdb";

const wchar_t* kTempPdbFileName = L"temp.pdb";

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

    ASSERT_TRUE(file_util::GetTempDir(&temp_pdb_file_path_));
    temp_pdb_file_path_ = temp_pdb_file_path_.Append(kTempPdbFileName);
  }

  void TearDown() {
    ASSERT_TRUE(::SymCleanup(process_));

    file_util::Delete(temp_pdb_file_path_, false);
  }

 protected:
  HANDLE process_;
  FilePath temp_pdb_file_path_;
};

}  // namespace

TEST_F(PdbUtilTest, GetDbiDbgHeaderOffsetTestDll) {
  // Test the test_dll.pdb doesn't have Omap information.
  PdbReader reader;
  std::vector<PdbStream*> streams;
  EXPECT_TRUE(reader.Read(GetSrcRelativePath(kTestDllPdbFilePath), &streams));

  PdbStream* dbi_stream = streams[kDbiStream];
  DbiHeader dbi_header;
  EXPECT_EQ(1, dbi_stream->Read(&dbi_header, 1));

  uint32 offset = pdb_util::GetDbiDbgHeaderOffset(dbi_header);
  EXPECT_LE(offset, dbi_stream->length() - sizeof(DbiDbgHeader));

  EXPECT_TRUE(dbi_stream->Seek(offset));
  DbiDbgHeader dbi_dbg_header;
  EXPECT_EQ(1, dbi_stream->Read(&dbi_dbg_header, 1));

  EXPECT_EQ(-1, dbi_dbg_header.omap_to_src);
  EXPECT_EQ(-1, dbi_dbg_header.omap_from_src);
}

TEST_F(PdbUtilTest, DISABLED_GetDbiDbgHeaderOffsetKernel32) {
  // Test that kernel32.pdb does have Omap information.
  PdbReader reader;
  std::vector<PdbStream*> streams;
  EXPECT_TRUE(reader.Read(GetSrcRelativePath(kKernel32PdbFilePath), &streams));

  PdbStream* dbi_stream = streams[kDbiStream];
  DbiHeader dbi_header;
  EXPECT_EQ(1, dbi_stream->Read(&dbi_header, 1));

  uint32 offset = pdb_util::GetDbiDbgHeaderOffset(dbi_header);
  EXPECT_LE(offset, dbi_stream->length() - sizeof(DbiDbgHeader));

  EXPECT_TRUE(dbi_stream->Seek(offset));
  DbiDbgHeader dbi_dbg_header;
  EXPECT_EQ(1, dbi_stream->Read(&dbi_dbg_header, 1));

  EXPECT_NE(-1, dbi_dbg_header.omap_to_src);
  EXPECT_NE(-1, dbi_dbg_header.omap_from_src);
}

TEST_F(PdbUtilTest, TestDllHasNoOmap) {
  // Test that test_dll.pdb has no Omap information.
  FilePath test_dll_pdb_file_path = GetSrcRelativePath(kTestDllPdbFilePath);
  DWORD64 base_address =
      ::SymLoadModuleExW(process_,
                         NULL,
                         test_dll_pdb_file_path.value().c_str(),
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

  FilePath test_dll_pdb_file_path = GetSrcRelativePath(kTestDllPdbFilePath);
  EXPECT_TRUE(pdb_util::AddOmapStreamToPdbFile(test_dll_pdb_file_path,
                                               temp_pdb_file_path_,
                                               omap_to_list,
                                               omap_from_list));

  DWORD64 base_address =
      ::SymLoadModuleExW(process_,
                         NULL,
                         temp_pdb_file_path_.value().c_str(),
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
  EXPECT_TRUE(::SymGetOmaps(process_,
                            base_address,
                            &omap_to,
                            &omap_to_length,
                            &omap_from,
                            &omap_from_length));

  ASSERT_EQ(arraysize(omap_to_data), omap_to_length);
  EXPECT_EQ(0, memcmp(omap_to_data, omap_to, sizeof(omap_to_data)));
  ASSERT_EQ(arraysize(omap_from_data), omap_from_length);
  EXPECT_EQ(0, memcmp(omap_from_data, omap_from, sizeof(omap_from_data)));

  EXPECT_TRUE(::SymUnloadModule64(process_, base_address));
}
