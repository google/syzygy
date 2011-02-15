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

FilePath GetSrcRelativePath(const wchar_t* path) {
  FilePath src_dir;
  PathService::Get(base::DIR_SOURCE_ROOT, &src_dir);
  return src_dir.Append(path);
}

}  // namespace

TEST(PdbUtilTest, GetDbiDbgHeaderOffsetTestDll) {
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

TEST(PdbUtilTest, DISABLED_GetDbiDbgHeaderOffsetKernel32) {
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
