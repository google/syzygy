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
#include "syzygy/pdb/pdb_reader.h"
#include "base/path_service.h"
#include "gtest/gtest.h"
#include "syzygy/pdb/pdb_constants.h"

namespace pdb {

namespace {

// TODO(chrisha): Centralize this stuff!

const wchar_t kOmappedTestDllPdbFilePath[] =
    L"syzygy\\pdb\\test_data\\omapped_test_dll.pdb";

const wchar_t kTestDllPdbFilePath[] =
    L"syzygy\\pdb\\test_data\\test_dll.pdb";

FilePath GetSrcRelativePath(const wchar_t* path) {
  FilePath src_dir;
  PathService::Get(base::DIR_SOURCE_ROOT, &src_dir);
  return src_dir.Append(path);
}

class TestPdbReader : public PdbReader {
 public:
  TestPdbReader() {
  }

  FILE* file() { return file_.get(); }
  PdbHeader header() { return header_; }
  void set_header(PdbHeader header) {
    header_ = header;
  }
  uint32* directory() { return directory_.get(); }

  using PdbReader::GetFileSize;
  using PdbReader::GetNumPages;
};

}  // namespace

TEST(PdbReaderTest, ReadAndAccessors) {
  FilePath omapped_test_dll_pdb =
    GetSrcRelativePath(kOmappedTestDllPdbFilePath);

  TestPdbReader reader;
  std::vector<PdbStream*> streams;
  EXPECT_TRUE(reader.Read(omapped_test_dll_pdb, &streams));
  EXPECT_GT(streams.size(), 0U);

  // A repeated read should pass. Note that streams will be full of invalid
  // pointers.
  FilePath test_dll_pdb = GetSrcRelativePath(kTestDllPdbFilePath);
  EXPECT_TRUE(reader.Read(test_dll_pdb));
  streams = reader.streams();

  // Test that the file handle remains open.
  EXPECT_TRUE(reader.file() != NULL);

  // Test that the header has been populated.
  PdbHeader header = reader.header();
  EXPECT_GT(header.page_size, 0U);
  EXPECT_GT(header.num_pages, 0U);
  EXPECT_GT(header.directory_size, 0U);
  EXPECT_GT(header.root_pages[0], 0U);

  // Test that the directory has been populated.
  uint32* directory = reader.directory();
  EXPECT_TRUE(directory != NULL);
  uint32 num_streams = directory[0];
  EXPECT_EQ(num_streams, streams.size());

  // Test the we can access the streams.
  EXPECT_GT(reader.streams().size(), 0u);
  EXPECT_TRUE(reader.stream(0) != NULL);

  // Test that we can access the path.
  EXPECT_EQ(test_dll_pdb, reader.path());

  // Test that the reader still has a reference to the streams so that they
  // can be freed later.
  EXPECT_EQ(streams, reader.streams());
}

TEST(PdbReaderTest, GetFileSize) {
  FilePath test_dll_pdb = GetSrcRelativePath(kTestDllPdbFilePath);

  file_util::ScopedFILE file(file_util::OpenFile(test_dll_pdb, "rb"));
  EXPECT_TRUE(file.get() != NULL);

  TestPdbReader reader;
  uint32 size1;
  EXPECT_TRUE(reader.GetFileSize(file.get(), &size1));

  int64 size2;
  EXPECT_TRUE(file_util::GetFileSize(test_dll_pdb, &size2));

  EXPECT_EQ(size2, size1);
}

TEST(PdbReaderTest, GetNumPages) {
  PdbHeader header = { 0 };
  header.page_size = 4;

  TestPdbReader reader;
  reader.set_header(header);

  EXPECT_EQ(0, reader.GetNumPages(0));
  EXPECT_EQ(1, reader.GetNumPages(1));
  EXPECT_EQ(1, reader.GetNumPages(3));
  EXPECT_EQ(1, reader.GetNumPages(4));
  EXPECT_EQ(2, reader.GetNumPages(5));
  EXPECT_EQ(2, reader.GetNumPages(6));
  EXPECT_EQ(2, reader.GetNumPages(8));
  EXPECT_EQ(3, reader.GetNumPages(9));
  EXPECT_EQ(3, reader.GetNumPages(11));
}

}  // namespace pdb
