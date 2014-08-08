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

#include "syzygy/pdb/pdb_file_stream.h"

#include "base/file_util.h"
#include "base/path_service.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pdb/pdb_constants.h"
#include "syzygy/pdb/pdb_data.h"
#include "syzygy/pdb/unittest_util.h"

namespace pdb {

namespace {

class TestPdbFileStream : public PdbFileStream {
 public:
  TestPdbFileStream(RefCountedFILE* file,
                    size_t length,
                    const uint32* pages,
                    size_t page_size)
      : PdbFileStream(file, length, pages, page_size) {
  }

  virtual ~TestPdbFileStream() { }

  using PdbFileStream::ReadBytes;
  using PdbFileStream::ReadFromPage;
};

class PdbFileStreamTest : public testing::Test {
 public:
  virtual void SetUp() {
    file_ = new RefCountedFILE(base::OpenFile(testing::GetSrcRelativePath(
        testing::kTestPdbFilePath), "rb"));
    ASSERT_TRUE(file_.get() != NULL);
  }

 protected:
  scoped_refptr<RefCountedFILE> file_;
};

}  // namespace

TEST_F(PdbFileStreamTest, Constructor) {
  size_t pages[] = {1, 2, 3};
  scoped_refptr<PdbFileStream> stream(new PdbFileStream(file_, 10, pages, 8));
  EXPECT_EQ(10, stream->length());
}

TEST_F(PdbFileStreamTest, ReadFromPage) {
  struct TestCase {
    uint32 page_num;
    size_t offset;
    size_t count;
    char* expected;
  };

  // Test calling ReadFromPage with different combinations of page number,
  // offset and count.
  TestCase test_cases[] = {
    {0, 0, 3, "Mic"},
    {0, 0, 4, "Micr"},
    {0, 1, 2, "ic"},
    {0, 2, 2, "cr"},
    {1, 0, 2, "os"},
    {1, 1, 3, "sof"},
    {2, 0, 4, "t C/"},
    {2, 2, 2, "C/"}
  };

  size_t pages[] = {0, 1, 2};
  size_t page_size = 4;
  scoped_refptr<TestPdbFileStream> stream(new TestPdbFileStream(
      file_, sizeof(PdbHeader), pages, page_size));

  char buffer[4] = {0};
  for (uint32 i = 0; i < arraysize(test_cases); ++i) {
    TestCase test_case = test_cases[i];
    EXPECT_TRUE(stream->ReadFromPage(&buffer, test_case.page_num,
                                     test_case.offset, test_case.count));
    EXPECT_EQ(0,
              memcmp(buffer, test_case.expected, strlen(test_case.expected)));
  }
}

TEST_F(PdbFileStreamTest, ReadBytes) {
  // Different sections of the pdb header magic string.
  char* test_cases[] = {
    "Mic",
    "roso",
    "ft",
    " C/C+",
    "+ MS",
    "F 7.00"
  };

  // Test that we can read varying sizes of bytes from the header of the
  // file with varying page sizes.
  char buffer[8] = {0};
  for (size_t page_size = 4; page_size <= 32; page_size *= 2) {
    size_t pages[] = {0, 1, 2, 3, 4, 5, 6, 7};
    scoped_refptr<TestPdbFileStream> stream(new TestPdbFileStream(
        file_.get(), sizeof(PdbHeader), pages, page_size));

    for (uint32 j = 0; j < arraysize(test_cases); ++j) {
      char* test_case = test_cases[j];
      size_t len = strlen(test_case);
      size_t bytes_read = 0;
      EXPECT_TRUE(stream->ReadBytes(&buffer, len, &bytes_read));
      EXPECT_EQ(0, memcmp(buffer, test_case, len));
      EXPECT_EQ(len, bytes_read);
    }
  }
}

}  // namespace pdb
