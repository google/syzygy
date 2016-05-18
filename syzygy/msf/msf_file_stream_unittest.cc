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

#include "syzygy/msf/msf_file_stream.h"

#include "base/path_service.h"
#include "base/files/file_util.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/msf/msf_constants.h"
#include "syzygy/msf/msf_data.h"
#include "syzygy/msf/unittest_util.h"

namespace msf {

namespace {

class TestMsfFileStream : public MsfFileStream {
 public:
  TestMsfFileStream(RefCountedFILE* file,
                    size_t length,
                    const uint32_t* pages,
                    size_t page_size)
      : MsfFileStream(file, length, pages, page_size) {}

  virtual ~TestMsfFileStream() {}

  using MsfFileStream::ReadFromPage;
};

class MsfFileStreamTest : public testing::Test {
 public:
  virtual void SetUp() {
    file_ = new RefCountedFILE(base::OpenFile(
        testing::GetSrcRelativePath(testing::kTestPdbFilePath), "rb"));
    ASSERT_TRUE(file_.get() != NULL);
  }

 protected:
  scoped_refptr<RefCountedFILE> file_;
};

}  // namespace

TEST_F(MsfFileStreamTest, Constructor) {
  size_t pages[] = {1, 2, 3};
  scoped_refptr<MsfFileStream> stream(
      new MsfFileStream(file_.get(), 10, pages, 8));
  EXPECT_EQ(10, stream->length());
}

TEST_F(MsfFileStreamTest, ReadFromPage) {
  struct TestCase {
    uint32_t page_num;
    size_t offset;
    size_t count;
    char* expected;
  };

  // Test calling ReadFromPage with different combinations of page number,
  // offset and count.
  TestCase test_cases[] = {{0, 0, 3, "Mic"},
                           {0, 0, 4, "Micr"},
                           {0, 1, 2, "ic"},
                           {0, 2, 2, "cr"},
                           {1, 0, 2, "os"},
                           {1, 1, 3, "sof"},
                           {2, 0, 4, "t C/"},
                           {2, 2, 2, "C/"}};

  size_t pages[] = {0, 1, 2};
  size_t page_size = 4;
  scoped_refptr<TestMsfFileStream> stream(
      new TestMsfFileStream(file_.get(), sizeof(MsfHeader), pages, page_size));

  char buffer[4] = {0};
  for (uint32_t i = 0; i < arraysize(test_cases); ++i) {
    TestCase test_case = test_cases[i];
    EXPECT_TRUE(stream->ReadFromPage(&buffer, test_case.page_num,
                                     test_case.offset, test_case.count));
    EXPECT_EQ(0,
              ::memcmp(buffer, test_case.expected, strlen(test_case.expected)));
  }
}

TEST_F(MsfFileStreamTest, ReadBytesAt) {
  // Different sections of the MSF header magic string.
  char* test_cases[] = {"Mic", "roso", "ft", " C/C+", "+ MS", "F 7.00"};

  // Test that we can read varying sizes of bytes from the header of the
  // file with varying page sizes.
  char buffer[8] = {0};
  for (size_t page_size = 4; page_size <= 32; page_size *= 2) {
    size_t pages[] = {0, 1, 2, 3, 4, 5, 6, 7};
    scoped_refptr<TestMsfFileStream> stream(new TestMsfFileStream(
        file_.get(), sizeof(MsfHeader), pages, page_size));

    size_t pos = 0;
    for (uint32_t j = 0; j < arraysize(test_cases); ++j) {
      char* test_case = test_cases[j];
      size_t len = strlen(test_case);
      EXPECT_TRUE(stream->ReadBytesAt(pos, len, &buffer));
      EXPECT_EQ(0U, ::memcmp(buffer, test_case, len));
      pos += len;
    }

    // Try a read past the end of the file.
    EXPECT_FALSE(stream->ReadBytesAt(sizeof(MsfHeader) - 1, 2, buffer));
  }
}

}  // namespace msf
