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

#include "syzygy/msf/msf_writer.h"

#include <algorithm>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/msf/msf_constants.h"
#include "syzygy/msf/msf_data.h"
#include "syzygy/msf/msf_reader.h"
#include "syzygy/msf/unittest_util.h"

namespace msf {

namespace {

uint32_t GetNumPages(uint32_t num_bytes) {
  return (num_bytes + msf::kMsfPageSize - 1) / msf::kMsfPageSize;
}

class TestMsfWriter : public MsfWriter {
 public:
  TestMsfWriter() {
    file_.reset(base::CreateAndOpenTemporaryFile(&path_));
    EXPECT_TRUE(file_.get() != NULL);
  }

  ~TestMsfWriter() {
    if (file_.get()) {
      fclose(file_.get());
      file_.reset();
    }
    base::DeleteFile(path_, false);
  }

  base::ScopedFILE& file() { return file_; }

  using MsfWriter::AppendStream;
  using MsfWriter::WriteHeader;

  base::FilePath path_;
};

class TestMsfStream : public MsfStream {
 public:
  TestMsfStream(uint32_t length, uint32_t mask)
      : MsfStream(length), data_(length) {
    uint32_t* data = reinterpret_cast<uint32_t*>(data_.data());

    // Just to make sure the data is non-repeating (so we can distinguish if it
    // has been correctly written or not) fill it with integers encoding their
    // own position in the stream.
    for (size_t i = 0; i < data_.size() / sizeof(data[0]); ++i)
      data[i] = i | mask;
  }

  bool ReadBytesAt(size_t pos, size_t count, void* dest) override {
    DCHECK(dest != NULL);

    if (count > length() - pos)
      return false;

    ::memcpy(dest, data_.data() + pos, count);

    return true;
  }

 private:
  std::vector<uint8_t> data_;
};

void EnsureMsfContentsAreIdentical(const MsfFile& msf_file,
                                   const MsfFile& msf_file_read) {
  ASSERT_EQ(msf_file.StreamCount(), msf_file_read.StreamCount());

  for (size_t i = 0; i < msf_file.StreamCount(); ++i) {
    MsfStream* stream = msf_file.GetStream(i).get();
    MsfStream* stream_read = msf_file_read.GetStream(i).get();

    ASSERT_TRUE(stream != NULL);
    ASSERT_TRUE(stream_read != NULL);

    ASSERT_EQ(stream->length(), stream_read->length());

    std::vector<uint8_t> data(stream->length());
    std::vector<uint8_t> data_read(stream_read->length());
    ASSERT_TRUE(stream->ReadBytesAt(0, stream->length(), &data.at(0)));
    ASSERT_TRUE(
        stream_read->ReadBytesAt(0, stream_read->length(), &data_read.at(0)));

    // We don't use ContainerEq because upon failure this generates a
    // ridiculously long and useless error message. We don't use memcmp because
    // it doesn't give any context as to where the failure occurs.
    for (size_t j = 0; j < data.size(); ++j)
      ASSERT_EQ(data[j], data_read[j]);
  }
}

}  // namespace

using msf::kMsfHeaderMagicString;
using msf::kMsfPageSize;
using msf::MsfHeader;
using msf::MsfReader;

TEST(MsfWriterTest, AppendStream) {
  TestMsfWriter writer;

  testing::ScopedTempFile temp_file;
  writer.file().reset(base::OpenFile(temp_file.path(), "wb"));
  ASSERT_TRUE(writer.file().get() != NULL);

  scoped_refptr<MsfStream> stream(new TestMsfStream(4 * kMsfPageSize, 0));

  // Test writing a stream that will force allocation of the free page map
  // pages.
  std::vector<uint32_t> pages_written;
  uint32_t page_count = 0;
  EXPECT_TRUE(writer.AppendStream(stream.get(), &pages_written, &page_count));
  writer.file().reset();

  // We expect pages_written to contain 4 pages, like the stream. However, we
  // expect page_count to have 2 more pages for the free page map.
  uint32_t expected_pages_written[] = {0, 3, 4, 5};
  EXPECT_THAT(pages_written,
              ::testing::ElementsAreArray(expected_pages_written));
  EXPECT_EQ(page_count, 6);

  // Build the expected stream contents. Two blank pages should have been
  // reserved by the append stream routine.
  std::vector<uint8_t> expected_contents(6 * kMsfPageSize);
  ASSERT_TRUE(stream->ReadBytesAt(0, kMsfPageSize, expected_contents.data()));
  ASSERT_TRUE(stream->ReadBytesAt(kMsfPageSize, 3 * kMsfPageSize,
                                  expected_contents.data() + 3 * kMsfPageSize));

  std::vector<uint8_t> contents(6 * kMsfPageSize);
  ASSERT_EQ(
      contents.size(),
      base::ReadFile(temp_file.path(), reinterpret_cast<char*>(contents.data()),
                     contents.size()));

  EXPECT_THAT(contents, ::testing::ContainerEq(expected_contents));
}

TEST(MsfWriterTest, WriteHeader) {
  TestMsfWriter writer;

  testing::ScopedTempFile temp_file;
  writer.file().reset(base::OpenFile(temp_file.path(), "wb"));
  ASSERT_TRUE(writer.file().get() != NULL);

  std::vector<uint32_t> root_directory_pages(kMsfMaxDirPages + 10, 1);

  // Try to write a root directorty that's too big and expect this to fail.
  EXPECT_FALSE(writer.WriteHeader(root_directory_pages, 67 * 4, 438));

  // Now write a reasonable root directory size.
  root_directory_pages.resize(1);
  EXPECT_TRUE(writer.WriteHeader(root_directory_pages, 67 * 4, 438));
  writer.file().reset();

  // Build the expected stream contents. Two blank pages should have been
  // reserved by the append stream routine.
  std::vector<uint8_t> expected_contents(sizeof(MsfHeader));
  MsfHeader* header = reinterpret_cast<MsfHeader*>(expected_contents.data());
  ::memcpy(header->magic_string, kMsfHeaderMagicString,
           kMsfHeaderMagicStringSize);
  header->page_size = kMsfPageSize;
  header->free_page_map = 1;
  header->num_pages = 438;
  header->directory_size = 67 * 4;
  header->root_pages[0] = 1;

  std::vector<uint8_t> contents(sizeof(MsfHeader));
  ASSERT_EQ(
      contents.size(),
      base::ReadFile(temp_file.path(), reinterpret_cast<char*>(contents.data()),
                     contents.size()));

  EXPECT_THAT(contents, ::testing::ContainerEq(expected_contents));
}

TEST(MsfWriterTest, WriteMsfFile) {
  MsfFile msf_file;
  for (uint32_t i = 0; i < 4; ++i)
    msf_file.AppendStream(new TestMsfStream(1 << (8 + i), (i << 24)));

  // Test that we can create an MSF file and then read it successfully.
  testing::ScopedTempFile file;
  {
    // Create a scope so that the file gets closed.
    TestMsfWriter writer;
    EXPECT_TRUE(writer.Write(file.path(), msf_file));
  }

  MsfFile msf_file_read;
  MsfReader reader;
  EXPECT_TRUE(reader.Read(file.path(), &msf_file_read));

  ASSERT_NO_FATAL_FAILURE(
      testing::EnsureMsfContentsAreIdentical(msf_file, msf_file_read));
}

}  // namespace msf
