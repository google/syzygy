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

#include "syzygy/pdb/pdb_writer.h"

#include "base/file_util.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pdb/pdb_constants.h"
#include "syzygy/pdb/pdb_data.h"
#include "syzygy/pdb/pdb_reader.h"

namespace pdb {

namespace {

uint32 GetNumPages(uint32 num_bytes) {
  return (num_bytes + pdb::kPdbPageSize - 1) / pdb::kPdbPageSize;
}

class TestPdbWriter : public PdbWriter {
 public:
  TestPdbWriter() {
    file_.reset(file_util::CreateAndOpenTemporaryFile(&path_));
    EXPECT_TRUE(file_.get() != NULL);
  }

  ~TestPdbWriter() {
    if (file_.get()) {
      fclose(file_.get());
      file_.reset();
    }
    file_util::Delete(path_, false);
  }

  file_util::ScopedFILE& file() { return file_; }

  using PdbWriter::AppendStream;
  using PdbWriter::WriteHeader;

  FilePath path_;
};

class TestPdbStream : public PdbStream {
 public:
  TestPdbStream(uint32 length, uint32 mask)
      : PdbStream(length), data_(length) {
    uint32* data = reinterpret_cast<uint32*>(data_.data());

    // Just to make sure the data is non-repeating (so we can distinguish if it
    // has been correctly written or not) fill it with integers encoding their
    // own position in the stream.
    for (size_t i = 0; i < data_.size() / sizeof(data[0]); ++i)
      data[i] = i | mask;
  }

  bool ReadBytes(void* dest, size_t count, size_t* bytes_read) {
    DCHECK(bytes_read != NULL);

    if (pos() == length()) {
      *bytes_read = 0;
      return true;
    }

    count = std::min(count, length() - pos());
    ::memcpy(dest, data_.data() + pos(), count);
    Seek(pos() + count);
    *bytes_read = count;

    return true;
  }

 private:
  std::vector<uint8> data_;
};

}  // namespace

using pdb::kPdbHeaderMagicString;
using pdb::kPdbPageSize;
using pdb::PdbHeader;
using pdb::PdbReader;

TEST(PdbWriterTest, AppendStream) {
  TestPdbWriter writer;

  testing::ScopedTempFile temp_file;
  writer.file().reset(file_util::OpenFile(temp_file.path(), "wb"));
  ASSERT_TRUE(writer.file().get() != NULL);

  scoped_refptr<PdbStream> stream(
      new TestPdbStream(4 * kPdbPageSize, 0));

  // Test writing a stream that will force allocation of the free page map
  // pages.
  std::vector<uint32> pages_written;
  uint32 page_count = 0;
  EXPECT_TRUE(writer.AppendStream(stream.get(), &pages_written, &page_count));
  writer.file().reset();

  // We expect pages_written to contain 4 pages, like the stream. However, we
  // expect page_count to have 2 more pages for the free page map.
  uint32 expected_pages_written[] = { 0, 3, 4, 5 };
  EXPECT_THAT(pages_written,
              ::testing::ElementsAreArray(expected_pages_written));
  EXPECT_EQ(page_count, 6);

  // Build the expected stream contents. Two blank pages should have been
  // reserved by the append stream routine.
  stream->Seek(0);
  std::vector<uint8> expected_contents(6 * kPdbPageSize);
  ASSERT_TRUE(stream->Read(expected_contents.data(), kPdbPageSize));
  ASSERT_TRUE(stream->Read(expected_contents.data() + 3 * kPdbPageSize,
                           3 * kPdbPageSize));

  std::vector<uint8> contents(6 * kPdbPageSize);
  ASSERT_EQ(contents.size(),
            file_util::ReadFile(temp_file.path(),
                                reinterpret_cast<char*>(contents.data()),
                                contents.size()));

  EXPECT_THAT(contents, ::testing::ContainerEq(expected_contents));
}

TEST(PdbWriterTest, WriteHeader) {
  TestPdbWriter writer;

  testing::ScopedTempFile temp_file;
  writer.file().reset(file_util::OpenFile(temp_file.path(), "wb"));
  ASSERT_TRUE(writer.file().get() != NULL);

  std::vector<uint32> root_directory_pages(kPdbMaxDirPages + 10, 1);

  // Try to write a root directorty that's too big and expect this to fail.
  EXPECT_FALSE(writer.WriteHeader(root_directory_pages, 67 * 4, 438));

  // Now write a reasonable root directory size.
  root_directory_pages.resize(1);
  EXPECT_TRUE(writer.WriteHeader(root_directory_pages, 67 * 4, 438));
  writer.file().reset();

  // Build the expected stream contents. Two blank pages should have been
  // reserved by the append stream routine.
  std::vector<uint8> expected_contents(sizeof(PdbHeader));
  PdbHeader* header = reinterpret_cast<PdbHeader*>(expected_contents.data());
  ::memcpy(header->magic_string, kPdbHeaderMagicString,
           kPdbHeaderMagicStringSize);
  header->page_size = kPdbPageSize;
  header->free_page_map = 1;
  header->num_pages = 438;
  header->directory_size = 67 * 4;
  header->root_pages[0] = 1;

  std::vector<uint8> contents(sizeof(PdbHeader));
  ASSERT_EQ(contents.size(),
            file_util::ReadFile(temp_file.path(),
                                reinterpret_cast<char*>(contents.data()),
                                contents.size()));

  EXPECT_THAT(contents, ::testing::ContainerEq(expected_contents));
}

TEST(PdbWriterTest, WritePdbFile) {
  PdbFile pdb_file;
  for (uint32 i = 0; i < 4; ++i)
    pdb_file.AppendStream(new TestPdbStream(1 << (8 + i), (i << 24)));

  // Test that we can create a pdb file and then read it successfully.
  testing::ScopedTempFile file;
  {
    // Create a scope so that the file gets closed.
    TestPdbWriter writer;
    EXPECT_TRUE(writer.Write(file.path(), pdb_file));
  }

  PdbFile pdb_file_read;
  PdbReader reader;
  EXPECT_TRUE(reader.Read(file.path(), &pdb_file_read));
  EXPECT_EQ(pdb_file.StreamCount(), pdb_file_read.StreamCount());

  for (size_t i = 0; i < pdb_file.StreamCount(); ++i) {
    PdbStream* stream = pdb_file.GetStream(i);
    PdbStream* stream_read = pdb_file_read.GetStream(i);

    ASSERT_TRUE(stream != NULL);
    ASSERT_TRUE(stream_read != NULL);

    EXPECT_EQ(stream->length(), stream_read->length());

    std::vector<uint8> data;
    std::vector<uint8> data_read;
    EXPECT_TRUE(stream->Seek(0));
    EXPECT_TRUE(stream_read->Seek(0));
    EXPECT_TRUE(stream->Read(&data, stream->length()));
    EXPECT_TRUE(stream_read->Read(&data_read, stream_read->length()));

    EXPECT_THAT(data, ::testing::ContainerEq(data_read));
  }
}

}  // namespace pdb
