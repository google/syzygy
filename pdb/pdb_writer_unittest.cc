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

#include "syzygy/pdb/pdb_writer.h"
#include "base/file_util.h"
#include "gtest/gtest.h"
#include "syzygy/pdb/pdb_constants.h"
#include "syzygy/pdb/pdb_reader.h"

namespace {

using pdb::PdbStream;
using pdb::PdbWriter;

uint32 GetNumPages(uint32 num_bytes) {
  return (num_bytes + pdb::kPdbPageSize - 1) / pdb::kPdbPageSize;
}

class TestPdbWriter : public PdbWriter {
 public:
  TestPdbWriter() {
    FilePath path;
    file_.reset(file_util::CreateAndOpenTemporaryFile(&path));
    EXPECT_TRUE(file_.get() != NULL);
  }

  FILE* file() { return file_.get(); }

  using PdbWriter::StreamInfo;
  using PdbWriter::StreamInfoList;
  using PdbWriter::PadToPageBoundary;
  using PdbWriter::AppendStream;
  using PdbWriter::WriteDirectory;
  using PdbWriter::WriteDirectoryPages;
  using PdbWriter::WriteHeader;
};

class TestPdbStream : public PdbStream {
 public:
  explicit TestPdbStream(uint32 length) : PdbStream(length) {
  }

 protected:
  int ReadBytes(void* dest, int count) {
    if (pos() == length())
      return 0;

    count = std::min(count, length() - pos());
    memset(dest, 0xFF, count);
    Seek(pos() + count);

    return count;
  }
};

}  // namespace

using pdb::kPdbHeaderMagicString;
using pdb::kPdbPageSize;
using pdb::PdbHeader;
using pdb::PdbReader;

TEST(PdbWriterTest, Write) {
  TestPdbStream test_streams[] = {
    TestPdbStream((1 << 8) + 123),
    TestPdbStream((1 << 9) + 321),
    TestPdbStream((1 << 10) + 456),
    TestPdbStream((1 << 11) + 654)
  };
  std::vector<PdbStream*> streams;
  for (uint32 i = 0; i < arraysize(test_streams); ++i)
    streams.push_back(&test_streams[i]);

  // Test that we can create a pdb file and then read it successfully.
  FilePath path;
  EXPECT_TRUE(file_util::CreateTemporaryFile(&path));
  {
    // Create a scope so that the file gets closed.
    TestPdbWriter writer;
    EXPECT_TRUE(writer.Write(path, streams));
  }

  streams.clear();
  PdbReader reader;
  EXPECT_TRUE(reader.Read(path, &streams));
  EXPECT_EQ(arraysize(test_streams), streams.size());
}

TEST(PdbWriterTest, PadToPageBoundary) {
  // Test that the right amount is padded for the given offset.
  uint32 test_cases[][2] = {
    {0, 0},  // offset, padding.
    {1, 1023},
    {1023, 1},
    {1024, 0},
    {1025, 1023},
    {2000, 48},
    {3000, 72},
    {4000, 96}
  };

  TestPdbWriter writer;
  uint32 total_bytes = 0;
  for (uint32 i = 0; i < arraysize(test_cases); ++i) {
    uint32* test_case = test_cases[i];
    uint32 padding = 0;
    EXPECT_TRUE(writer.PadToPageBoundary("", test_case[0], &padding));
    EXPECT_EQ(test_case[1], padding);
    total_bytes += padding;
  }

  // Test that zeroes are padded successfully.
  FILE* file = writer.file();
  for (uint32 i = 0; i < total_bytes; ++i) {
    EXPECT_EQ(0, fseek(file, i, SEEK_SET));
    uint8 buffer;
    EXPECT_EQ(1, fread(&buffer, 1, 1, file));
    EXPECT_EQ(0, buffer);
  }
}

TEST(PdbWriterTest, AppendStream) {
  // Test that the bytes written corresponds to the stream length and padding.
  TestPdbWriter writer;
  size_t len = (1 << 17) + 123;
  TestPdbStream stream(len);
  uint32 bytes_written;
  EXPECT_TRUE(writer.AppendStream(&stream, &bytes_written));
  EXPECT_EQ(GetNumPages(len) * kPdbPageSize, bytes_written);

  // Test that the correct data is written.
  FILE* file = writer.file();
  for (size_t i = 0; i < len; ++i) {
    EXPECT_EQ(0, fseek(file, i, SEEK_SET));
    uint8 buffer;
    EXPECT_EQ(1, fread(&buffer, 1, 1, file));
    EXPECT_EQ(0xFF, buffer);
  }
}

TEST(PdbWriterTest, WriteDirectory) {
  uint32 stream_lengths[] = {
    kPdbPageSize + 10,
    2 * kPdbPageSize + 20,
    4 * kPdbPageSize + 40
  };

  TestPdbWriter::StreamInfoList stream_info_list;
  uint32 total_bytes = 0;
  for (uint32 i = 0; i < arraysize(stream_lengths); ++i) {
    TestPdbWriter::StreamInfo stream_info;
    stream_info.offset = total_bytes;
    stream_info.length = stream_lengths[i];
    stream_info_list.push_back(stream_info);
    total_bytes += GetNumPages(stream_lengths[i]) * kPdbPageSize;
  };

  TestPdbWriter writer;
  uint32 dir_size = 0;
  uint32 bytes_written = 0;
  EXPECT_TRUE(
      writer.WriteDirectory(stream_info_list, &dir_size, &bytes_written));

  // Test the directory size.
  // The number of streams.
  uint32 expected_dir_size = sizeof(uint32);
  // The length of each stream.
  expected_dir_size += stream_info_list.size() * sizeof(uint32);
  // The page numbers of each stream.
  for (uint32 i = 0; i < arraysize(stream_lengths); ++i) {
    expected_dir_size += GetNumPages(stream_lengths[i]) * sizeof(uint32);
  }
  EXPECT_EQ(expected_dir_size, dir_size);
  EXPECT_EQ(GetNumPages(dir_size) * kPdbPageSize, bytes_written);

  // Test the directory contents.
  FILE* file = writer.file();
  EXPECT_EQ(0, fseek(file, 0, SEEK_SET));

  uint32 num_streams;
  EXPECT_EQ(1, fread(&num_streams, sizeof(uint32), 1, file));
  EXPECT_EQ(arraysize(stream_lengths), num_streams);

  for (uint32 i = 0; i < arraysize(stream_lengths); ++i) {
    uint32 stream_length = 0;
    EXPECT_EQ(1, fread(&stream_length, sizeof(uint32), 1, file));
    EXPECT_EQ(stream_lengths[i], stream_length);
  }

  uint32 page_count = 0;
  for (uint32 i = 0; i < arraysize(stream_lengths); ++i) {
    uint32 num_pages = GetNumPages(stream_lengths[i]);
    for (uint32 j = 0; j < num_pages; ++j) {
      uint32 page_num = 0;
      EXPECT_EQ(1, fread(&page_num, sizeof(uint32), 1, file));
      EXPECT_EQ(page_count + j, page_num);
    }
    page_count += num_pages;
  }
}

TEST(PdbWriterTest, WriteDirectoryPages) {
  TestPdbWriter writer;
  uint32 dir_size = (1 << 12) + 234;
  uint32 dir_page = 15;
  uint32 dir_pages_size = 0;
  uint32 bytes_written = 0;
  EXPECT_TRUE(writer.WriteDirectoryPages(dir_size, dir_page, &dir_pages_size,
                                         &bytes_written));

  // Test the directory pages size.
  uint32 num_dir_pages = GetNumPages(dir_size);
  EXPECT_EQ(num_dir_pages * sizeof(uint32), dir_pages_size);
  EXPECT_EQ(GetNumPages(dir_pages_size) * kPdbPageSize, bytes_written);

  // Test the directory pages contents.
  FILE* file = writer.file();
  EXPECT_EQ(0, fseek(file, 0, SEEK_SET));
  for (uint32 i = 0; i < num_dir_pages; ++i) {
    uint32 page_num = 0;
    EXPECT_EQ(1, fread(&page_num, sizeof(uint32), 1, file));
    EXPECT_EQ(dir_page + i, page_num);
  }
}

TEST(PdbWriterTest, WriteHeader) {
  TestPdbWriter writer;
  uint32 file_size = 1 << 20;
  uint32 dir_size = (1 << 12) + 234;
  uint32 dir_root_size = (1 << 6) + 64;
  uint32 dir_root_page = 4;
  EXPECT_TRUE(writer.WriteHeader(file_size, dir_size, dir_root_size,
                                 dir_root_page));

  // Test the header contents.
  FILE* file = writer.file();
  EXPECT_EQ(0, fseek(file, 0, SEEK_SET));
  PdbHeader header = { 0 };
  EXPECT_EQ(1, fread(&header, sizeof(header), 1, file));

  EXPECT_EQ(0, memcmp(header.magic_string, kPdbHeaderMagicString,
                      sizeof(kPdbHeaderMagicString)));
  EXPECT_EQ(kPdbPageSize, header.page_size);
  EXPECT_EQ(1, header.free_page_map);
  EXPECT_EQ(GetNumPages(file_size), header.num_pages);
  EXPECT_EQ(dir_size, header.directory_size);
  EXPECT_EQ(0, header.reserved);

  uint32 num_dir_root_pages = GetNumPages(dir_root_size);
  for (uint32 i = 0; i < num_dir_root_pages; ++i) {
    EXPECT_EQ(dir_root_page + i, header.root_pages[i]);
  }
}
