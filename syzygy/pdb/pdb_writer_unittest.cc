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

#include "base/command_line.h"
#include "base/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/process/launch.h"
#include "base/strings/utf_string_conversions.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pdb/pdb_constants.h"
#include "syzygy/pdb/pdb_data.h"
#include "syzygy/pdb/pdb_reader.h"
#include "syzygy/pdb/pdb_util.h"
#include "syzygy/pdb/unittest_util.h"
#include "syzygy/pe/unittest_util.h"

namespace pdb {

namespace {

uint32 GetNumPages(uint32 num_bytes) {
  return (num_bytes + pdb::kPdbPageSize - 1) / pdb::kPdbPageSize;
}

class TestPdbWriter : public PdbWriter {
 public:
  TestPdbWriter() {
    file_.reset(base::CreateAndOpenTemporaryFile(&path_));
    EXPECT_TRUE(file_.get() != NULL);
  }

  ~TestPdbWriter() {
    if (file_.get()) {
      fclose(file_.get());
      file_.reset();
    }
    base::DeleteFile(path_, false);
  }

  base::ScopedFILE& file() { return file_; }

  using PdbWriter::AppendStream;
  using PdbWriter::WriteHeader;

  base::FilePath path_;
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

  const std::vector<uint8> data() const { return data_; }

 private:
  std::vector<uint8> data_;
};

void EnsurePdbContentsAreIdentical(const PdbFile& pdb_file,
                                   const PdbFile& pdb_file_read) {
  ASSERT_EQ(pdb_file.StreamCount(), pdb_file_read.StreamCount());

  for (size_t i = 0; i < pdb_file.StreamCount(); ++i) {
    PdbStream* stream = pdb_file.GetStream(i);
    PdbStream* stream_read = pdb_file_read.GetStream(i);

    ASSERT_TRUE(stream != NULL);
    ASSERT_TRUE(stream_read != NULL);

    ASSERT_EQ(stream->length(), stream_read->length());

    std::vector<uint8> data;
    std::vector<uint8> data_read;
    ASSERT_TRUE(stream->Seek(0));
    ASSERT_TRUE(stream_read->Seek(0));
    ASSERT_TRUE(stream->Read(&data, stream->length()));
    ASSERT_TRUE(stream_read->Read(&data_read, stream_read->length()));

    // We don't use ContainerEq because upon failure this generates a
    // ridiculously long and useless error message. We don't use memcmp because
    // it doesn't given any context as to where the failure occurs.
    for (size_t j = 0; j < data.size(); ++j)
      ASSERT_EQ(data[j], data_read[j]);
  }
}

}  // namespace

using pdb::kPdbHeaderMagicString;
using pdb::kPdbPageSize;
using pdb::PdbHeader;
using pdb::PdbReader;

TEST(PdbWriterTest, AppendStream) {
  TestPdbWriter writer;

  testing::ScopedTempFile temp_file;
  writer.file().reset(base::OpenFile(temp_file.path(), "wb"));
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
            base::ReadFile(temp_file.path(),
                                reinterpret_cast<char*>(contents.data()),
                                contents.size()));

  EXPECT_THAT(contents, ::testing::ContainerEq(expected_contents));
}

TEST(PdbWriterTest, WriteHeader) {
  TestPdbWriter writer;

  testing::ScopedTempFile temp_file;
  writer.file().reset(base::OpenFile(temp_file.path(), "wb"));
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
            base::ReadFile(temp_file.path(),
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

  ASSERT_NO_FATAL_FAILURE(
      EnsurePdbContentsAreIdentical(pdb_file, pdb_file_read));
}

TEST(PdbWriterTest, PdbStrCompatible) {
  base::FilePath test_dll_pdb =
      testing::GetSrcRelativePath(testing::kTestPdbFilePath);

  PdbFile file;
  PdbReader reader;
  ASSERT_TRUE(reader.Read(test_dll_pdb, &file));

  // We need at least 8 MB of data in the DLL to ensure that the free page map
  // requires a second page. We manually add data to it until we get to that
  // point.
  int64 test_dll_pdb_length = 0;
  ASSERT_TRUE(base::GetFileSize(test_dll_pdb, &test_dll_pdb_length));
  while (test_dll_pdb_length < 9 * 1024 * 1024) {
    file.AppendStream(new TestPdbStream(1024 * 1024, file.StreamCount()));
    test_dll_pdb_length += 1024 * 1024;
  }

  // Write the Syzygy modified PDB to disk.
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath pdb_path = temp_dir.path().Append(testing::kTestDllPdbName);
  PdbWriter writer;
  ASSERT_TRUE(writer.Write(pdb_path, file));

  // Write a new stream to disk.
  base::FilePath stream_path = temp_dir.path().AppendASCII("new_stream.dat");
  scoped_refptr<TestPdbStream> new_stream(
      new TestPdbStream(1024 * 1024, 0xff));
  {
    base::ScopedFILE stream_file(base::OpenFile(
        stream_path, "wb"));
    ASSERT_TRUE(stream_file.get() != NULL);
    ASSERT_EQ(new_stream->data().size(),
              ::fwrite(new_stream->data().data(),
                       sizeof(new_stream->data()[0]),
                       new_stream->data().size(),
                       stream_file.get()));
  }

  // Get the path to pdbstr.exe, which we redistribute in third_party.
  base::FilePath pdbstr_path =
      testing::GetSrcRelativePath(testing::kPdbStrPath);

  // Create the arguments to pdbstr.
  std::string pdb_arg = base::WideToUTF8(pdb_path.value());
  pdb_arg.insert(0, "-p:");
  std::string stream_arg = base::WideToUTF8(stream_path.value());
  stream_arg.insert(0, "-i:");

  // Add a new stream to the PDB in place. This should produce no output.
  {
    CommandLine cmd(pdbstr_path);
    cmd.AppendArg(pdb_arg);
    cmd.AppendArg(stream_arg);
    cmd.AppendArg("-w");
    cmd.AppendArg("-s:nonexistent-stream-name");

    std::string output;
    ASSERT_TRUE(base::GetAppOutput(cmd, &output));
    ASSERT_TRUE(output.empty());
  }

  // Read the pdbstr modified PDB.
  PdbFile file_read;
  ASSERT_TRUE(reader.Read(pdb_path, &file_read));

  // Add the new stream to the original PDB.
  file.AppendStream(new_stream.get());

  // Clear stream 0 (the previous directory) and stream 1 (the PDB header
  // stream). These can vary but be functionally equivalent. We only care about
  // the actual content streams, which are the rest of them.
  scoped_refptr<PdbStream> empty_stream(new TestPdbStream(0, 0));
  file.ReplaceStream(0, empty_stream.get());
  file.ReplaceStream(1, empty_stream.get());
  file_read.ReplaceStream(0, empty_stream.get());
  file_read.ReplaceStream(1, empty_stream.get());

  // Ensure that the two PDBs are identical.
  ASSERT_NO_FATAL_FAILURE(
      EnsurePdbContentsAreIdentical(file, file_read));
}

}  // namespace pdb
