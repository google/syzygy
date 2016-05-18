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

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "base/command_line.h"
#include "base/files/scoped_temp_dir.h"
#include "base/process/launch.h"
#include "base/strings/utf_string_conversions.h"
#include "gtest/gtest.h"
#include "syzygy/msf/unittest_util.h"
#include "syzygy/pdb/pdb_file.h"
#include "syzygy/pdb/pdb_reader.h"
#include "syzygy/pdb/pdb_stream.h"
#include "syzygy/pdb/unittest_util.h"
#include "syzygy/pe/unittest_util.h"

namespace pdb {

namespace {

class TestPdbWriter : public PdbWriter {
 public:
  TestPdbWriter() {
  }

  ~TestPdbWriter() {
  }

  using PdbWriter::AppendStream;
};

class TestPdbStream : public PdbStream {
 public:
  TestPdbStream(uint32_t length, uint32_t mask)
      : PdbStream(length), data_(length) {
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

  const std::vector<uint8_t> data() const { return data_; }

 private:
  std::vector<uint8_t> data_;
};

}  // namespace

TEST(PdbWriterTest, PdbStrCompatible) {
  base::FilePath test_dll_msf =
      testing::GetSrcRelativePath(testing::kTestPdbFilePath);

  PdbFile file;
  PdbReader reader;
  ASSERT_TRUE(reader.Read(test_dll_msf, &file));

  // We need at least 8 MB of data in the DLL to ensure that the free page map
  // requires a second page. We manually add data to it until we get to that
  // point.
  int64_t test_dll_msf_length = 0;
  ASSERT_TRUE(base::GetFileSize(test_dll_msf, &test_dll_msf_length));
  while (test_dll_msf_length < 9 * 1024 * 1024) {
    file.AppendStream(new TestPdbStream(1024 * 1024, file.StreamCount()));
    test_dll_msf_length += 1024 * 1024;
  }

  // Write the Syzygy modified PDB to disk.
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath msf_path = temp_dir.path().Append(testing::kTestPdbFilePath);
  ASSERT_TRUE(base::CreateDirectory(msf_path.DirName()));
  PdbWriter writer;
  ASSERT_TRUE(writer.Write(msf_path, file));

  // Write a new stream to disk.
  base::FilePath stream_path = temp_dir.path().AppendASCII("new_stream.dat");
  scoped_refptr<TestPdbStream> new_stream(new TestPdbStream(1024 * 1024, 0xff));
  {
    base::ScopedFILE stream_file(base::OpenFile(stream_path, "wb"));
    ASSERT_TRUE(stream_file.get() != NULL);
    ASSERT_EQ(new_stream->data().size(),
              ::fwrite(new_stream->data().data(), sizeof(new_stream->data()[0]),
                       new_stream->data().size(), stream_file.get()));
  }

  // Get the path to pdbstr.exe, which we redistribute in third_party.
  base::FilePath msfstr_path =
      testing::GetSrcRelativePath(testing::kPdbStrPath);

  // Create the arguments to pdbstr.
  std::string msf_arg = base::WideToUTF8(msf_path.value());
  msf_arg.insert(0, "-p:");
  std::string stream_arg = base::WideToUTF8(stream_path.value());
  stream_arg.insert(0, "-i:");

  // Add a new stream to the PDB in place. This should produce no output.
  {
    base::CommandLine cmd(msfstr_path);
    cmd.AppendArg(msf_arg);
    cmd.AppendArg(stream_arg);
    cmd.AppendArg("-w");
    cmd.AppendArg("-s:nonexistent-stream-name");

    std::string output;
    ASSERT_TRUE(base::GetAppOutput(cmd, &output));
    ASSERT_TRUE(output.empty());
  }

  // Read the pdbstr modified PDB.
  PdbFile file_read;
  ASSERT_TRUE(reader.Read(msf_path, &file_read));

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
      testing::EnsureMsfContentsAreIdentical(file, file_read));
}

}  // namespace pdb
