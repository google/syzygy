// Copyright 2014 Google Inc. All Rights Reserved.
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

#include "syzygy/ar/ar_reader.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/ar/unittest_util.h"
#include "syzygy/core/unittest_util.h"

namespace ar {

namespace {

// Test fixture.
class ArReaderTest : public testing::Test {
 public:
  virtual void SetUp() OVERRIDE {
    lib_path_ = testing::GetSrcRelativePath(testing::kArchiveFile);
  }

  base::FilePath lib_path_;
};

}  // namespace

TEST_F(ArReaderTest, InitAndBuildFileIndex) {
  ArReader reader;
  EXPECT_TRUE(reader.path().empty());
  EXPECT_TRUE(reader.symbols().empty());
  EXPECT_TRUE(reader.offsets().empty());
  EXPECT_TRUE(reader.files().empty());
  EXPECT_TRUE(reader.files_inverse().empty());

  EXPECT_TRUE(reader.Init(lib_path_));
  EXPECT_EQ(lib_path_, reader.path());
  EXPECT_EQ(testing::kArchiveSymbolCount, reader.symbols().size());
  EXPECT_EQ(testing::kArchiveFileCount, reader.offsets().size());
  EXPECT_TRUE(reader.files().empty());
  EXPECT_TRUE(reader.files_inverse().empty());

  // Check some of the symbols for accuracy.
  SymbolIndexMap symbols;
  symbols.insert(std::make_pair(std::string("_MOZ_Z_crc32"), 12));
  SymbolIndexMap::const_iterator sym_it = symbols.begin();
  for (; sym_it != symbols.end(); ++sym_it) {
    SymbolIndexMap::const_iterator sym_it2 = reader.symbols().find(
        sym_it->first);
    ASSERT_TRUE(sym_it2 != reader.symbols().end());
    EXPECT_EQ(*sym_it, *sym_it2);
  }

  // Build the filename map.
  EXPECT_TRUE(reader.BuildFileIndex());
  EXPECT_EQ(lib_path_, reader.path());
  EXPECT_EQ(testing::kArchiveSymbolCount, reader.symbols().size());
  EXPECT_EQ(testing::kArchiveFileCount, reader.offsets().size());
  EXPECT_EQ(15u, reader.files().size());
  EXPECT_EQ(15u, reader.files_inverse().size());

  // Double check the filename map inverts properly.
  for (size_t i = 0; i < reader.files().size(); ++i) {
    ArReader::FileNameMap::const_iterator it = reader.files_inverse().find(
        reader.files()[i]);
    ASSERT_TRUE(it != reader.files_inverse().end());
    EXPECT_EQ(i, it->second);
  }

  typedef std::pair<std::string, uint64> FileInfo;
  typedef std::vector<FileInfo> FileInfos;
  FileInfos expected, observed;
  expected.push_back(std::make_pair(std::string(
      "..\\..\\build\\Debug\\obj\\zlib\\zutil.obj"), 6179ul));
  expected.push_back(std::make_pair(std::string(
      "..\\..\\build\\Debug\\obj\\zlib\\uncompr.obj"), 3172ul));
  expected.push_back(std::make_pair(std::string(
      "..\\..\\build\\Debug\\obj\\zlib\\trees.obj"), 38365ul));
  expected.push_back(std::make_pair(std::string(
      "..\\..\\build\\Debug\\obj\\zlib\\inftrees.obj"), 7710ul));
  expected.push_back(std::make_pair(std::string(
      "..\\..\\build\\Debug\\obj\\zlib\\inflate.obj"), 38078ul));
  expected.push_back(std::make_pair(std::string(
      "..\\..\\build\\Debug\\obj\\zlib\\inffast.obj"), 7577ul));
  expected.push_back(std::make_pair(std::string(
      "..\\..\\build\\Debug\\obj\\zlib\\infback.obj"), 19688ul));
  expected.push_back(std::make_pair(std::string(
      "..\\..\\build\\Debug\\obj\\zlib\\gzwrite.obj"), 14454ul));
  expected.push_back(std::make_pair(std::string(
      "..\\..\\build\\Debug\\obj\\zlib\\gzread.obj"), 21369ul));
  expected.push_back(std::make_pair(std::string(
      "..\\..\\build\\Debug\\obj\\zlib\\gzlib.obj"), 17426ul));
  expected.push_back(std::make_pair(std::string(
      "..\\..\\build\\Debug\\obj\\zlib\\gzclose.obj"), 3843ul));
  expected.push_back(std::make_pair(std::string(
      "..\\..\\build\\Debug\\obj\\zlib\\deflate.obj"), 46559ul));
  expected.push_back(std::make_pair(std::string(
      "..\\..\\build\\Debug\\obj\\zlib\\crc32.obj"), 21713ul));
  expected.push_back(std::make_pair(std::string(
      "..\\..\\build\\Debug\\obj\\zlib\\compress.obj"), 4302ul));
  expected.push_back(std::make_pair(std::string(
      "..\\..\\build\\Debug\\obj\\zlib\\adler32.obj"), 6738ul));

  // Ensure that all of the streams have the name and size that we expect.
  ParsedArFileHeader header;
  DataBuffer data, data7;
  for (size_t i = 0; i < reader.offsets().size(); ++i) {
    EXPECT_TRUE(reader.HasNext());
    EXPECT_TRUE(reader.ExtractNext(&header, &data));
    EXPECT_EQ(data.size(), header.size);
    observed.push_back(std::make_pair(header.name, header.size));

    // Keep around the data from one of the streams.
    if (i == 7)
      std::swap(data, data7);
  }
  EXPECT_FALSE(reader.HasNext());
  EXPECT_THAT(observed, testing::ContainerEq(expected));

  // Ensure that a random access read works as expected.
  EXPECT_TRUE(reader.Extract(7, &header, &data));
  EXPECT_EQ(data7, data);
  EXPECT_TRUE(reader.HasNext());
}

TEST_F(ArReaderTest, NoFilenameTable) {
  base::FilePath lib = testing::GetSrcRelativePath(
      testing::kWeakSymbolArchiveFile);
  ArReader reader;
  EXPECT_TRUE(reader.Init(lib));
  EXPECT_TRUE(reader.BuildFileIndex());
  EXPECT_EQ(testing::kWeakSymbolArchiveSymbolCount, reader.symbols().size());
  EXPECT_EQ(testing::kWeakSymbolArchiveFileCount, reader.offsets().size());
  EXPECT_EQ(testing::kWeakSymbolArchiveFileCount, reader.files().size());
}

}  // namespace ar
