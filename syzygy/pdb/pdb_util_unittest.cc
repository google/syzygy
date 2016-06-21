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

#include "syzygy/pdb/pdb_util.h"

#include <objbase.h>
#include <vector>

#include "base/command_line.h"
#include "base/path_service.h"
#include "base/scoped_native_library.h"
#include "base/files/scoped_temp_dir.h"
#include "base/process/launch.h"
#include "base/strings/utf_string_conversions.h"
#include "base/win/pe_image.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/common/dbghelp_util.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pdb/pdb_byte_stream.h"
#include "syzygy/pdb/pdb_reader.h"
#include "syzygy/pdb/pdb_stream_reader.h"
#include "syzygy/pdb/pdb_writer.h"
#include "syzygy/pdb/unittest_util.h"
#include "syzygy/pe/pe_data.h"
#include "syzygy/pe/unittest_util.h"

namespace pdb {

namespace {

const wchar_t* kTempPdbFileName = L"temp.pdb";
const wchar_t* kTempPdbFileName2 = L"temp2.pdb";

const GUID kSampleGuid = {0xACDC900D, 0x9009, 0xFEED, {7, 6, 5, 4, 3, 2, 1, 0}};

const PdbInfoHeader70 kSamplePdbHeader = {
  kPdbCurrentVersion,
  1336402486,  // 7 May 2012, 14:54:00 GMT.
  999,
  {0xDEADBEEF, 0x900D, 0xF00D, {0, 1, 2, 3, 4, 5, 6, 7}}
};

const DbiHeader kSampleDbiHeader = {
  -1,   // signature.
  19990903,  // version.
  999,  // age.
};

const OMAP kOmapToData[] = {
  {4096, 4096},
  {5012, 5012},
  {6064, 6064},
  {7048, 240504}
};

const OMAP kOmapFromData[] = {
  {4096, 4096},
  {5012, 5012},
  {240504, 7048}
};

class PdbUtilTest : public testing::Test {
 public:
  PdbUtilTest() : process_(this) {
  }

  void SetUp() {
    ASSERT_TRUE(common::SymInitialize(process_, NULL, false));

    ASSERT_HRESULT_SUCCEEDED(::CoCreateGuid(&new_guid_));
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());

    temp_pdb_file_path_ = temp_dir_.path().Append(kTempPdbFileName);
    temp_pdb_file_path2_ = temp_dir_.path().Append(kTempPdbFileName2);
  }

  void TearDown() {
    ASSERT_TRUE(::SymCleanup(process_));
  }

  void VerifyGuidData(const base::FilePath& pdb_path,
                      const GUID& guid) {
    DWORD64 base_address =
        ::SymLoadModuleExW(process_,
                           NULL,
                           pdb_path.value().c_str(),
                           NULL,
                           1,
                           1,
                           NULL,
                           0);
    EXPECT_NE(0, base_address);

    // Get the module info to verify that the new PDB has the GUID we specified.
    IMAGEHLP_MODULEW64 module_info = { sizeof(module_info) };
    EXPECT_TRUE(::SymGetModuleInfoW64(process_, base_address, &module_info));
    EXPECT_EQ(new_guid_, module_info.PdbSig70);

    EXPECT_TRUE(::SymUnloadModule64(process_, base_address));
  }

  void VerifyOmapData(const base::FilePath& pdb_path,
                      const std::vector<OMAP>& omap_to_list,
                      const std::vector<OMAP>& omap_from_list) {
    DWORD64 base_address =
        ::SymLoadModuleExW(process_,
                           NULL,
                           pdb_path.value().c_str(),
                           NULL,
                           1,
                           1,
                           NULL,
                           0);
    ASSERT_NE(0, base_address);

    OMAP* omap_to = NULL;
    DWORD64 omap_to_length = 0;
    OMAP* omap_from = NULL;
    DWORD64 omap_from_length = 0;
    ASSERT_TRUE(::SymGetOmaps(process_,
                              base_address,
                              &omap_to,
                              &omap_to_length,
                              &omap_from,
                              &omap_from_length));

    ASSERT_EQ(omap_to_list.size(), omap_to_length);
    EXPECT_EQ(0, memcmp(&omap_to_list[0], omap_to,
                        omap_to_list.size() * sizeof(OMAP)));
    ASSERT_EQ(omap_from_list.size(), omap_from_length);
    EXPECT_EQ(0, memcmp(&omap_from_list[0], omap_from,
                        omap_from_list.size() * sizeof(OMAP)));

    EXPECT_TRUE(::SymUnloadModule64(process_, base_address));
  }

 protected:
  HANDLE process_;
  GUID new_guid_;
  base::ScopedTempDir temp_dir_;
  base::FilePath temp_pdb_file_path_;
  base::FilePath temp_pdb_file_path2_;
};

class TestPdbStream : public PdbStream {
 public:
  TestPdbStream() : PdbStream(0), bytes_(NULL) {
  }

  template <typename T>
  explicit TestPdbStream(const T& t)
      : PdbStream(sizeof(T)), bytes_(reinterpret_cast<const uint8_t*>(&t)) {}

  explicit TestPdbStream(const std::vector<char>& data)
      : PdbStream(data.size()),
        bytes_(reinterpret_cast<const uint8_t*>(&data.at(0))) {}

  bool ReadBytesAt(size_t pos, size_t count, void* dest) override {
    if (count > length() - pos)
      return false;
    ::memcpy(dest, bytes_ + pos, count);
    return true;
  }

 private:
  const uint8_t* const bytes_;
};

// Comparison operator for PdbInfoHeader70 objects.
bool AreEqual(const PdbInfoHeader70& header1,
              const PdbInfoHeader70& header2) {
  return ::memcmp(&header1, &header2, sizeof(header1)) == 0;
}

}  // namespace

TEST(PdbBitSetTest, ReadEmptyStream) {
  scoped_refptr<PdbStream> stream(new TestPdbStream());
  pdb::PdbStreamReaderWithPosition reader(stream.get());

  PdbBitSet bs;
  EXPECT_FALSE(bs.Read(&reader));
}

TEST(PdbBitSetTest, SimpleMutators) {
  PdbBitSet bs;
  EXPECT_TRUE(bs.IsEmpty());
  EXPECT_EQ(bs.size(), 0u);
  bs.Resize(43);
  EXPECT_EQ(bs.size(), 64u);

  for (size_t i = 0; i < 64; ++i)
    EXPECT_FALSE(bs.IsSet(i));

  bs.Toggle(15);
  EXPECT_TRUE(bs.IsSet(15));
  bs.Toggle(15);
  EXPECT_FALSE(bs.IsSet(15));

  bs.Set(25);
  EXPECT_TRUE(bs.IsSet(25));
  bs.Clear(25);
  EXPECT_FALSE(bs.IsSet(25));

  for (size_t i = 0; i < 64; i += 10)
    bs.Set(i);

  for (size_t i = 0; i < 64; ++i)
    EXPECT_EQ((i % 10) == 0, bs.IsSet(i));
}

TEST(PdbBitSetTest, ReadEmptyBitSet) {
  const uint32_t kSize = 0;
  scoped_refptr<PdbStream> stream(new TestPdbStream(kSize));
  pdb::PdbStreamReaderWithPosition reader(stream.get());
  PdbBitSet bs;
  EXPECT_TRUE(bs.Read(&reader));
  EXPECT_TRUE(bs.IsEmpty());
  EXPECT_EQ(bs.size(), 0u);
}

TEST(PdbBitSetTest, ReadSingleDwordBitSet) {
  const uint32_t kData[] = {1, (1 << 0) | (1 << 5) | (1 << 13)};
  scoped_refptr<PdbStream> stream(new TestPdbStream(kData));
  pdb::PdbStreamReaderWithPosition reader(stream.get());
  PdbBitSet bs;
  EXPECT_TRUE(bs.Read(&reader));
  EXPECT_FALSE(bs.IsEmpty());
  EXPECT_EQ(bs.size(), 32u);
  for (size_t i = 0; i < bs.size(); ++i)
    EXPECT_EQ(i == 0 || i == 5 || i == 13, bs.IsSet(i));
}

TEST(PdbBitSetTest, ReadMultiDwordBitSet) {
  const uint32_t kData[] = {2, (1 << 0) | (1 << 5) | (1 << 13), (1 << 5)};
  scoped_refptr<PdbStream> stream(new TestPdbStream(kData));
  pdb::PdbStreamReaderWithPosition reader(stream.get());
  PdbBitSet bs;
  EXPECT_TRUE(bs.Read(&reader));
  EXPECT_FALSE(bs.IsEmpty());
  EXPECT_EQ(bs.size(), 64u);
  for (size_t i = 0; i < bs.size(); ++i)
    EXPECT_EQ(i == 0 || i == 5 || i == 13 || i == (32 + 5), bs.IsSet(i));
}

TEST(PdbBitSetTest, WriteEmptyBitSet) {
  const uint32_t kData[] = {0};
  scoped_refptr<PdbStream> stream(new TestPdbStream(kData));
  pdb::PdbStreamReaderWithPosition reader(stream.get());
  PdbBitSet bs;
  EXPECT_TRUE(bs.Read(&reader));

  scoped_refptr<PdbByteStream> new_stream(new PdbByteStream());
  scoped_refptr<WritablePdbStream> writer(new_stream->GetWritableStream());
  EXPECT_TRUE(bs.Write(writer.get(), true));
  EXPECT_EQ(sizeof(kData), new_stream->length());

  uint32_t data[arraysize(kData)] = {};
  EXPECT_TRUE(new_stream->ReadBytesAt(0, sizeof(data), data));
  EXPECT_THAT(data, testing::ElementsAreArray(kData));
}

TEST(PdbBitSetTest, WriteEmptyBitSetWithoutSize) {
  const uint32_t kData[] = {0};
  scoped_refptr<PdbStream> stream(new TestPdbStream(kData));
  pdb::PdbStreamReaderWithPosition reader(stream.get());
  PdbBitSet bs;
  EXPECT_TRUE(bs.Read(&reader));

  scoped_refptr<PdbByteStream> new_stream(new PdbByteStream());
  scoped_refptr<WritablePdbStream> writer(new_stream->GetWritableStream());
  EXPECT_TRUE(bs.Write(writer.get(), false));

  EXPECT_EQ(0, new_stream->length());
}

TEST(PdbBitSetTest, WriteBitSet) {
  const uint32_t kData[] = {2, (1 << 0) | (1 << 5) | (1 << 13), (1 << 5)};
  scoped_refptr<PdbStream> stream(new TestPdbStream(kData));
  pdb::PdbStreamReaderWithPosition reader(stream.get());
  PdbBitSet bs;
  EXPECT_TRUE(bs.Read(&reader));

  scoped_refptr<PdbByteStream> new_stream(new PdbByteStream());
  scoped_refptr<WritablePdbStream> writer(new_stream->GetWritableStream());
  EXPECT_TRUE(bs.Write(writer.get(), true));
  EXPECT_EQ(sizeof(kData), new_stream->length());

  uint32_t data[arraysize(kData)] = {};
  EXPECT_TRUE(new_stream->ReadBytesAt(0, sizeof(data), data));
  EXPECT_THAT(data, testing::ElementsAreArray(kData));
}

TEST(PdbBitSetTest, WriteBitSetWithoutSize) {
  const uint32_t kInputData[] = {2, (1 << 0) | (1 << 5) | (1 << 13), (1 << 5)};
  const uint32_t kExpectedData[] = {(1 << 0) | (1 << 5) | (1 << 13), (1 << 5)};
  scoped_refptr<PdbStream> stream(new TestPdbStream(kInputData));
  pdb::PdbStreamReaderWithPosition reader(stream.get());
  PdbBitSet bs;
  EXPECT_TRUE(bs.Read(&reader));

  scoped_refptr<PdbByteStream> new_stream(new PdbByteStream());
  scoped_refptr<WritablePdbStream> writer(new_stream->GetWritableStream());
  EXPECT_TRUE(bs.Write(writer.get(), false));
  EXPECT_EQ(sizeof(kExpectedData), new_stream->length());

  uint32_t data[arraysize(kExpectedData)] = {};
  EXPECT_TRUE(new_stream->ReadBytesAt(0, sizeof(data), data));
  EXPECT_THAT(data, testing::ElementsAreArray(kExpectedData));
}

TEST_F(PdbUtilTest, HashString) {
  EXPECT_EQ(1024, HashString(""));
  EXPECT_EQ(20527, HashString("___onexitend"));
  EXPECT_EQ(24736, HashString("__imp____getmainargs"));
  EXPECT_EQ(61647, HashString("___security_cookie"));
}

TEST_F(PdbUtilTest, GetDbiDbgHeaderOffsetTestDll) {
  // Test the test_dll.dll.pdb doesn't have Omap information.
  PdbReader reader;
  PdbFile pdb_file;
  EXPECT_TRUE(reader.Read(
      testing::GetSrcRelativePath(testing::kTestPdbFilePath),
      &pdb_file));

  PdbStream* dbi_stream = pdb_file.GetStream(kDbiStream).get();
  DbiHeader dbi_header;
  EXPECT_TRUE(dbi_stream->ReadBytesAt(0, sizeof(dbi_header), &dbi_header));

  uint32_t offset = GetDbiDbgHeaderOffset(dbi_header);
  EXPECT_LE(offset, dbi_stream->length() - sizeof(DbiDbgHeader));

  DbiDbgHeader dbi_dbg_header;
  EXPECT_TRUE(
      dbi_stream->ReadBytesAt(offset, sizeof(dbi_dbg_header), &dbi_dbg_header));

  EXPECT_EQ(-1, dbi_dbg_header.omap_to_src);
  EXPECT_EQ(-1, dbi_dbg_header.omap_from_src);
}

TEST_F(PdbUtilTest, GetDbiDbgHeaderOffsetOmappedTestDll) {
  // Test that omapped_test_dll.dll.pdb does have Omap information.
  PdbReader reader;
  PdbFile pdb_file;
  EXPECT_TRUE(reader.Read(
      testing::GetSrcRelativePath(testing::kOmappedTestPdbFilePath),
      &pdb_file));

  PdbStream* dbi_stream = pdb_file.GetStream(kDbiStream).get();
  DbiHeader dbi_header;
  EXPECT_TRUE(dbi_stream->ReadBytesAt(0, sizeof(dbi_header), &dbi_header));

  uint32_t offset = GetDbiDbgHeaderOffset(dbi_header);
  EXPECT_LE(offset, dbi_stream->length() - sizeof(DbiDbgHeader));

  DbiDbgHeader dbi_dbg_header;
  EXPECT_TRUE(
      dbi_stream->ReadBytesAt(offset, sizeof(dbi_dbg_header), &dbi_dbg_header));

  EXPECT_NE(-1, dbi_dbg_header.omap_to_src);
  EXPECT_NE(-1, dbi_dbg_header.omap_from_src);
}

TEST_F(PdbUtilTest, TestDllHasNoOmap) {
  // Test that test_dll.dll.pdb has no Omap information.
  base::FilePath test_pdb_file_path = testing::GetSrcRelativePath(
      testing::kTestPdbFilePath);
  DWORD64 base_address =
      ::SymLoadModuleExW(process_,
                         NULL,
                         test_pdb_file_path.value().c_str(),
                         NULL,
                         1,
                         1,
                         NULL,
                         0);
  EXPECT_NE(0, base_address);

  OMAP* omap_to = NULL;
  DWORD64 omap_to_length = 0;
  OMAP* omap_from = NULL;
  DWORD64 omap_from_length = 0;
  EXPECT_FALSE(::SymGetOmaps(process_,
                             base_address,
                             &omap_to,
                             &omap_to_length,
                             &omap_from,
                             &omap_from_length));

  EXPECT_TRUE(::SymUnloadModule64(process_, base_address));
}

TEST_F(PdbUtilTest, SetOmapToAndFromStream) {
  // Add Omap information to test_dll.pdb and test that the output file
  // has Omap information.
  std::vector<OMAP> omap_to_list(kOmapToData,
                                 kOmapToData + arraysize(kOmapToData));
  std::vector<OMAP> omap_from_list(kOmapFromData,
                                   kOmapFromData + arraysize(kOmapFromData));

  base::FilePath test_pdb_file_path = testing::GetSrcRelativePath(
      testing::kTestPdbFilePath);
  PdbReader pdb_reader;
  PdbFile pdb_file;
  ASSERT_TRUE(pdb_reader.Read(test_pdb_file_path, &pdb_file));

  EXPECT_TRUE(SetOmapToStream(omap_to_list, &pdb_file));
  EXPECT_TRUE(SetOmapFromStream(omap_from_list, &pdb_file));

  PdbWriter pdb_writer;
  ASSERT_TRUE(pdb_writer.Write(temp_pdb_file_path_, pdb_file));

  VerifyOmapData(temp_pdb_file_path_,
                 omap_to_list,
                 omap_from_list);
}

TEST_F(PdbUtilTest, PdbHeaderMatchesImageDebugDirectory) {
  PdbReader reader;
  PdbFile pdb_file;
  EXPECT_TRUE(reader.Read(
      testing::GetSrcRelativePath(testing::kTestPdbFilePath),
      &pdb_file));

  PdbInfoHeader70 header = { 0 };
  ASSERT_GE(pdb_file.StreamCount(), kPdbHeaderInfoStream);
  ASSERT_TRUE(pdb_file.GetStream(kPdbHeaderInfoStream) != NULL);
  EXPECT_TRUE(pdb_file.GetStream(kPdbHeaderInfoStream)
                  ->ReadBytesAt(0, sizeof(header), &header));
  EXPECT_EQ(header.version, kPdbCurrentVersion);

  base::NativeLibraryLoadError error;
  base::NativeLibrary test_dll =
      base::LoadNativeLibrary(
          testing::GetSrcRelativePath(testing::kTestDllFilePath),
          &error);
  ASSERT_TRUE(test_dll != NULL);

  // Make sure the DLL is unloaded on exit.
  base::ScopedNativeLibrary test_dll_keeper(test_dll);
  base::win::PEImage image(test_dll);

  ASSERT_EQ(sizeof(IMAGE_DEBUG_DIRECTORY),
            image.GetImageDirectoryEntrySize(IMAGE_DIRECTORY_ENTRY_DEBUG));
  const IMAGE_DEBUG_DIRECTORY* debug_directory =
      reinterpret_cast<const IMAGE_DEBUG_DIRECTORY*>(
          image.GetImageDirectoryEntryAddr(IMAGE_DIRECTORY_ENTRY_DEBUG));

  ASSERT_EQ(IMAGE_DEBUG_TYPE_CODEVIEW, debug_directory->Type);
  ASSERT_GE(debug_directory->SizeOfData, sizeof(pe::CvInfoPdb70));

  const pe::CvInfoPdb70* cv_info =
      reinterpret_cast<const pe::CvInfoPdb70*>(
          image.RVAToAddr(debug_directory->AddressOfRawData));

  ASSERT_EQ(pe::kPdb70Signature, cv_info->cv_signature);
  ASSERT_EQ(header.signature, cv_info->signature);
  ASSERT_EQ(header.pdb_age, cv_info->pdb_age);
}

TEST_F(PdbUtilTest, ReadPdbHeader) {
  const base::FilePath pdb_path = testing::GetSrcRelativePath(
      testing::kTestPdbFilePath);
  PdbInfoHeader70 pdb_header = {};
  EXPECT_TRUE(ReadPdbHeader(pdb_path, &pdb_header));
}

TEST(EnsureStreamWritableTest, DoesNothingWhenAlreadyWritable) {
  PdbFile pdb_file;
  scoped_refptr<PdbStream> stream = new PdbByteStream();
  size_t index = pdb_file.AppendStream(stream.get());
  EXPECT_TRUE(EnsureStreamWritable(index, &pdb_file));
  scoped_refptr<PdbStream> stream2 = pdb_file.GetStream(index);
  EXPECT_EQ(stream.get(), stream2.get());
}

TEST(EnsureStreamWritableTest, WorksWhenReadOnly) {
  PdbFile pdb_file;
  scoped_refptr<PdbStream> stream = new TestPdbStream();
  size_t index = pdb_file.AppendStream(stream.get());
  EXPECT_TRUE(EnsureStreamWritable(index, &pdb_file));
  scoped_refptr<PdbStream> stream2 = pdb_file.GetStream(index);
  EXPECT_TRUE(stream2.get() != NULL);
  EXPECT_NE(stream.get(), stream2.get());
  EXPECT_TRUE(stream2->GetWritableStream() != NULL);
}

TEST(EnsureStreamWritableTest, FailsWhenNonExistent) {
  PdbFile pdb_file;
  EXPECT_FALSE(EnsureStreamWritable(45, &pdb_file));
}

TEST(SetGuidTest, FailsWhenStreamsDoNotExist) {
  PdbFile pdb_file;

  // Leave the Pdb header missing.
  pdb_file.SetStream(kPdbHeaderInfoStream, NULL);
  pdb_file.SetStream(kDbiStream, new TestPdbStream(kSampleDbiHeader));
  EXPECT_FALSE(SetGuid(kSampleGuid, &pdb_file));

  // Add the header stream, but leave the Dbi header missing.
  pdb_file.SetStream(kPdbHeaderInfoStream, new TestPdbStream(kSamplePdbHeader));
  pdb_file.SetStream(kDbiStream, NULL);
  EXPECT_FALSE(SetGuid(kSampleGuid, &pdb_file));
}

TEST(SetGuidTest, FailsWhenStreamsAreTooShort) {
  PdbFile pdb_file;

  const uint8_t kByte = 6;
  pdb_file.SetStream(kPdbHeaderInfoStream, new TestPdbStream(kByte));
  pdb_file.SetStream(kDbiStream, new TestPdbStream(kSampleDbiHeader));
  EXPECT_FALSE(SetGuid(kSampleGuid, &pdb_file));

  pdb_file.SetStream(kPdbHeaderInfoStream, new TestPdbStream(kSamplePdbHeader));
  pdb_file.SetStream(kDbiStream, new TestPdbStream(kByte));
  EXPECT_FALSE(SetGuid(kSampleGuid, &pdb_file));
}

TEST(SetGuidTest, Succeeds) {
  PdbFile pdb_file;

  pdb_file.SetStream(kPdbHeaderInfoStream, new TestPdbStream(kSamplePdbHeader));
  pdb_file.SetStream(kDbiStream, new TestPdbStream(kSampleDbiHeader));

  scoped_refptr<PdbStream> stream =
      pdb_file.GetStream(kPdbHeaderInfoStream);
  ASSERT_TRUE(stream.get() != NULL);
  ASSERT_EQ(stream->length(), sizeof(PdbInfoHeader70));

  uint32_t time1 = static_cast<uint32_t>(time(NULL));
  EXPECT_TRUE(SetGuid(kSampleGuid, &pdb_file));
  uint32_t time2 = static_cast<uint32_t>(time(NULL));

  // Read the new header.
  PdbInfoHeader70 pdb_header = {};
  stream = pdb_file.GetStream(kPdbHeaderInfoStream);
  EXPECT_TRUE(stream->ReadBytesAt(0, sizeof(pdb_header), &pdb_header));

  // Validate that the fields are as expected.
  EXPECT_LE(time1, pdb_header.timestamp);
  EXPECT_LE(pdb_header.timestamp, time2);
  EXPECT_EQ(1u, pdb_header.pdb_age);
  EXPECT_EQ(kSampleGuid, pdb_header.signature);

  DbiHeader dbi_header = {};
  stream = pdb_file.GetStream(kDbiStream);
  ASSERT_TRUE(stream.get() != NULL);
  ASSERT_EQ(stream->length(), sizeof(dbi_header));

  EXPECT_TRUE(stream->ReadBytesAt(0, sizeof(dbi_header), &dbi_header));
  EXPECT_EQ(1u, dbi_header.age);
}

TEST(ReadHeaderInfoStreamTest, ReadFromPdbFile) {
  const base::FilePath pdb_path = testing::GetSrcRelativePath(
      testing::kTestPdbFilePath);

  PdbFile pdb_file;
  PdbReader pdb_reader;
  ASSERT_TRUE(pdb_reader.Read(pdb_path, &pdb_file));

  PdbInfoHeader70 pdb_header = {};
  NameStreamMap name_stream_map;
  EXPECT_TRUE(ReadHeaderInfoStream(pdb_file, &pdb_header, &name_stream_map));
}

TEST(ReadHeaderInfoStreamTest, ReadEmptyStream) {
  scoped_refptr<PdbStream> stream(new TestPdbStream());
  PdbInfoHeader70 pdb_header = {};
  NameStreamMap name_stream_map;
  EXPECT_FALSE(
      ReadHeaderInfoStream(stream.get(), &pdb_header, &name_stream_map));
}

TEST(ReadHeaderInfoStreamTest, ReadStreamWithOnlyHeader) {
  scoped_refptr<PdbStream> reader(new PdbByteStream());
  scoped_refptr<WritablePdbStream> writer(reader->GetWritableStream());

  PdbInfoHeader70 pdb_header = {};
  ASSERT_TRUE(writer->Write(pdb_header));

  NameStreamMap name_stream_map;
  EXPECT_FALSE(
      ReadHeaderInfoStream(reader.get(), &pdb_header, &name_stream_map));
}

TEST(ReadHeaderInfoStreamTest, ReadStreamWithEmptyNameStreamMap) {
  scoped_refptr<PdbStream> reader(new PdbByteStream());
  scoped_refptr<WritablePdbStream> writer(reader->GetWritableStream());

  PdbInfoHeader70 pdb_header = {};
  ASSERT_TRUE(writer->Write(pdb_header));
  ASSERT_TRUE(writer->Write(static_cast<uint32_t>(0)));  // total string length.
  ASSERT_TRUE(writer->Write(static_cast<uint32_t>(0)));  // number of names.
  ASSERT_TRUE(writer->Write(static_cast<uint32_t>(0)));  // size of bitsets.
  ASSERT_TRUE(writer->Write(static_cast<uint32_t>(0)));  // first bitset.
  ASSERT_TRUE(writer->Write(static_cast<uint32_t>(0)));  // second bitset.

  NameStreamMap name_stream_map;
  EXPECT_TRUE(
      ReadHeaderInfoStream(reader.get(), &pdb_header, &name_stream_map));
  EXPECT_EQ(name_stream_map.size(), 0u);
}

TEST(ReadHeaderInfoStreamTest, ReadStreamWithNameStreamMap) {
  scoped_refptr<PdbStream> reader(new PdbByteStream());
  scoped_refptr<WritablePdbStream> writer(reader->GetWritableStream());

  PdbInfoHeader70 pdb_header = {};
  ASSERT_TRUE(writer->Write(pdb_header));
  ASSERT_TRUE(writer->Write(static_cast<uint32_t>(9)));  // total string length.
  uint32_t offset1 = writer->pos();
  ASSERT_TRUE(writer->Write(3, "/a"));  // name 1.
  uint32_t offset2 = writer->pos();
  ASSERT_TRUE(writer->Write(3, "/b"));  // name 2.
  uint32_t offset3 = writer->pos();
  ASSERT_TRUE(writer->Write(3, "/c"));  // name 3.
  ASSERT_TRUE(writer->Write(static_cast<uint32_t>(3)));  // number of names.
  ASSERT_TRUE(writer->Write(static_cast<uint32_t>(3)));  // size of bitsets.

  PdbBitSet present;
  present.Resize(3);
  present.Set(0);
  present.Set(1);
  present.Set(2);
  ASSERT_TRUE(present.Write(writer.get(), true));

  ASSERT_TRUE(writer->Write(static_cast<uint32_t>(0)));  // second bitset.

  ASSERT_TRUE(writer->Write(0));
  ASSERT_TRUE(writer->Write(static_cast<uint32_t>(42)));
  ASSERT_TRUE(writer->Write(offset2 - offset1));
  ASSERT_TRUE(writer->Write(static_cast<uint32_t>(7)));
  ASSERT_TRUE(writer->Write(offset3 - offset1));
  ASSERT_TRUE(writer->Write(static_cast<uint32_t>(95)));

  NameStreamMap name_stream_map;
  EXPECT_TRUE(
      ReadHeaderInfoStream(reader.get(), &pdb_header, &name_stream_map));

  NameStreamMap expected;
  expected["/a"] = 42;
  expected["/b"] = 7;
  expected["/c"] = 95;
  EXPECT_THAT(name_stream_map, testing::ContainerEq(expected));
}

TEST(ReadHeaderInfoStreamTest, ReadFromPdb) {
  const base::FilePath pdb_path = testing::GetSrcRelativePath(
      testing::kTestPdbFilePath);
  PdbFile pdb_file;
  PdbReader pdb_reader;
  EXPECT_TRUE(pdb_reader.Read(pdb_path, &pdb_file));

  PdbInfoHeader70 pdb_header = {};
  NameStreamMap name_stream_map;
  EXPECT_TRUE(
      ReadHeaderInfoStream(pdb_file.GetStream(kPdbHeaderInfoStream).get(),
                           &pdb_header, &name_stream_map));
}

TEST(WriteHeaderInfoStreamTest, WriteToPdbFile) {
  const base::FilePath pdb_path = testing::GetSrcRelativePath(
      testing::kTestPdbFilePath);

  PdbFile pdb_file;
  PdbReader pdb_reader;
  ASSERT_TRUE(pdb_reader.Read(pdb_path, &pdb_file));

  PdbInfoHeader70 pdb_header = {};
  NameStreamMap name_stream_map;
  ASSERT_TRUE(ReadHeaderInfoStream(pdb_file, &pdb_header, &name_stream_map));

  pdb_header.pdb_age++;
  name_stream_map["NewStream!"] = 999;

  EXPECT_TRUE(WriteHeaderInfoStream(pdb_header, name_stream_map, &pdb_file));

  PdbInfoHeader70 pdb_header2 = {};
  NameStreamMap name_stream_map2;
  ASSERT_TRUE(ReadHeaderInfoStream(pdb_file, &pdb_header2, &name_stream_map2));

  EXPECT_TRUE(AreEqual(pdb_header, pdb_header2));
  EXPECT_EQ(name_stream_map, name_stream_map2);
}

TEST(WriteHeaderInfoStreamTest, WriteEmpty) {
  scoped_refptr<PdbStream> reader(new PdbByteStream());
  scoped_refptr<WritablePdbStream> writer(reader->GetWritableStream());

  NameStreamMap name_stream_map;
  EXPECT_TRUE(WriteHeaderInfoStream(kSamplePdbHeader,
                                    name_stream_map,
                                    writer.get()));

  PdbInfoHeader70 read_pdb_header = {};
  NameStreamMap read_name_stream_map;
  EXPECT_TRUE(ReadHeaderInfoStream(reader.get(),
                                   &read_pdb_header,
                                   &read_name_stream_map));

  EXPECT_EQ(0, ::memcmp(&kSamplePdbHeader,
                        &read_pdb_header,
                        sizeof(kSamplePdbHeader)));
  EXPECT_THAT(name_stream_map, testing::ContainerEq(read_name_stream_map));
}

TEST(WriteHeaderInfoStreamTest, WriteNonEmpty) {
  scoped_refptr<PdbStream> reader(new PdbByteStream());
  scoped_refptr<WritablePdbStream> writer(reader->GetWritableStream());

  NameStreamMap name_stream_map;
  name_stream_map["/StreamFoo"] = 9;
  name_stream_map["/StreamBar"] = 42;
  name_stream_map["/Stream/With/A/Path"] = 19;
  EXPECT_TRUE(WriteHeaderInfoStream(kSamplePdbHeader,
                                    name_stream_map,
                                    writer.get()));

  PdbInfoHeader70 read_pdb_header = {};
  NameStreamMap read_name_stream_map;
  EXPECT_TRUE(ReadHeaderInfoStream(reader.get(),
                                   &read_pdb_header,
                                   &read_name_stream_map));

  EXPECT_EQ(0, ::memcmp(&kSamplePdbHeader,
                        &read_pdb_header,
                        sizeof(kSamplePdbHeader)));
  EXPECT_THAT(name_stream_map, testing::ContainerEq(read_name_stream_map));
}

TEST_F(PdbUtilTest, NamedStreamsWorkWithPdbStr) {
  // We start by creating a PDB file (a copy of a checked in sample one) and
  // adding a new stream to it using our named-stream implementation.
  {
    base::FilePath orig_pdb_path = testing::GetSrcRelativePath(
        testing::kTestPdbFilePath);

    // Read the sample PDB.
    PdbReader pdb_reader;
    PdbFile pdb_file;
    ASSERT_TRUE(pdb_reader.Read(orig_pdb_path, &pdb_file));

    // Add a new stream to it.
    scoped_refptr<PdbStream> foo_reader(new PdbByteStream());
    scoped_refptr<WritablePdbStream> foo_writer(
        foo_reader->GetWritableStream());
    size_t foo_index = pdb_file.AppendStream(foo_reader.get());
    foo_writer->WriteString("foo");

    // Get the PDB header stream.
    scoped_refptr<PdbStream> header_stream(pdb_file.GetStream(
        kPdbHeaderInfoStream));
    ASSERT_TRUE(header_stream.get() != NULL);

    // Read the existing name-stream map.
    PdbInfoHeader70 pdb_header = {};
    NameStreamMap name_stream_map;
    ASSERT_TRUE(ReadHeaderInfoStream(header_stream.get(), &pdb_header,
                                     &name_stream_map));

    // Add an entry for the new stream.
    name_stream_map["foo"] = foo_index;

    // Write the new header stream to it.
    scoped_refptr<PdbStream> new_header_reader(new PdbByteStream());
    scoped_refptr<WritablePdbStream> new_header_writer(
        new_header_reader->GetWritableStream());
    ASSERT_TRUE(pdb::WriteHeaderInfoStream(pdb_header, name_stream_map,
                                           new_header_writer.get()));
    pdb_file.ReplaceStream(kPdbHeaderInfoStream, new_header_reader.get());

    // Write the PDB.
    PdbWriter pdb_writer;
    ASSERT_TRUE(pdb_writer.Write(temp_pdb_file_path_, pdb_file));
  }

  // We've now created a new PDB file. We want to make sure that pdbstr.exe
  // plays nicely with our named streams by doing a few things:
  // (1) If we try to read a non-existing stream, we should get empty output.
  // (2) We should be able to read an existing stream and get non-empty output.
  // (3) We should be able to add a new stream, and then read it using our
  //     mechanisms.

  // Get the path to pdbstr.exe, which we redistribute in third_party.
  base::FilePath pdbstr_path =
      testing::GetSrcRelativePath(testing::kPdbStrPath);

  // Create the argument specifying the PDB path.
  std::string pdb_arg = base::WideToUTF8(temp_pdb_file_path_.value());
  pdb_arg.insert(0, "-p:");

  // First test: try to read a non-existing stream. Should produce no output.
  {
    base::CommandLine cmd(pdbstr_path);
    cmd.AppendArg(pdb_arg);
    cmd.AppendArg("-r");
    cmd.AppendArg("-s:nonexistent-stream-name");
    base::LaunchOptions options;
    options.inherit_handles = true;
    base::Process process = base::LaunchProcess(cmd, options);

    int exit_code = 0;
    ASSERT_TRUE(process.WaitForExit(&exit_code));
    ASSERT_EQ(-1, exit_code);
  }

  // Second test: read an existing stream (the one we just added). Should
  // exit without error and return the expected contents (with a trailing
  // newline).
  {
    base::CommandLine cmd(pdbstr_path);
    cmd.AppendArg(pdb_arg);
    cmd.AppendArg("-r");
    cmd.AppendArg("-s:foo");
    std::string output;
    ASSERT_TRUE(base::GetAppOutput(cmd, &output));
    ASSERT_EQ(std::string("foo\r\n"), output);
  }

  // Third test: Add another new stream. This should return without error, and
  // we should then be able to read the stream using our mechanisms.
  {
    base::FilePath bar_txt = temp_dir_.path().Append(L"bar.txt");
    base::ScopedFILE bar_file(base::OpenFile(
        bar_txt, "wb"));
    fprintf(bar_file.get(), "bar");
    bar_file.reset();

    std::string bar_arg = base::WideToUTF8(bar_txt.value());
    bar_arg.insert(0, "-i:");

    base::CommandLine cmd(pdbstr_path);
    cmd.AppendArg(pdb_arg);
    cmd.AppendArg("-w");
    cmd.AppendArg("-s:bar");
    cmd.AppendArg(bar_arg);
    std::string output;
    ASSERT_TRUE(base::GetAppOutput(cmd, &output));
    ASSERT_TRUE(output.empty());

    PdbFile pdb_file;
    PdbReader pdb_reader;
    ASSERT_TRUE(pdb_reader.Read(temp_pdb_file_path_, &pdb_file));

    // Get the PDB header stream.
    scoped_refptr<PdbStream> header_stream(pdb_file.GetStream(
        kPdbHeaderInfoStream));
    ASSERT_TRUE(header_stream.get() != NULL);

    // Read the existing name-stream map.
    PdbInfoHeader70 pdb_header = {};
    NameStreamMap name_stream_map;
    ASSERT_TRUE(ReadHeaderInfoStream(header_stream.get(), &pdb_header,
                                     &name_stream_map));

    // There should be a 'bar' stream.
    ASSERT_TRUE(name_stream_map.count("bar"));

    // Get the bar stream.
    scoped_refptr<PdbStream> bar_stream(pdb_file.GetStream(
        name_stream_map["bar"]));
    ASSERT_TRUE(bar_stream.get() != NULL);

    // Read all of the data and ensure it is as expected.
    std::string bar_data;
    bar_data.resize(bar_stream->length());
    ASSERT_TRUE(bar_stream->ReadBytesAt(0, bar_data.size(), &bar_data.at(0)));
    ASSERT_EQ("bar", bar_data);
  }
}

TEST_F(PdbUtilTest, LoadNamedStreamFromPdbFile) {
  PdbReader reader;
  PdbFile pdb_file;
  EXPECT_TRUE(reader.Read(
      testing::GetOutputRelativePath(testing::kTestDllPdbName),
      &pdb_file));

  scoped_refptr<PdbStream> stream;
  EXPECT_TRUE(LoadNamedStreamFromPdbFile(
      "StreamThatDoesNotExist", &pdb_file, &stream));
  EXPECT_TRUE(stream.get() == NULL);

  // The MSVC toolchain produces a handful of named streams whose existence we
  // can rely on.
  EXPECT_TRUE(LoadNamedStreamFromPdbFile("/LinkInfo", &pdb_file, &stream));
  ASSERT_TRUE(stream.get() != NULL);
}

}  // namespace pdb
