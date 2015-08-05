// Copyright 2015 Google Inc. All Rights Reserved.
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

#include "syzygy/pdb/pdb_stream_record.h"

#include "base/strings/utf_string_conversions.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pdb/pdb_byte_stream.h"
#include "syzygy/pe/cvinfo_ext.h"

namespace pdb {

namespace {

class PdbStreamRecordTest : public testing::Test {
 protected:
  void SetUp() override {
    stream_ = new PdbByteStream;
    write_stream_ = stream_->GetWritablePdbStream();
  }

  void WriteWideString(const base::string16& wide_string) {
    std::string narrow_string;
    ASSERT_TRUE(base::WideToUTF8(wide_string.c_str(), wide_string.length(),
                                 &narrow_string));
    ASSERT_TRUE(write_stream_->WriteString(narrow_string));
  }

  template <typename T>
  void WriteData(const T& value) {
    ASSERT_TRUE(write_stream_->Write(value));
  }

  scoped_refptr<PdbByteStream> stream_;
  scoped_refptr<WritablePdbStream> write_stream_;
};

}  // namespace

TEST_F(PdbStreamRecordTest, ReadWideString) {
  const base::string16 wide_string = L"base::string16 wide_string";
  base::string16 control_string;

  // Fail when attempting to read empty stream.
  EXPECT_FALSE(ReadWideString(stream_.get(), &control_string));

  WriteWideString(wide_string);
  EXPECT_TRUE(ReadWideString(stream_.get(), &control_string));
  EXPECT_EQ(wide_string, control_string);
}

TEST_F(PdbStreamRecordTest, ReadLeafUnsignedNumericDirect) {
  const uint16_t kVal16 = 42;
  uint64_t numeric;

  // Fail when attempting to read empty stream.
  EXPECT_FALSE(ReadUnsignedNumeric(stream_.get(), &numeric));

  // For values smaller than 0x8000 the numeric leaf reads just their value.
  WriteData(kVal16);
  ASSERT_TRUE(ReadUnsignedNumeric(stream_.get(), &numeric));
  EXPECT_EQ(kVal16, numeric);
}

TEST_F(PdbStreamRecordTest, ReadLeafUnsignedNumericUshort) {
  const uint16_t kVal16 = 42;
  const uint16_t kLfUshort = Microsoft_Cci_Pdb::LF_USHORT;
  uint64_t numeric;

  // Test reading 16-bit values inside LF_USHORT.
  WriteData(kLfUshort);
  WriteData(kVal16);
  ASSERT_TRUE(ReadUnsignedNumeric(stream_.get(), &numeric));
  EXPECT_EQ(kVal16, numeric);
}

TEST_F(PdbStreamRecordTest, ReadLeafUnsignedNumericUlong) {
  const uint32_t kVal32 = 1333666999;
  const uint16_t kLfUlong = Microsoft_Cci_Pdb::LF_ULONG;
  uint64_t numeric;

  // Test reading 32-bit values.
  WriteData(kLfUlong);
  WriteData(kVal32);
  ASSERT_TRUE(ReadUnsignedNumeric(stream_.get(), &numeric));
  EXPECT_EQ(kVal32, numeric);
}

TEST_F(PdbStreamRecordTest, ReadLeafUnsignedNumericUquad) {
  const uint64_t kVal64 = 314159265358979;
  const uint16 kLfUquad = Microsoft_Cci_Pdb::LF_UQUADWORD;
  uint64_t numeric;

  // Test reading 64-bit values.
  WriteData(kLfUquad);
  WriteData(kVal64);
  ASSERT_TRUE(ReadUnsignedNumeric(stream_.get(), &numeric));
  EXPECT_EQ(kVal64, numeric);
}

TEST_F(PdbStreamRecordTest, ReadBasicType) {
  const uint32_t kValue = 0x12345678;
  uint32_t control_value = 0;

  // Fail when attempting to read empty stream.
  EXPECT_FALSE(ReadBasicType(stream_.get(), &control_value));

  WriteData(kValue);
  EXPECT_TRUE(ReadBasicType(stream_.get(), &control_value));
  EXPECT_EQ(kValue, control_value);
}

}  // namespace pdb
