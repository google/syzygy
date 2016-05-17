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
#include "syzygy/common/binary_stream.h"
#include "syzygy/common/buffer_writer.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/cvinfo_ext.h"

namespace pdb {

namespace {

class PdbStreamRecordTest : public testing::Test {
 protected:
  PdbStreamRecordTest() : writer_(&data_), reader_(&data_), parser_(&reader_) {}

  void WriteWideString(const base::string16& wide_string) {
    std::string narrow_string;
    ASSERT_TRUE(base::WideToUTF8(wide_string.c_str(), wide_string.length(),
                                 &narrow_string));
    ASSERT_TRUE(writer_.WriteString(narrow_string));
  }

  template <typename T>
  void WriteData(const T& value) {
    ASSERT_TRUE(writer_.Write(value));
  }

  std::vector<uint8_t> data_;
  common::VectorBufferWriter writer_;
  common::BinaryVectorStreamReader reader_;
  common::BinaryStreamParser parser_;
};

}  // namespace

TEST_F(PdbStreamRecordTest, ReadWideString) {
  const base::string16 wide_string = L"base::string16 wide_string";
  base::string16 control_string;

  // Fail when attempting to read empty stream.
  EXPECT_FALSE(ReadWideString(&parser_, &control_string));

  WriteWideString(wide_string);
  EXPECT_TRUE(ReadWideString(&parser_, &control_string));
  EXPECT_EQ(wide_string, control_string);
}

TEST_F(PdbStreamRecordTest, ReadLeafNumericConstantDirect) {
  const uint16_t kVal16 = 42;
  NumericConstant numeric;

  // Fail when attempting to read empty stream.
  EXPECT_FALSE(ReadNumericConstant(&parser_, &numeric));

  // For values smaller than 0x8000 the numeric leaf reads just their value.
  WriteData(kVal16);
  ASSERT_TRUE(ReadNumericConstant(&parser_, &numeric));
  EXPECT_EQ(NumericConstant::CONSTANT_UNSIGNED, numeric.kind());
  EXPECT_EQ(kVal16, numeric.unsigned_value());
}

TEST_F(PdbStreamRecordTest, ReadLeafNumericConstantChar) {
  const int8_t kVal8 = -42;
  const uint16_t kLfChar = Microsoft_Cci_Pdb::LF_CHAR;
  NumericConstant numeric;

  // Test reading signed 8-bit values.
  WriteData(kLfChar);
  WriteData(kVal8);
  ASSERT_TRUE(ReadNumericConstant(&parser_, &numeric));
  EXPECT_EQ(NumericConstant::CONSTANT_SIGNED, numeric.kind());
  EXPECT_EQ(kVal8, numeric.signed_value());
}

TEST_F(PdbStreamRecordTest, ReadLeafNumericConstantUshort) {
  const uint16_t kVal16 = 42;
  const uint16_t kLfUshort = Microsoft_Cci_Pdb::LF_USHORT;
  NumericConstant numeric;

  // Test reading 16-bit values inside LF_USHORT.
  WriteData(kLfUshort);
  WriteData(kVal16);
  ASSERT_TRUE(ReadNumericConstant(&parser_, &numeric));
  EXPECT_EQ(NumericConstant::CONSTANT_UNSIGNED, numeric.kind());
  EXPECT_EQ(kVal16, numeric.unsigned_value());
}

TEST_F(PdbStreamRecordTest, ReadLeafNumericConstantShort) {
  const int16_t kVal16 = -42;
  const uint16_t kLfShort = Microsoft_Cci_Pdb::LF_SHORT;
  NumericConstant numeric;

  // Test reading signed 16-bit values.
  WriteData(kLfShort);
  WriteData(kVal16);
  ASSERT_TRUE(ReadNumericConstant(&parser_, &numeric));
  EXPECT_EQ(NumericConstant::CONSTANT_SIGNED, numeric.kind());
  EXPECT_EQ(kVal16, numeric.signed_value());
}

TEST_F(PdbStreamRecordTest, ReadLeafNumericConstantUlong) {
  const uint32_t kVal32 = 1333666999;
  const uint16_t kLfUlong = Microsoft_Cci_Pdb::LF_ULONG;
  NumericConstant numeric;

  // Test reading 32-bit values.
  WriteData(kLfUlong);
  WriteData(kVal32);
  ASSERT_TRUE(ReadNumericConstant(&parser_, &numeric));
  EXPECT_EQ(NumericConstant::CONSTANT_UNSIGNED, numeric.kind());
  EXPECT_EQ(kVal32, numeric.unsigned_value());
}

TEST_F(PdbStreamRecordTest, ReadLeafNumericConstantLong) {
  const int32_t kVal32 = -1333666999;
  const uint16_t kLfLong = Microsoft_Cci_Pdb::LF_LONG;
  NumericConstant numeric;

  // Test reading signed 32-bit values.
  WriteData(kLfLong);
  WriteData(kVal32);
  ASSERT_TRUE(ReadNumericConstant(&parser_, &numeric));
  EXPECT_EQ(NumericConstant::CONSTANT_SIGNED, numeric.kind());
  EXPECT_EQ(kVal32, numeric.signed_value());
}

TEST_F(PdbStreamRecordTest, ReadLeafUnsignedNumericUquad) {
  const uint64_t kVal64 = 314159265358979;
  const uint16_t kLfUquad = Microsoft_Cci_Pdb::LF_UQUADWORD;
  NumericConstant numeric;

  // Test reading 64-bit values.
  WriteData(kLfUquad);
  WriteData(kVal64);
  ASSERT_TRUE(ReadNumericConstant(&parser_, &numeric));
  EXPECT_EQ(NumericConstant::CONSTANT_UNSIGNED, numeric.kind());
  EXPECT_EQ(kVal64, numeric.unsigned_value());
}

TEST_F(PdbStreamRecordTest, ReadLeafUnsignedNumericQuad) {
  const int64_t kVal64 = -314159265358979;
  const uint16_t kLfQuad = Microsoft_Cci_Pdb::LF_QUADWORD;
  NumericConstant numeric;

  // Test reading signed 64-bit values.
  WriteData(kLfQuad);
  WriteData(kVal64);
  ASSERT_TRUE(ReadNumericConstant(&parser_, &numeric));
  EXPECT_EQ(NumericConstant::CONSTANT_SIGNED, numeric.kind());
  EXPECT_EQ(kVal64, numeric.signed_value());
}

TEST_F(PdbStreamRecordTest, ReadLeafUnsignedNumeric) {
  const uint16_t kVal16 = 42;
  uint64_t constant;

  // Fail when attempting to read empty stream.
  EXPECT_FALSE(ReadUnsignedNumeric(&parser_, &constant));

  WriteData(kVal16);
  ASSERT_TRUE(ReadUnsignedNumeric(&parser_, &constant));
  EXPECT_EQ(kVal16, constant);
}

TEST_F(PdbStreamRecordTest, ReadBasicType) {
  const uint32_t kValue = 0x12345678;
  uint32_t control_value = 0;

  // Fail when attempting to read empty stream.
  EXPECT_FALSE(ReadBasicType(&parser_, &control_value));

  WriteData(kValue);
  EXPECT_TRUE(ReadBasicType(&parser_, &control_value));
  EXPECT_EQ(kValue, control_value);
}

}  // namespace pdb
