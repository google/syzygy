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

TEST(PdbStreamRecordTest, ReadWideString) {
  const base::string16 wide_string = L"base::string16 wide_string";
  const size_t string_length = wide_string.length();

  const std::string narrow_string = base::WideToUTF8(wide_string);

  ASSERT_EQ(narrow_string.length(), string_length);

  scoped_refptr<PdbByteStream> stream(new PdbByteStream);
  uint8_t* byte_data = new uint8_t[string_length + 1];

  ASSERT_TRUE(byte_data);

  ::memcpy(byte_data, narrow_string.c_str(), string_length);
  byte_data[narrow_string.length()] = '\0';

  ASSERT_TRUE(stream->Init(byte_data, string_length + 1));

  base::string16 control_string;

  ReadWideString(stream.get(), &control_string);
  EXPECT_EQ(wide_string, control_string);

  delete byte_data;
}

TEST(PdbStreamRecordTest, ReadLeafUnsignedNumeric) {
  const uint16_t val16 = 42;
  const uint32_t val32 = 1333666999;
  const uint64_t val64 = 314159265358979;

  const uint16_t lf_ushort = Microsoft_Cci_Pdb::LF_USHORT;
  const uint16_t lf_ulong = Microsoft_Cci_Pdb::LF_ULONG;
  const uint16 lf_uquad = Microsoft_Cci_Pdb::LF_UQUADWORD;

  scoped_refptr<PdbByteStream> stream(new PdbByteStream);

  // Allocate enough space.
  uint8_t* byte_data = new uint8_t[16];

  uint64_t numeric;

  // For values smaller than 0x8000 the numeric leaf reads just their value.
  ::memcpy(byte_data, &val16, 2);
  ASSERT_TRUE(stream->Init(byte_data, 2));
  ASSERT_TRUE(ReadUnsignedNumeric(stream.get(), &numeric));
  EXPECT_EQ(val16, numeric);

  // Reset the stream.
  EXPECT_TRUE(stream->Seek(0));

  // Test reading 16-bit values inside LF_USHORT.
  ::memcpy(byte_data, &lf_ushort, sizeof(lf_ushort));
  ::memcpy(byte_data + sizeof(lf_ushort), &val16, sizeof(val16));
  ASSERT_TRUE(stream->Init(byte_data, sizeof(val16) + sizeof(lf_ushort)));
  ASSERT_TRUE(ReadUnsignedNumeric(stream.get(), &numeric));
  EXPECT_EQ(val16, numeric);

  // Reset the stream.
  EXPECT_TRUE(stream->Seek(0));

  // Test reading 32-bit values.
  ::memcpy(byte_data, &lf_ulong, sizeof(lf_ulong));
  ::memcpy(byte_data + sizeof(lf_ulong), &val32, sizeof(val32));
  ASSERT_TRUE(stream->Init(byte_data, sizeof(val32) + sizeof(lf_ulong)));
  ASSERT_TRUE(ReadUnsignedNumeric(stream.get(), &numeric));
  EXPECT_EQ(val32, numeric);

  // Reset the stream.
  EXPECT_TRUE(stream->Seek(0));

  // Test reading 64-bit values.
  ::memcpy(byte_data, &lf_uquad, sizeof(lf_uquad));
  ::memcpy(byte_data + sizeof(lf_uquad), &val64, sizeof(val64));
  ASSERT_TRUE(stream->Init(byte_data, sizeof(val64) + sizeof(lf_ulong)));
  ASSERT_TRUE(ReadUnsignedNumeric(stream.get(), &numeric));
  EXPECT_EQ(val64, numeric);

  delete byte_data;
}

}  // namespace pdb
