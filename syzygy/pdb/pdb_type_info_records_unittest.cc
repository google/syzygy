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

#include "syzygy/pdb/gen/pdb_type_info_records.h"

#include "base/files/file_util.h"
#include "base/strings/utf_string_conversions.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pdb/pdb_byte_stream.h"
#include "syzygy/pdb/unittest_util.h"

namespace pdb {

namespace {

class PdbTypeInfoRecordsTest : public testing::Test {
 protected:
  void SetUp() override {
    stream_ = new PdbByteStream;
    write_stream_ = stream_->GetWritablePdbStream();
  }

  void WriteUnsignedNumeric(uint64_t value) {
    void* data_pointer = &value;

    if (value < Microsoft_Cci_Pdb::LF_NUMERIC) {
      ASSERT_TRUE(write_stream_->Write(2, data_pointer));
    } else if (value <= UINT16_MAX) {
      WriteData<uint16_t>(Microsoft_Cci_Pdb::LF_USHORT);
      ASSERT_TRUE(write_stream_->Write(2, data_pointer));
    } else if (value <= UINT32_MAX) {
      WriteData<uint16_t>(Microsoft_Cci_Pdb::LF_ULONG);
      ASSERT_TRUE(write_stream_->Write(4, data_pointer));
    } else if (value <= UINT64_MAX) {
      WriteData<uint16_t>(Microsoft_Cci_Pdb::LF_UQUADWORD);
      ASSERT_TRUE(write_stream_->Write(8, data_pointer));
    } else {
      FAIL();
    }
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

TEST_F(PdbTypeInfoRecordsTest, ReadLeafClass) {
  const uint16_t kCount = 21;
  const LeafPropertyField kProperty = {0x0200};
  EXPECT_TRUE(kProperty.decorated_name_present);
  const uint32_t kField = 0x4253;
  const uint32_t kDerived = 0x65A2;
  const uint32_t kVshape = 0x1234AB;
  const uint64_t kSize = 0xA0;
  const base::string16 kName = L"TestClassName";
  const base::string16 kDecoratedName = L"TestClassName@@decoration";

  LeafClass type_record;

  // Fail reading from an empty stream.
  EXPECT_FALSE(type_record.Initialize(stream_.get()));

  // Fill the stream.
  WriteData(kCount);
  WriteData(kProperty);
  WriteData(kField);
  WriteData(kDerived);
  WriteData(kVshape);
  WriteUnsignedNumeric(kSize);
  WriteWideString(kName);
  WriteWideString(kDecoratedName);

  ASSERT_TRUE(type_record.Initialize(stream_.get()));

  EXPECT_EQ(kCount, type_record.body().count);
  EXPECT_EQ(kProperty.raw, type_record.property().raw);
  EXPECT_EQ(kField, type_record.body().field);
  EXPECT_EQ(kDerived, type_record.body().derived);
  EXPECT_EQ(kVshape, type_record.body().vshape);
  EXPECT_EQ(kSize, type_record.size());
  EXPECT_TRUE(type_record.has_decorated_name());
  EXPECT_EQ(kName, type_record.name());
  EXPECT_EQ(kDecoratedName, type_record.decorated_name());
}

TEST_F(PdbTypeInfoRecordsTest, ReadLeafMember) {
  const uint32_t kType = 0x1993;
  const LeafMemberAttributeField kAttr = {0x12A5};
  const uint64_t kOffset = 0xA205B064;
  const base::string16 kName = L"memberName@@test";

  LeafMember type_record;

  // Fail reading from an empty stream.
  EXPECT_FALSE(type_record.Initialize(stream_.get()));

  // Fill the stream.
  WriteData(kAttr);
  WriteData(kType);
  WriteUnsignedNumeric(kOffset);
  WriteWideString(kName);

  ASSERT_TRUE(type_record.Initialize(stream_.get()));

  EXPECT_EQ(kType, type_record.body().index);
  EXPECT_EQ(kAttr.raw, type_record.attr().raw);
  EXPECT_EQ(kOffset, type_record.offset());
  EXPECT_EQ(kName, type_record.name());
}

TEST_F(PdbTypeInfoRecordsTest, ReadLeafModifier) {
  const uint32_t kType = 0x2008;
  const LeafModifierAttribute kAttr = {0x0001};

  LeafModifier type_record;

  // Fail reading from an empty stream.
  EXPECT_FALSE(type_record.Initialize(stream_.get()));

  // Fill the stream.
  WriteData(kType);
  WriteData(kAttr);

  ASSERT_TRUE(type_record.Initialize(stream_.get()));

  EXPECT_EQ(kType, type_record.body().type);
  EXPECT_EQ(kAttr.raw, type_record.attr().raw);
}

TEST_F(PdbTypeInfoRecordsTest, ReadLeafPointer) {
  const uint32_t kType = 0x2008;
  const LeafPointerAttribute kAttr = {0x12A5};

  LeafPointer type_record;

  // Fail reading from an empty stream.
  EXPECT_FALSE(type_record.Initialize(stream_.get()));

  // Fill the stream.
  WriteData(kType);
  WriteData(kAttr);

  ASSERT_TRUE(type_record.Initialize(stream_.get()));

  EXPECT_EQ(kType, type_record.body().utype);
  EXPECT_EQ(kAttr.raw, type_record.attr().raw);
}

}  // namespace pdb
