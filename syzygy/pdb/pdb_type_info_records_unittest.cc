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

#include "syzygy/pdb/gen/pdb_type_info_records.h"  // NOLINT

#include "base/files/file_util.h"
#include "base/strings/utf_string_conversions.h"
#include "gtest/gtest.h"
#include "syzygy/common/binary_stream.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pdb/unittest_util.h"

namespace pdb {

namespace {

class PdbTypeInfoRecordsTest : public testing::Test {
 protected:
  PdbTypeInfoRecordsTest()
      : writer_(&data_), reader_(&data_), parser_(&reader_) {}

  void WriteUnsignedNumeric(uint64_t value) {
    void* data_pointer = &value;

    if (value < Microsoft_Cci_Pdb::LF_NUMERIC) {
      ASSERT_TRUE(writer_.Write(2, data_pointer));
    } else if (value <= UINT16_MAX) {
      WriteData<uint16_t>(Microsoft_Cci_Pdb::LF_USHORT);
      ASSERT_TRUE(writer_.Write(2, data_pointer));
    } else if (value <= UINT32_MAX) {
      WriteData<uint16_t>(Microsoft_Cci_Pdb::LF_ULONG);
      ASSERT_TRUE(writer_.Write(4, data_pointer));
    } else if (value <= UINT64_MAX) {
      WriteData<uint16_t>(Microsoft_Cci_Pdb::LF_UQUADWORD);
      ASSERT_TRUE(writer_.Write(8, data_pointer));
    } else {
      FAIL();
    }
  }

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

TEST_F(PdbTypeInfoRecordsTest, ReadLeafArglist) {
  const uint32_t kCount = 0x2047;

  LeafArgList type_record;

  // Fail reading from an empty stream.
  EXPECT_FALSE(type_record.Initialize(&parser_));

  // Fill the stream.
  WriteData(kCount);

  ASSERT_TRUE(type_record.Initialize(&parser_));

  EXPECT_EQ(kCount, type_record.body().count);
}

TEST_F(PdbTypeInfoRecordsTest, ReadLeafArray) {
  const uint32_t kElemType = 0x1918;
  const uint32_t kIndexType = 0x1989;
  const uint64_t kSize = 0x101101;
  const wchar_t kName[] = L"TestArrayName";

  LeafArray type_record;

  // Fail reading from an empty stream.
  EXPECT_FALSE(type_record.Initialize(&parser_));

  // Fill the stream.
  WriteData(kElemType);
  WriteData(kIndexType);
  WriteUnsignedNumeric(kSize);
  WriteWideString(kName);

  ASSERT_TRUE(type_record.Initialize(&parser_));

  EXPECT_EQ(kElemType, type_record.body().elemtype);
  EXPECT_EQ(kIndexType, type_record.body().idxtype);
  EXPECT_EQ(kSize, type_record.size());
  EXPECT_EQ(kName, type_record.name());
}

TEST_F(PdbTypeInfoRecordsTest, ReadLeafBClass) {
  const uint32_t kType = 0x1492;
  const LeafMemberAttributeField kAttr = {0xABBA};
  const uint64_t kOffset = 80085;

  LeafBClass type_record;

  // Fail reading from an empty stream.
  EXPECT_FALSE(type_record.Initialize(&parser_));

  // Fill the stream.
  WriteData(kAttr);
  WriteData(kType);
  WriteUnsignedNumeric(kOffset);

  ASSERT_TRUE(type_record.Initialize(&parser_));

  EXPECT_EQ(kType, type_record.body().index);
  EXPECT_EQ(kAttr.raw, type_record.attr().raw);
  EXPECT_EQ(kOffset, type_record.offset());
}

TEST_F(PdbTypeInfoRecordsTest, ReadLeafBitfield) {
  const uint32_t kType = 0x22031993;
  const uint8_t kLength = 13;
  const uint8_t kPosition = 9;

  LeafBitfield type_record;

  // Fail reading from an empty stream.
  EXPECT_FALSE(type_record.Initialize(&parser_));

  // Fill the stream.
  WriteData(kType);
  WriteData(kLength);
  WriteData(kPosition);

  ASSERT_TRUE(type_record.Initialize(&parser_));

  EXPECT_EQ(kType, type_record.body().type);
  EXPECT_EQ(kLength, type_record.body().length);
  EXPECT_EQ(kPosition, type_record.body().position);
}

TEST_F(PdbTypeInfoRecordsTest, ReadLeafClass) {
  const uint16_t kCount = 21;
  const LeafPropertyField kProperty = {0x0200};
  EXPECT_TRUE(kProperty.decorated_name_present);
  const uint32_t kField = 0x4253;
  const uint32_t kDerived = 0x65A2;
  const uint32_t kVshape = 0x1234AB;
  const uint64_t kSize = 0xA0;
  const wchar_t kName[] = L"TestClassName";
  const wchar_t kDecoratedName[] = L"TestClassName@@decoration";

  LeafClass type_record;

  // Fail reading from an empty stream.
  EXPECT_FALSE(type_record.Initialize(&parser_));

  // Fill the stream.
  WriteData(kCount);
  WriteData(kProperty);
  WriteData(kField);
  WriteData(kDerived);
  WriteData(kVshape);
  WriteUnsignedNumeric(kSize);
  WriteWideString(kName);
  WriteWideString(kDecoratedName);

  ASSERT_TRUE(type_record.Initialize(&parser_));

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

TEST_F(PdbTypeInfoRecordsTest, ReadLeafEnum) {
  const uint16_t kCount = 31;
  const LeafPropertyField kProperty = {0x0200};
  EXPECT_TRUE(kProperty.decorated_name_present);
  const uint32_t kUtype = 0x1324;
  const uint32_t kField = 0x2203;
  const wchar_t kName[] = L"TestEnumName";
  const wchar_t kDecoratedName[] = L"TestEnumName@@decoration";

  LeafEnum type_record;

  // Fail reading from an empty stream.
  EXPECT_FALSE(type_record.Initialize(&parser_));

  // Fill the stream.
  WriteData(kCount);
  WriteData(kProperty);
  WriteData(kUtype);
  WriteData(kField);
  WriteWideString(kName);
  WriteWideString(kDecoratedName);

  ASSERT_TRUE(type_record.Initialize(&parser_));

  EXPECT_EQ(kCount, type_record.body().count);
  EXPECT_EQ(kProperty.raw, type_record.property().raw);
  EXPECT_EQ(kField, type_record.body().field);
  EXPECT_TRUE(type_record.has_decorated_name());
  EXPECT_EQ(kName, type_record.name());
  EXPECT_EQ(kDecoratedName, type_record.decorated_name());
}

TEST_F(PdbTypeInfoRecordsTest, ReadLeafEnumerate) {
  const LeafMemberAttributeField kAttr = {0x1989};
  const uint64_t kValue = 0x8BADF00D;
  const wchar_t kName[] = L"enumName@@test";

  LeafEnumerate type_record;

  // Fail reading from an empty stream.
  EXPECT_FALSE(type_record.Initialize(&parser_));

  // Fill the stream.
  WriteData(kAttr);
  WriteUnsignedNumeric(kValue);
  WriteWideString(kName);

  ASSERT_TRUE(type_record.Initialize(&parser_));

  EXPECT_EQ(kAttr.raw, type_record.attr().raw);
  EXPECT_EQ(NumericConstant::CONSTANT_UNSIGNED, type_record.value().kind());
  EXPECT_EQ(kValue, type_record.value().unsigned_value());
  EXPECT_EQ(kName, type_record.name());
}

TEST_F(PdbTypeInfoRecordsTest, ReadLeafFriendCls) {
  const uint16_t kPad = 0x0000;
  const uint32_t kType = 0x05141316;

  LeafFriendCls type_record;

  // Fail reading from an empty stream.
  EXPECT_FALSE(type_record.Initialize(&parser_));

  // Fill the stream.
  WriteData(kPad);
  WriteData(kType);

  ASSERT_TRUE(type_record.Initialize(&parser_));

  EXPECT_EQ(kPad, type_record.body().pad0);
  EXPECT_EQ(kType, type_record.body().index);
}

TEST_F(PdbTypeInfoRecordsTest, ReadLeafFriendFcn) {
  const uint16_t kPad = 0x0000;
  const uint32_t kType = 0x1918;
  const wchar_t kName[] = L"friendFunctionName@@test";

  LeafFriendFcn type_record;

  // Fail reading from an empty stream.
  EXPECT_FALSE(type_record.Initialize(&parser_));

  // Fill the stream.
  WriteData(kPad);
  WriteData(kType);
  WriteWideString(kName);

  ASSERT_TRUE(type_record.Initialize(&parser_));

  EXPECT_EQ(kPad, type_record.body().pad0);
  EXPECT_EQ(kType, type_record.body().index);
  EXPECT_EQ(kName, type_record.name());
}

TEST_F(PdbTypeInfoRecordsTest, ReadLeafIndex) {
  const uint16_t kPad = 0x0000;
  const uint32_t kType = 0x07041348;

  LeafIndex type_record;

  // Fail reading from an empty stream.
  EXPECT_FALSE(type_record.Initialize(&parser_));

  // Fill the stream.
  WriteData(kPad);
  WriteData(kType);

  ASSERT_TRUE(type_record.Initialize(&parser_));

  EXPECT_EQ(kPad, type_record.body().pad0);
  EXPECT_EQ(kType, type_record.body().index);
}

TEST_F(PdbTypeInfoRecordsTest, ReadLeafMember) {
  const uint32_t kType = 0x1993;
  const LeafMemberAttributeField kAttr = {0x12A5};
  const uint64_t kOffset = 0xA205B064;
  const wchar_t kName[] = L"memberName@@test";

  LeafMember type_record;

  // Fail reading from an empty stream.
  EXPECT_FALSE(type_record.Initialize(&parser_));

  // Fill the stream.
  WriteData(kAttr);
  WriteData(kType);
  WriteUnsignedNumeric(kOffset);
  WriteWideString(kName);

  ASSERT_TRUE(type_record.Initialize(&parser_));

  EXPECT_EQ(kType, type_record.body().index);
  EXPECT_EQ(kAttr.raw, type_record.attr().raw);
  EXPECT_EQ(kOffset, type_record.offset());
  EXPECT_EQ(kName, type_record.name());
}

TEST_F(PdbTypeInfoRecordsTest, ReadLeafMethod) {
  const uint16_t kCount = 1348;
  const uint32_t kMlist = 0xBADDCAFE;
  const wchar_t kName[] = L"methodName@@test";

  LeafMethod type_record;

  // Fail reading from an empty stream.
  EXPECT_FALSE(type_record.Initialize(&parser_));

  // Fill the stream.
  WriteData(kCount);
  WriteData(kMlist);
  WriteWideString(kName);

  ASSERT_TRUE(type_record.Initialize(&parser_));

  EXPECT_EQ(kCount, type_record.body().count);
  EXPECT_EQ(kMlist, type_record.body().mList);
  EXPECT_EQ(kName, type_record.name());
}

TEST_F(PdbTypeInfoRecordsTest, ReadLeafMFunction) {
  const uint32_t kReturnType = 0x013243546;
  const uint32_t kClassType = 0xAABB;
  const uint32_t kThisType = 0xFADE;
  const uint8_t kCallConvention = 0x05;
  const uint8_t kPad = 0x00;
  const uint16_t kParamCount = 12;
  const uint32_t kArglistType = 0xA8F115CD;
  const uint32_t kThisAdjust = 0x1011AABB;

  LeafMFunction type_record;

  // Fail reading from an empty stream.
  EXPECT_FALSE(type_record.Initialize(&parser_));

  // Fill the stream.
  WriteData(kReturnType);
  WriteData(kClassType);
  WriteData(kThisType);
  WriteData(kCallConvention);
  WriteData(kPad);
  WriteData(kParamCount);
  WriteData(kArglistType);
  WriteData(kThisAdjust);

  ASSERT_TRUE(type_record.Initialize(&parser_));

  EXPECT_EQ(kReturnType, type_record.body().rvtype);
  EXPECT_EQ(kClassType, type_record.body().classtype);
  EXPECT_EQ(kThisType, type_record.body().thistype);
  EXPECT_EQ(kCallConvention, type_record.body().calltype);
  EXPECT_EQ(kPad, type_record.body().reserved);
  EXPECT_EQ(kParamCount, type_record.body().parmcount);
  EXPECT_EQ(kArglistType, type_record.body().arglist);
  EXPECT_EQ(kThisAdjust, type_record.body().thisadjust);
}

TEST_F(PdbTypeInfoRecordsTest, ReadLeafModifier) {
  const uint32_t kType = 0x2008;
  const LeafModifierAttribute kAttr = {0x0001};

  LeafModifier type_record;

  // Fail reading from an empty stream.
  EXPECT_FALSE(type_record.Initialize(&parser_));

  // Fill the stream.
  WriteData(kType);
  WriteData(kAttr);

  ASSERT_TRUE(type_record.Initialize(&parser_));

  EXPECT_EQ(kType, type_record.body().type);
  EXPECT_EQ(kAttr.raw, type_record.attr().raw);
}

TEST_F(PdbTypeInfoRecordsTest, ReadLeafNestType) {
  const LeafMemberAttributeField kAttr = {0xAC1D};
  const uint32_t kType = 0x1A11;
  const wchar_t kName[] = L"nestTypeName@@test";

  LeafNestType type_record;

  // Fail reading from an empty stream.
  EXPECT_FALSE(type_record.Initialize(&parser_));

  // Fill the stream.
  WriteData(kAttr);
  WriteData(kType);
  WriteWideString(kName);

  ASSERT_TRUE(type_record.Initialize(&parser_));

  EXPECT_EQ(kAttr.raw, type_record.attr().raw);
  EXPECT_EQ(kType, type_record.body().index);
  EXPECT_EQ(kName, type_record.name());
}

TEST_F(PdbTypeInfoRecordsTest, ReadLeafOneMethod) {
  const LeafMemberAttributeField kAttr = {0x1212};
  const uint32_t kType = 0xD15EA5E;
  const uint32_t kVbaseOff = 0x10051936;
  const wchar_t kName[] = L"oneMethodName@@test";

  EXPECT_EQ(kAttr.mprop, Microsoft_Cci_Pdb::CV_MTintro);

  LeafOneMethod type_record;

  // Fail reading from an empty stream.
  EXPECT_FALSE(type_record.Initialize(&parser_));

  // Fill the stream.
  WriteData(kAttr);
  WriteData(kType);
  WriteData(kVbaseOff);
  WriteWideString(kName);

  ASSERT_TRUE(type_record.Initialize(&parser_));

  EXPECT_EQ(kAttr.raw, type_record.attr().raw);
  EXPECT_EQ(kType, type_record.body().index);
  EXPECT_EQ(kName, type_record.name());
  EXPECT_TRUE(type_record.has_vbaseoff());
  EXPECT_EQ(kVbaseOff, type_record.vbaseoff());
}

TEST_F(PdbTypeInfoRecordsTest, ReadLeafPointer) {
  const uint32_t kType = 0x2008;
  const LeafPointerAttribute kAttr = {0x12A5};

  LeafPointer type_record;

  // Fail reading from an empty stream.
  EXPECT_FALSE(type_record.Initialize(&parser_));

  // Fill the stream.
  WriteData(kType);
  WriteData(kAttr);

  ASSERT_TRUE(type_record.Initialize(&parser_));

  EXPECT_EQ(kType, type_record.body().utype);
  EXPECT_EQ(kAttr.raw, type_record.attr().raw);
  EXPECT_FALSE(type_record.has_containing_class());
  EXPECT_FALSE(type_record.has_pmtype());
}

TEST_F(PdbTypeInfoRecordsTest, ReadLeafMemberPointer) {
  const uint32_t kType = 0x1918;
  const LeafPointerAttribute kAttr = {0x1254};
  const uint32_t kContainingClass = 0x01020304;
  const uint16_t kPmtype = Microsoft_Cci_Pdb::CV_PMTYPE_D_Virtual;

  EXPECT_EQ(Microsoft_Cci_Pdb::CV_PTR_MODE_PMEM, kAttr.ptrmode);

  LeafPointer type_record;

  // Fail reading from an empty stream.
  EXPECT_FALSE(type_record.Initialize(&parser_));

  // Fill the stream.
  WriteData(kType);
  WriteData(kAttr);
  WriteData(kContainingClass);
  WriteData(kPmtype);

  ASSERT_TRUE(type_record.Initialize(&parser_));

  EXPECT_EQ(kType, type_record.body().utype);
  EXPECT_EQ(kAttr.raw, type_record.attr().raw);
  EXPECT_TRUE(type_record.has_containing_class());
  EXPECT_TRUE(type_record.has_pmtype());
  EXPECT_EQ(kContainingClass, type_record.containing_class());
  EXPECT_EQ(kPmtype, type_record.pmtype());
}

TEST_F(PdbTypeInfoRecordsTest, ReadLeafProcedure) {
  const uint32_t kReturnType = 0xFF00FF00;
  const uint8_t kCallConvention = 0xFF;
  const uint8_t kPad = 0x00;
  const uint16_t kParamCount = 255;
  const uint32_t kArglistType = 0xA8F115CD;

  LeafProcedure type_record;

  // Fail reading from an empty stream.
  EXPECT_FALSE(type_record.Initialize(&parser_));

  // Fill the stream.
  WriteData(kReturnType);
  WriteData(kCallConvention);
  WriteData(kPad);
  WriteData(kParamCount);
  WriteData(kArglistType);

  ASSERT_TRUE(type_record.Initialize(&parser_));

  EXPECT_EQ(kReturnType, type_record.body().rvtype);
  EXPECT_EQ(kCallConvention, type_record.body().calltype);
  EXPECT_EQ(kPad, type_record.body().reserved);
  EXPECT_EQ(kParamCount, type_record.body().parmcount);
  EXPECT_EQ(kArglistType, type_record.body().arglist);
}

TEST_F(PdbTypeInfoRecordsTest, ReadLeafSTMember) {
  const uint32_t kType = 0xD15EA5E0;
  const LeafMemberAttributeField kAttr = {0x12A5};
  const wchar_t kName[] = L"staticMemberName@@test";

  LeafSTMember type_record;

  // Fail reading from an empty stream.
  EXPECT_FALSE(type_record.Initialize(&parser_));

  // Fill the stream.
  WriteData(kAttr);
  WriteData(kType);
  WriteWideString(kName);

  ASSERT_TRUE(type_record.Initialize(&parser_));

  EXPECT_EQ(kType, type_record.body().index);
  EXPECT_EQ(kAttr.raw, type_record.attr().raw);
  EXPECT_EQ(kName, type_record.name());
}

TEST_F(PdbTypeInfoRecordsTest, ReadLeafUnion) {
  const uint16_t kCount = 21;
  const LeafPropertyField kProperty = {0x0200};
  EXPECT_TRUE(kProperty.decorated_name_present);
  const uint32_t kField = 0x3107;
  const uint64_t kSize = 0xBABE;
  const wchar_t kName[] = L"TestUnionName";
  const wchar_t kDecoratedName[] = L"TestUnionName@@decoration";

  LeafUnion type_record;

  // Fail reading from an empty stream.
  EXPECT_FALSE(type_record.Initialize(&parser_));

  // Fill the stream.
  WriteData(kCount);
  WriteData(kProperty);
  WriteData(kField);
  WriteUnsignedNumeric(kSize);
  WriteWideString(kName);
  WriteWideString(kDecoratedName);

  ASSERT_TRUE(type_record.Initialize(&parser_));

  EXPECT_EQ(kCount, type_record.body().count);
  EXPECT_EQ(kProperty.raw, type_record.property().raw);
  EXPECT_EQ(kField, type_record.body().field);
  EXPECT_EQ(kSize, type_record.size());
  EXPECT_TRUE(type_record.has_decorated_name());
  EXPECT_EQ(kName, type_record.name());
  EXPECT_EQ(kDecoratedName, type_record.decorated_name());
}

TEST_F(PdbTypeInfoRecordsTest, ReadLeafVBClass) {
  const uint32_t kType = 0x0480;
  const LeafMemberAttributeField kAttr = {0x0BAD};
  const uint32_t kVbptr = 79123;
  const uint64_t kVbpoff = 80085;
  const uint64_t kVboff = 0x07011867;

  LeafVBClass type_record;

  // Fail reading from an empty stream.
  EXPECT_FALSE(type_record.Initialize(&parser_));

  // Fill the stream.
  WriteData(kAttr);
  WriteData(kType);
  WriteData(kVbptr);
  WriteUnsignedNumeric(kVbpoff);
  WriteUnsignedNumeric(kVboff);

  ASSERT_TRUE(type_record.Initialize(&parser_));

  EXPECT_EQ(kType, type_record.body().index);
  EXPECT_EQ(kAttr.raw, type_record.attr().raw);
  EXPECT_EQ(kVbptr, type_record.body().vbptr);
  EXPECT_EQ(kVbpoff, type_record.vbpoff());
  EXPECT_EQ(kVboff, type_record.vboff());
}

TEST_F(PdbTypeInfoRecordsTest, ReadLeafVFuncOff) {
  const uint16_t kPad = 0x0000;
  const uint32_t kType = 0x20AC;
  const uint32_t kOffset = 0x0FF531;

  LeafVFuncOff type_record;

  // Fail reading from an empty stream.
  EXPECT_FALSE(type_record.Initialize(&parser_));

  // Fill the stream.
  WriteData(kPad);
  WriteData(kType);
  WriteData(kOffset);

  ASSERT_TRUE(type_record.Initialize(&parser_));

  EXPECT_EQ(kType, type_record.body().type);
  EXPECT_EQ(kOffset, type_record.body().offset);
}

TEST_F(PdbTypeInfoRecordsTest, ReadLeafVFuncTab) {
  const uint16_t kPad = 0x0000;
  const uint32_t kType = 0x2015;

  LeafVFuncTab type_record;

  // Fail reading from an empty stream.
  EXPECT_FALSE(type_record.Initialize(&parser_));

  // Fill the stream.
  WriteData(kPad);
  WriteData(kType);

  ASSERT_TRUE(type_record.Initialize(&parser_));

  EXPECT_EQ(kType, type_record.body().type);
}

TEST_F(PdbTypeInfoRecordsTest, ReadLeafVTShape) {
  const uint32_t kCount = 0x2047;

  LeafVTShape type_record;

  // Fail reading from an empty stream.
  EXPECT_FALSE(type_record.Initialize(&parser_));

  // Fill the stream.
  WriteData(kCount);

  ASSERT_TRUE(type_record.Initialize(&parser_));

  EXPECT_EQ(kCount, type_record.body().count);
}

TEST_F(PdbTypeInfoRecordsTest, ReadMethodListRecord) {
  const LeafMemberAttributeField kAttr = {0x1212};
  const uint16_t kPad = 0x0000;
  const uint32_t kType = 0xF0F0F0F0;
  const uint32_t kVbaseOff = 0xBA5E0000;

  EXPECT_EQ(kAttr.mprop, Microsoft_Cci_Pdb::CV_MTintro);

  MethodListRecord type_record;

  // Fail reading from an empty stream.
  EXPECT_FALSE(type_record.Initialize(&parser_));

  // Fill the stream.
  WriteData(kAttr);
  WriteData(kPad);
  WriteData(kType);
  WriteData(kVbaseOff);

  ASSERT_TRUE(type_record.Initialize(&parser_));

  EXPECT_EQ(kAttr.raw, type_record.attr().raw);
  EXPECT_EQ(kType, type_record.body().index);
  EXPECT_TRUE(type_record.has_vbaseoff());
  EXPECT_EQ(kVbaseOff, type_record.vbaseoff());
}

}  // namespace pdb
