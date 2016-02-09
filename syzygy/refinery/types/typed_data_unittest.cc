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

#include "syzygy/refinery/types/typed_data.h"

#include <stddef.h>
#include <stdint.h>

#include "base/memory/ref_counted.h"
#include "gtest/gtest.h"
#include "syzygy/refinery/testing/self_bit_source.h"
#include "syzygy/refinery/types/type.h"
#include "syzygy/refinery/types/type_repository.h"

namespace refinery {

namespace {

struct TestUDT {
  uint16_t one;
  struct InnerUDT {
    uint8_t inner_one;
    uint32_t inner_two;
  } two;
  const TestUDT* three;
  int32_t four : 10;
  int32_t five : 10;
  int32_t six[10];
};

const TestUDT test_instance =
    {1, {2, 3}, &test_instance, 4, -5, {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}};

class TypedDataTest : public testing::Test {
 protected:
  void SetUp() override {
    CreateTypes();

    ASSERT_TRUE(udt_);
  }

  TypedData GetTestInstance() {
    return TypedData(test_bit_source(), udt_, ToAddr(&test_instance));
  }

  Address ToAddr(const void* ptr) { return reinterpret_cast<Address>(ptr); }

  void AssertFieldMatchesDataType(const TestUDT* ignore,
                                  const TypedData& data) {
    ASSERT_TRUE(data.IsPrimitiveType());
    ASSERT_TRUE(data.IsPointerType());
    ASSERT_FALSE(data.IsUserDefinedType());
  }
  void AssertFieldMatchesDataType(const TestUDT::InnerUDT& ignore,
                                  const TypedData& data) {
    ASSERT_FALSE(data.IsPrimitiveType());
    ASSERT_FALSE(data.IsPointerType());
    ASSERT_TRUE(data.IsUserDefinedType());
  }
  void AssertFieldMatchesDataType(uint8_t ignore, const TypedData& data) {
    ASSERT_TRUE(data.IsPrimitiveType());
    ASSERT_FALSE(data.IsPointerType());
    ASSERT_FALSE(data.IsUserDefinedType());
  }
  void AssertFieldMatchesDataType(uint16_t ignore, const TypedData& data) {
    ASSERT_TRUE(data.IsPrimitiveType());
    ASSERT_FALSE(data.IsPointerType());
    ASSERT_FALSE(data.IsUserDefinedType());
  }
  void AssertFieldMatchesDataType(uint32_t ignore, const TypedData& data) {
    ASSERT_TRUE(data.IsPrimitiveType());
    ASSERT_FALSE(data.IsPointerType());
    ASSERT_FALSE(data.IsUserDefinedType());
  }

  template <typename FieldType>
  void AssertFieldMatchesData(const FieldType& field, const TypedData& data) {
    AssertFieldMatchesDataType(field, data);
    ASSERT_EQ(ToAddr(&field), data.addr());
    ASSERT_EQ(sizeof(field), data.type()->size());
  }

  UserDefinedTypePtr udt() const { return udt_; }
  TypePtr uint32_type() const { return uint32_type_; }

 private:
  void CreateTypes() {
    repo_ = new TypeRepository();

    TypePtr uint8_type = new BasicType(L"uint8_t", sizeof(uint8_t));
    TypePtr uint16_type = new BasicType(L"uint16_t", sizeof(uint16_t));
    uint32_type_ = new BasicType(L"uint32_t", sizeof(uint32_t));
    TypePtr int32_type = new BasicType(L"int32_t", sizeof(int32_t));
    repo_->AddType(uint8_type);
    repo_->AddType(uint16_type);
    repo_->AddType(uint32_type_);
    repo_->AddType(int32_type);

    UserDefinedType::Fields fields;
    UserDefinedType::Functions functions;

    // Inner.
    UserDefinedTypePtr inner(new UserDefinedType(
        L"Inner", sizeof(TestUDT::InnerUDT), UserDefinedType::UDT_STRUCT));
    fields.push_back(new UserDefinedType::MemberField(
        L"inner_one", offsetof(TestUDT::InnerUDT, inner_one), 0, 0, 0,
        uint8_type->type_id(), repo_.get()));
    fields.push_back(new UserDefinedType::MemberField(
        L"inner_two", offsetof(TestUDT::InnerUDT, inner_two), 0, 0, 0,
        uint32_type_->type_id(), repo_.get()));
    inner->Finalize(&fields, &functions);
    repo_->AddType(inner);

    DCHECK(fields.empty());
    DCHECK(functions.empty());

    // Outer.
    UserDefinedTypePtr outer(new UserDefinedType(L"TestUDT", sizeof(TestUDT),
                                                 UserDefinedType::UDT_STRUCT));
    PointerTypePtr ptr_type(
        new PointerType(sizeof(TestUDT*), PointerType::PTR_MODE_PTR));
    repo_->AddType(ptr_type);

    fields.push_back(new UserDefinedType::MemberField(
        L"one", offsetof(TestUDT, one), 0, 0, 0, uint16_type->type_id(),
        repo_.get()));
    fields.push_back(
        new UserDefinedType::MemberField(L"two", offsetof(TestUDT, two), 0, 0,
                                         0, inner->type_id(), repo_.get()));
    fields.push_back(new UserDefinedType::MemberField(
        L"three", offsetof(TestUDT, three), 0, 0, 0, ptr_type->type_id(),
        repo_.get()));
    fields.push_back(new UserDefinedType::MemberField(
        L"four", offsetof(TestUDT, three) + sizeof(test_instance.three), 0, 0,
        10, int32_type->type_id(), repo_.get()));
    fields.push_back(new UserDefinedType::MemberField(
        L"five", offsetof(TestUDT, three) + sizeof(test_instance.three), 0, 10,
        10, int32_type->type_id(), repo_.get()));

    ArrayTypePtr array_type = new ArrayType(sizeof(test_instance.six));
    array_type->Finalize(kNoTypeFlags, uint32_type_->type_id(),
                         arraysize(test_instance.six), int32_type->type_id());
    repo_->AddType(array_type);

    fields.push_back(new UserDefinedType::MemberField(
        L"six", offsetof(TestUDT, six), kNoTypeFlags, 0, 0,
        array_type->type_id(), repo_.get()));
    outer->Finalize(&fields, &functions);
    repo_->AddType(outer);

    ptr_type->Finalize(Type::FLAG_CONST, outer->type_id());

    udt_ = outer;
  }

  BitSource* test_bit_source() { return &test_bit_source_; }

  UserDefinedTypePtr udt_;
  TypePtr uint32_type_;
  testing::SelfBitSource test_bit_source_;
  scoped_refptr<TypeRepository> repo_;
};

}  // namespace

TEST_F(TypedDataTest, IsValid) {
  EXPECT_FALSE(TypedData().IsValid());

  TypedData data = GetTestInstance();
  EXPECT_TRUE(data.IsValid());

  TypedData copy = data;
  EXPECT_TRUE(copy.IsValid());
}

TEST_F(TypedDataTest, GetRange) {
  TypedData data = GetTestInstance();

  AddressRange range = data.GetRange();
  EXPECT_EQ(data.addr(), range.start());
  EXPECT_EQ(data.type()->size(), range.size());
}

TEST_F(TypedDataTest, GetNamedField) {
  TypedData data(GetTestInstance());

  TypedData one;
  ASSERT_TRUE(data.GetNamedField(L"one", &one));
  AssertFieldMatchesData(test_instance.one, one);

  TypedData two;
  ASSERT_TRUE(data.GetNamedField(L"two", &two));
  AssertFieldMatchesData(test_instance.two, two);

  TypedData inner_one;
  ASSERT_TRUE(two.GetNamedField(L"inner_one", &inner_one));
  AssertFieldMatchesData(test_instance.two.inner_one, inner_one);

  TypedData inner_two;
  ASSERT_TRUE(two.GetNamedField(L"inner_two", &inner_two));
  AssertFieldMatchesData(test_instance.two.inner_two, inner_two);

  TypedData three;
  ASSERT_TRUE(data.GetNamedField(L"three", &three));
  AssertFieldMatchesData(test_instance.three, three);

  TypedData four;
  ASSERT_TRUE(data.GetNamedField(L"four", &four));
  ASSERT_EQ(0, four.bit_pos());
  ASSERT_EQ(10, four.bit_len());

  TypedData five;
  ASSERT_TRUE(data.GetNamedField(L"five", &five));
  ASSERT_EQ(10, five.bit_pos());
  ASSERT_EQ(10, five.bit_len());

  TypedData six;
  ASSERT_TRUE(data.GetNamedField(L"six", &six));
  ASSERT_TRUE(six.IsArrayType());
}

TEST_F(TypedDataTest, GetField) {
  TypedData data(GetTestInstance());
  const UserDefinedType::Fields& data_fields = udt()->fields();

  TypedData one;
  ASSERT_TRUE(data.GetField(0, &one));
  AssertFieldMatchesData(test_instance.one, one);
  ASSERT_EQ(data_fields[0]->type_id(), one.type()->type_id());

  TypedData two;
  ASSERT_TRUE(data.GetField(1, &two));
  AssertFieldMatchesData(test_instance.two, two);
  ASSERT_EQ(data_fields[1]->type_id(), two.type()->type_id());

  UserDefinedTypePtr inner_udt;
  ASSERT_TRUE(two.type()->CastTo(&inner_udt));
  const UserDefinedType::Fields& inner_fields = inner_udt->fields();

  TypedData inner_one;
  ASSERT_TRUE(two.GetField(0, &inner_one));
  AssertFieldMatchesData(test_instance.two.inner_one, inner_one);
  ASSERT_EQ(inner_fields[0]->type_id(), inner_one.type()->type_id());

  TypedData inner_two;
  ASSERT_TRUE(two.GetField(1, &inner_two));
  AssertFieldMatchesData(test_instance.two.inner_two, inner_two);
  ASSERT_EQ(inner_fields[1]->type_id(), inner_two.type()->type_id());

  TypedData three;
  ASSERT_TRUE(data.GetField(2, &three));
  AssertFieldMatchesData(test_instance.three, three);
  ASSERT_EQ(data_fields[2]->type_id(), three.type()->type_id());
}

TEST_F(TypedDataTest, GetSignedValue) {
  TypedData data(GetTestInstance());

  TypedData four;
  ASSERT_TRUE(data.GetNamedField(L"four", &four));
  int64_t value = 0;
  ASSERT_TRUE(four.GetSignedValue(&value));
  EXPECT_EQ(4, value);

  TypedData five;
  ASSERT_TRUE(data.GetNamedField(L"five", &five));
  ASSERT_TRUE(five.GetSignedValue(&value));
  EXPECT_EQ(-5, value);
}

TEST_F(TypedDataTest, GetUnsignedValue) {
  TypedData data(GetTestInstance());

  TypedData four;
  ASSERT_TRUE(data.GetNamedField(L"four", &four));
  uint64_t value = 0;
  ASSERT_TRUE(four.GetUnsignedValue(&value));
  EXPECT_EQ(4, value);

  TypedData five;
  ASSERT_TRUE(data.GetNamedField(L"five", &five));
  ASSERT_TRUE(five.GetUnsignedValue(&value));
  EXPECT_EQ(0x3FB, value);
}

TEST_F(TypedDataTest, GetPointerValue) {
  TypedData data(GetTestInstance());

  TypedData three;
  ASSERT_TRUE(data.GetNamedField(L"three", &three));
  Address addr = 0;
  ASSERT_TRUE(three.GetPointerValue(&addr));

  EXPECT_EQ(reinterpret_cast<uintptr_t>(test_instance.three), addr);
}

TEST_F(TypedDataTest, Dereference) {
  TypedData data(GetTestInstance());

  TypedData three;
  ASSERT_TRUE(data.GetNamedField(L"three", &three));

  TypedData derefenced;
  ASSERT_TRUE(three.Dereference(&derefenced));

  // Make sure the dereferenced object is identical.
  ASSERT_TRUE(derefenced.bit_source() == data.bit_source());
  ASSERT_TRUE(derefenced.type() == data.type());
  ASSERT_TRUE(derefenced.addr() == data.addr());
}

TEST_F(TypedDataTest, GetArrayElement) {
  TypedData data(GetTestInstance());

  TypedData array;
  ASSERT_TRUE(data.GetNamedField(L"six", &array));

  int64_t value = 0;
  TypedData element;
  for (size_t i = 0; i < arraysize(test_instance.six); ++i) {
    ASSERT_TRUE(array.GetArrayElement(i, &element));
    ASSERT_TRUE(element.GetSignedValue(&value));
    ASSERT_EQ(test_instance.six[i], value);
  }

  ASSERT_FALSE(array.GetArrayElement(arraysize(test_instance.six), &element));
}

TEST_F(TypedDataTest, OffsetAndCast) {
  TypedData data(GetTestInstance());

  TypedData cast;
  // Identity cast.
  ASSERT_TRUE(data.OffsetAndCast(0, data.type(), &cast));
  EXPECT_EQ(data.bit_source(), cast.bit_source());
  EXPECT_EQ(data.addr(), cast.addr());
  EXPECT_EQ(data.type(), cast.type());

  // Append-cast.
  ASSERT_TRUE(data.OffsetAndCast(1, uint32_type(), &cast));
  EXPECT_EQ(data.bit_source(), cast.bit_source());
  EXPECT_EQ(ToAddr(&test_instance + 1), cast.addr());
  EXPECT_EQ(uint32_type(), cast.type());

  // Try a negative offset.
  ASSERT_TRUE(data.OffsetAndCast(-2, uint32_type(), &cast));
  EXPECT_EQ(ToAddr(&test_instance - 2), cast.addr());
}

TEST_F(TypedDataTest, OffsetBytesAndCast) {
  TypedData data(GetTestInstance());

  TypedData cast;
  // Identity cast.
  ASSERT_TRUE(data.OffsetBytesAndCast(0, data.type(), &cast));
  EXPECT_EQ(data.bit_source(), cast.bit_source());
  EXPECT_EQ(data.addr(), cast.addr());
  EXPECT_EQ(data.type(), cast.type());

  // Forwards.
  const ptrdiff_t kDistance = 24;
  ASSERT_TRUE(data.OffsetBytesAndCast(kDistance, uint32_type(), &cast));
  EXPECT_EQ(data.bit_source(), cast.bit_source());
  EXPECT_EQ(ToAddr(&test_instance) + kDistance, cast.addr());
  EXPECT_EQ(uint32_type(), cast.type());

  // Try a negative offset.
  ASSERT_TRUE(data.OffsetBytesAndCast(-kDistance, uint32_type(), &cast));
  EXPECT_EQ(ToAddr(&test_instance) - kDistance, cast.addr());
}

}  // namespace refinery
