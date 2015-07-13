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

#include "gtest/gtest.h"
#include "syzygy/refinery/core/bit_source.h"
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
};

const TestUDT test_instance = {1, {2, 3}, &test_instance};

// A bit source that reflects the process' own memory.
class TestBitSource : public BitSource {
 public:
  ~TestBitSource() override {}

  bool GetAll(const AddressRange& range, void* data_ptr) override {
    ::memcpy(data_ptr, reinterpret_cast<void*>(range.addr()), range.size());
    return true;
  }

  bool GetFrom(const AddressRange& range,
               size_t* data_cnt,
               void* data_ptr) override {
    *data_cnt = range.size();
    return GetAll(range, data_ptr);
  }

  bool HasSome(const AddressRange& range) override { return true; }
};

class TypedDataTest : public testing::Test {
 protected:
  TypedData GetTestInstance() {
    return TypedData(
        test_bit_source(), CreateUDTType(),
        AddressRange(ToAddr(&test_instance), sizeof(test_instance)));
  }

  Address ToAddr(const void* ptr) { return reinterpret_cast<Address>(ptr); }

  void AssertFieldMatchesDataType(const TestUDT* ignore,
                                  const TypedData& data) {
    ASSERT_TRUE(data.IsPrimitiveType());
    ASSERT_TRUE(data.IsPointerType());
  }
  void AssertFieldMatchesDataType(const TestUDT::InnerUDT& ignore,
                                  const TypedData& data) {
    ASSERT_FALSE(data.IsPrimitiveType());
    ASSERT_FALSE(data.IsPointerType());
  }
  void AssertFieldMatchesDataType(uint8_t ignore, const TypedData& data) {
    ASSERT_TRUE(data.IsPrimitiveType());
    ASSERT_FALSE(data.IsPointerType());
  }
  void AssertFieldMatchesDataType(uint16_t ignore, const TypedData& data) {
    ASSERT_TRUE(data.IsPrimitiveType());
    ASSERT_FALSE(data.IsPointerType());
  }
  void AssertFieldMatchesDataType(uint32_t ignore, const TypedData& data) {
    ASSERT_TRUE(data.IsPrimitiveType());
    ASSERT_FALSE(data.IsPointerType());
  }

  template <typename FieldType>
  void AssertFieldMatchesData(const FieldType& field, const TypedData& data) {
    AssertFieldMatchesDataType(field, data);
    ASSERT_EQ(ToAddr(&field), data.range().addr());
    ASSERT_EQ(sizeof(field), data.range().size());
  }

 private:
  TypePtr CreateUDTType() {
    TypePtr uint8_type = new BasicType(L"uint8_t", sizeof(uint8_t));
    TypePtr uint16_type = new BasicType(L"uint16_t", sizeof(uint16_t));
    TypePtr uint32_type = new BasicType(L"uint32_t", sizeof(uint32_t));
    repo_.AddType(uint8_type);
    repo_.AddType(uint16_type);
    repo_.AddType(uint32_type);

    UserDefinedType::Fields fields;
    UserDefinedTypePtr inner(
        new UserDefinedType(L"Inner", sizeof(TestUDT::InnerUDT)));
    fields.push_back(UserDefinedType::Field(
        L"inner_one", offsetof(TestUDT::InnerUDT, inner_one), 0, 0, 0,
        uint8_type->type_id()));
    fields.push_back(UserDefinedType::Field(
        L"inner_two", offsetof(TestUDT::InnerUDT, inner_two), 0, 0, 0,
        uint32_type->type_id()));
    inner->Finalize(fields);
    repo_.AddType(inner);

    fields.clear();
    UserDefinedTypePtr outer(new UserDefinedType(L"TestUDT", sizeof(TestUDT)));
    PointerTypePtr ptr_type(new PointerType(sizeof(TestUDT*)));
    repo_.AddType(ptr_type);

    fields.push_back(UserDefinedType::Field(L"one", offsetof(TestUDT, one), 0,
                                            0, 0, uint16_type->type_id()));
    fields.push_back(UserDefinedType::Field(L"two", offsetof(TestUDT, two), 0,
                                            0, 0, inner->type_id()));
    fields.push_back(UserDefinedType::Field(L"three", offsetof(TestUDT, three),
                                            0, 0, 0, ptr_type->type_id()));
    outer->Finalize(fields);
    repo_.AddType(outer);

    ptr_type->Finalize(Type::FLAG_CONST, outer->type_id());

    return outer;
  }

  BitSource* test_bit_source() { return &test_bit_source_; }

  TestBitSource test_bit_source_;
  TypeRepository repo_;
};

}  // namespace

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
}

TEST_F(TypedDataTest, GetField) {
  TypedData data(GetTestInstance());

  TypedData one;
  ASSERT_TRUE(data.GetField(0, &one));
  AssertFieldMatchesData(test_instance.one, one);

  TypedData two;
  ASSERT_TRUE(data.GetField(1, &two));
  AssertFieldMatchesData(test_instance.two, two);

  TypedData inner_one;
  ASSERT_TRUE(two.GetField(0, &inner_one));
  AssertFieldMatchesData(test_instance.two.inner_one, inner_one);

  TypedData inner_two;
  ASSERT_TRUE(two.GetField(1, &inner_two));
  AssertFieldMatchesData(test_instance.two.inner_two, inner_two);

  TypedData three;
  ASSERT_TRUE(data.GetField(2, &three));
  AssertFieldMatchesData(test_instance.three, three);
}

TEST_F(TypedDataTest, GetValue) {
  TypedData data(GetTestInstance());

  // Test a simple value fetch.
  TypedData one;
  ASSERT_TRUE(data.GetNamedField(L"one", &one));
  uint16_t data16 = 0;
  ASSERT_TRUE(one.GetValue(&data16));
  ASSERT_EQ(test_instance.one, data16);

  // Wrong size data fetch should fail.
  uint8_t data8 = 0;
  ASSERT_FALSE(one.GetValue(&data8));
  uint32_t data32 = 0;
  ASSERT_FALSE(one.GetValue(&data32));

  // Test a nested field fetch.
  TypedData two;
  ASSERT_TRUE(data.GetField(1, &two));
  TypedData inner_two;
  ASSERT_TRUE(two.GetField(1, &inner_two));

  ASSERT_FALSE(inner_two.GetValue(&data8));
  ASSERT_FALSE(inner_two.GetValue(&data16));
  ASSERT_TRUE(inner_two.GetValue(&data32));
  ASSERT_EQ(test_instance.two.inner_two, data32);
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
  ASSERT_TRUE(derefenced.range() == data.range());
}

}  // namespace refinery
