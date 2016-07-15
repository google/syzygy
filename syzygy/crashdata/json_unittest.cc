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

#include "syzygy/crashdata/json.h"

#include "gtest/gtest.h"

namespace crashdata {

namespace {

void TestConversion(bool pretty_print,
                    const Value& value,
                    const char* expected_json) {
  std::string json;
  EXPECT_TRUE(ToJson(pretty_print, &value, &json));
  EXPECT_EQ(json, expected_json);
}

}  // namespace

TEST(CrashDataJsonTest, BadValueFails) {
  Value value;
  std::string json;

  for (size_t i = Value_Type_Type_MIN; i <= Value_Type_Type_MAX; ++i) {
    value.set_type(static_cast<Value_Type>(i));
    EXPECT_FALSE(ToJson(true, &value, &json));
    EXPECT_TRUE(json.empty());
  }
}

TEST(CrashDataJsonTest, BadLeafFails) {
  Value value;
  Leaf* leaf = ValueGetLeaf(&value);
  std::string json;

  for (size_t i = Leaf_Type_Type_MIN; i <= Leaf_Type_Type_MAX; ++i) {
    leaf->set_type(static_cast<Leaf_Type>(i));
    EXPECT_FALSE(ToJson(true, &value, &json));
    EXPECT_TRUE(json.empty());
  }
}

TEST(CrashDataJsonTest, BadKeyValue) {
  Value value;
  value.set_type(Value_Type_DICTIONARY);
  Dictionary* dict = value.mutable_dictionary();
  KeyValue* kv = dict->add_values();
  std::string json;

  // No key and no value should fail.
  EXPECT_FALSE(ToJson(true, &value, &json));
  EXPECT_TRUE(json.empty());

  // A key and no value should fail.
  kv->set_key("key");
  EXPECT_FALSE(ToJson(true, &value, &json));
  EXPECT_TRUE(json.empty());

  // No key and a valid value should fail.
  kv->clear_key();
  Value* value2 = kv->mutable_value();
  Leaf* leaf = ValueGetLeaf(value2);
  leaf->set_type(Leaf_Type_INTEGER);
  leaf->set_integer(42);
  EXPECT_FALSE(ToJson(true, &value, &json));
  EXPECT_TRUE(json.empty());
}

TEST(CrashDataJsonTest, ValueLeafInteger) {
  Value value;
  LeafSetInt(-48, ValueGetLeaf(&value));

  const char kExpected[] = "-48";
  TestConversion(true, value, kExpected);
  TestConversion(false, value, kExpected);;
}

TEST(CrashDataJsonTest, ValueLeafUnsignedInteger) {
  Value value;
  LeafSetUInt(653, ValueGetLeaf(&value));

  const char kExpected[] = "653";
  TestConversion(true, value, kExpected);
  TestConversion(false, value, kExpected);;
}

TEST(CrashDataJsonTest, ValueLeafReal) {
  Value value;
  LeafSetReal(2.0e99, ValueGetLeaf(&value));

  const char kExpected[] = "1.9999999999999999E+99";
  TestConversion(true, value, kExpected);
  TestConversion(false, value, kExpected);
}

TEST(CrashDataJsonTest, ValueLeafString) {
  Value value;
  *LeafGetString(ValueGetLeaf(&value)) = "foo \"\\ bar";

  const char kExpected[] = "\"foo \\\"\\\\ bar\"";
  TestConversion(true, value, kExpected);
  TestConversion(false, value, kExpected);
}

TEST(CrashDataJsonTest, ValueLeafAddress) {
  Value value;
  LeafGetAddress(ValueGetLeaf(&value))->set_address(0xBADBEEF);

  const char kExpected[] = "\"0x0BADBEEF\"";
  TestConversion(true, value, kExpected);
  TestConversion(false, value, kExpected);;
}

TEST(CrashDataJsonTest, ValueLeafStackTrace) {
  Value value;
  StackTrace* stack = LeafGetStackTrace(ValueGetLeaf(&value));
  stack->add_frames(0xDEADBEEF);
  stack->add_frames(0xBADF00D);
  stack->add_frames(0x10000000);
  stack->add_frames(0x20000000);
  stack->add_frames(0x30000000);
  stack->add_frames(0x40000000);

  const char kExpectedPretty[] =
      "[\n"
      "  \"0xDEADBEEF\", \"0x0BADF00D\", \"0x10000000\", \"0x20000000\",\n"
      "  \"0x30000000\", \"0x40000000\"\n"
      "]";
  TestConversion(true, value, kExpectedPretty);

  const char kExpectedCompact[] = "[\"0xDEADBEEF\",\"0x0BADF00D\","
      "\"0x10000000\",\"0x20000000\",\"0x30000000\",\"0x40000000\"]";
  TestConversion(false, value, kExpectedCompact);
}

TEST(CrashDataJsonTest, ValueLeafBlob) {
  Value value;
  Blob* blob = LeafGetBlob(ValueGetLeaf(&value));
  blob->mutable_address()->set_address(0xF00);
  std::string* data = blob->mutable_data();
  for (size_t i = 0; i < 3; ++i) {
    data->push_back(static_cast<unsigned char>(0xDE));
    data->push_back(static_cast<unsigned char>(0xAD));
    data->push_back(static_cast<unsigned char>(0xBE));
    data->push_back(static_cast<unsigned char>(0xEF));
  }

  const char kExpectedPretty[] =
      "{\n"
      "  \"type\": \"blob\",\n"
      "  \"address\": \"0x00000F00\",\n"
      "  \"size\": null,\n"
      "  \"data\": [\n"
      "    \"0xDE\", \"0xAD\", \"0xBE\", \"0xEF\", \"0xDE\", \"0xAD\","
      " \"0xBE\", \"0xEF\",\n"
      "    \"0xDE\", \"0xAD\", \"0xBE\", \"0xEF\"\n"
      "  ]\n"
      "}";
  TestConversion(true, value, kExpectedPretty);

  const char kExpectedCompact[] =
      "{\"type\":\"blob\",\"address\":\"0x00000F00\",\"size\":null,"
      "\"data\":[\"0xDE\",\"0xAD\",\"0xBE\",\"0xEF\",\"0xDE\",\"0xAD\","
      "\"0xBE\",\"0xEF\",\"0xDE\",\"0xAD\",\"0xBE\",\"0xEF\"]}";
  TestConversion(false, value, kExpectedCompact);
}

TEST(CrashDataJsonTest, ValueList) {
  Value value;
  ValueList* list = ValueGetValueList(&value);

  LeafGetAddress(ValueGetLeaf(list->add_values()))->set_address(0xDEADF00D);
  LeafSetInt(42, ValueGetLeaf(list->add_values()));

  const char kExpectedPretty[] =
      "[\n"
      "  \"0xDEADF00D\",\n"
      "  42\n"
      "]";
  TestConversion(true, value, kExpectedPretty);

  const char kExpectedCompact[] = "[\"0xDEADF00D\",42]";
  TestConversion(false, value, kExpectedCompact);
}

TEST(CrashDataJsonTest, ValueDict) {
  Value value;
  Dictionary* dict = ValueGetDict(&value);

  LeafGetAddress(ValueGetLeaf(DictAddValue("key1", dict)))->set_address(
      0xDEADF00D);
  LeafSetInt(42, ValueGetLeaf(DictAddValue("key2", dict)));

  const char kExpectedPretty[] =
      "{\n"
      "  \"key1\": \"0xDEADF00D\",\n"
      "  \"key2\": 42\n"
      "}";
  TestConversion(true, value, kExpectedPretty);

  const char kExpectedCompact[] = "{\"key1\":\"0xDEADF00D\",\"key2\":42}";
  TestConversion(false, value, kExpectedCompact);
}

TEST(CrashDataJsonTest, AllTypes) {
  Value value;
  value.set_type(Value_Type_DICTIONARY);
  Dictionary* dict = value.mutable_dictionary();

  // One of each type of leaf.
  LeafSetInt(-42, ValueGetLeaf(DictAddValue("int", dict)));
  LeafSetUInt(42, ValueGetLeaf(DictAddValue("uint", dict)));
  LeafSetReal(2.0e99, ValueGetLeaf(DictAddValue("real", dict)));
  *LeafGetString(ValueGetLeaf(DictAddValue("string", dict))) = "foobar";
  LeafGetAddress(ValueGetLeaf(DictAddValue("address", dict)))->set_address(
      0xDEADF00D);
  LeafGetStackTrace(ValueGetLeaf(DictAddValue("stack-trace", dict)))
      ->add_frames(0xBAADBEEF);
  LeafGetBlob(ValueGetLeaf(DictAddValue("blob", dict)))->mutable_data()
      ->append("hey");

  // Nested dictionary with a single element.
  LeafSetInt(100, ValueGetLeaf(DictAddValue("INT", ValueGetDict(
      DictAddValue("dict", dict)))));

  // Nested list with a single element
  ValueList* list = ValueGetValueList(DictAddValue("list", dict));
  LeafSetInt(200, ValueGetLeaf(list->add_values()));

  const char kExpectedPretty[] =
      "{\n"
      "  \"int\": -42,\n"
      "  \"uint\": 42,\n"
      "  \"real\": 1.9999999999999999E+99,\n"
      "  \"string\": \"foobar\",\n"
      "  \"address\": \"0xDEADF00D\",\n"
      "  \"stack-trace\": [\n"
      "    \"0xBAADBEEF\"\n"
      "  ],\n"
      "  \"blob\": {\n"
      "    \"type\": \"blob\",\n"
      "    \"address\": null,\n"
      "    \"size\": null,\n"
      "    \"data\": [\n"
      "      \"0x68\", \"0x65\", \"0x79\"\n"
      "    ]\n"
      "  },\n"
      "  \"dict\": {\n"
      "    \"INT\": 100\n"
      "  },\n"
      "  \"list\": [\n"
      "    200\n"
      "  ]\n"
      "}";
  TestConversion(true, value, kExpectedPretty);

  const char kExpectedCompact[] =
      "{"
        "\"int\":-42,"
        "\"uint\":42,"
        "\"real\":1.9999999999999999E+99,"
        "\"string\":\"foobar\","
        "\"address\":\"0xDEADF00D\","
        "\"stack-trace\":[\"0xBAADBEEF\"],"
        "\"blob\":{"
          "\"type\":\"blob\","
          "\"address\":null,"
          "\"size\":null,"
          "\"data\":[\"0x68\",\"0x65\",\"0x79\"]"
        "},"
        "\"dict\":{"
          "\"INT\":100"
        "},"
        "\"list\":["
          "200"
        "]"
      "}";
  TestConversion(false, value, kExpectedCompact);
}

}  // namespace crashdata
