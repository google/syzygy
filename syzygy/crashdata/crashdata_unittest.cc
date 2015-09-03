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

#include "syzygy/crashdata/crashdata.h"

#include "gtest/gtest.h"

namespace crashdata {

TEST(CrashDataTest, ValueGetLeaf) {
  Value v;
  Leaf* l = ValueGetLeaf(&v);
  EXPECT_EQ(Value_Type_LEAF, v.type());
  EXPECT_TRUE(v.has_leaf());
  EXPECT_FALSE(v.has_list());
  EXPECT_FALSE(v.has_dictionary());
  EXPECT_EQ(l, v.mutable_leaf());
}

TEST(CrashDataTest, ValueGetList) {
  Value v;
  ValueList* l = ValueGetValueList(&v);
  EXPECT_EQ(Value_Type_VALUE_LIST, v.type());
  EXPECT_FALSE(v.has_leaf());
  EXPECT_TRUE(v.has_list());
  EXPECT_FALSE(v.has_dictionary());
  EXPECT_EQ(l, v.mutable_list());
}

TEST(CrashDataTest, ValueGetDict) {
  Value v;
  Dictionary* d = ValueGetDict(&v);
  EXPECT_EQ(Value_Type_DICTIONARY, v.type());
  EXPECT_FALSE(v.has_leaf());
  EXPECT_FALSE(v.has_list());
  EXPECT_TRUE(v.has_dictionary());
  EXPECT_EQ(d, v.mutable_dictionary());
}

TEST(CrashDataTest, DictAddValue) {
  Value v;
  Dictionary* d = ValueGetDict(&v);
  EXPECT_EQ(0u, d->values_size());

  std::string key("key");
  Value* v1 = DictAddValue(key, d);

  EXPECT_EQ(1u, d->values_size());
  const KeyValue& kv = d->values().Get(0);
  EXPECT_EQ(key, kv.key());
  EXPECT_EQ(v1, &kv.value());
}

TEST(CrashDataTest, DictAddLeaf) {
  Value v;
  Dictionary* d = ValueGetDict(&v);
  EXPECT_EQ(0u, d->values_size());

  std::string key("key");
  Leaf* l = DictAddLeaf(key, d);

  EXPECT_EQ(1u, d->values_size());
  const KeyValue& kv = d->values().Get(0);
  EXPECT_EQ(key, kv.key());
  EXPECT_EQ(Value_Type_LEAF, kv.value().type());
  EXPECT_EQ(l, &kv.value().leaf());
}

TEST(CrashDataTest, DictAddDict) {
  Value v;
  Dictionary* d = ValueGetDict(&v);
  EXPECT_EQ(0u, d->values_size());

  std::string key("key");
  Dictionary* dict = DictAddDict(key, d);

  EXPECT_EQ(1u, d->values_size());
  const KeyValue& kv = d->values().Get(0);
  EXPECT_EQ(key, kv.key());
  EXPECT_EQ(Value_Type_DICTIONARY, kv.value().type());
  EXPECT_EQ(dict, &kv.value().dictionary());
}

TEST(CrashDataTest, LeafSetInt) {
  Value v;
  Leaf* l = ValueGetLeaf(&v);

  LeafSetInt(42, l);
  EXPECT_EQ(Leaf_Type_INTEGER, l->type());
  EXPECT_EQ(42, l->integer());

  EXPECT_TRUE(l->has_integer());
  EXPECT_FALSE(l->has_unsigned_integer());
  EXPECT_FALSE(l->has_real());
  EXPECT_FALSE(l->has_string());
  EXPECT_FALSE(l->has_address());
  EXPECT_FALSE(l->has_stack_trace());
  EXPECT_FALSE(l->has_blob());
}

TEST(CrashDataTest, LeafSetUInt) {
  Value v;
  Leaf* l = ValueGetLeaf(&v);

  LeafSetUInt(42, l);
  EXPECT_EQ(Leaf_Type_UNSIGNED_INTEGER, l->type());
  EXPECT_EQ(42, l->unsigned_integer());

  EXPECT_FALSE(l->has_integer());
  EXPECT_TRUE(l->has_unsigned_integer());
  EXPECT_FALSE(l->has_real());
  EXPECT_FALSE(l->has_string());
  EXPECT_FALSE(l->has_address());
  EXPECT_FALSE(l->has_stack_trace());
  EXPECT_FALSE(l->has_blob());
}

TEST(CrashDataTest, LeafSetReal) {
  Value v;
  Leaf* l = ValueGetLeaf(&v);

  LeafSetReal(0.2, l);
  EXPECT_EQ(Leaf_Type_REAL, l->type());
  EXPECT_EQ(0.2, l->real());

  EXPECT_FALSE(l->has_integer());
  EXPECT_FALSE(l->has_unsigned_integer());
  EXPECT_TRUE(l->has_real());
  EXPECT_FALSE(l->has_string());
  EXPECT_FALSE(l->has_address());
  EXPECT_FALSE(l->has_stack_trace());
  EXPECT_FALSE(l->has_blob());
}

TEST(CrashDataTest, LeafGetString) {
  Value v;
  Leaf* l = ValueGetLeaf(&v);

  std::string* s = LeafGetString(l);
  EXPECT_EQ(Leaf_Type_STRING, l->type());
  EXPECT_EQ(s, l->mutable_string());

  EXPECT_FALSE(l->has_integer());
  EXPECT_FALSE(l->has_unsigned_integer());
  EXPECT_FALSE(l->has_real());
  EXPECT_TRUE(l->has_string());
  EXPECT_FALSE(l->has_address());
  EXPECT_FALSE(l->has_stack_trace());
  EXPECT_FALSE(l->has_blob());
}

TEST(CrashDataTest, LeafGetAddress) {
  Value v;
  Leaf* l = ValueGetLeaf(&v);

  Address* a = LeafGetAddress(l);
  EXPECT_EQ(Leaf_Type_ADDRESS, l->type());
  EXPECT_EQ(a, l->mutable_address());

  EXPECT_FALSE(l->has_integer());
  EXPECT_FALSE(l->has_unsigned_integer());
  EXPECT_FALSE(l->has_real());
  EXPECT_FALSE(l->has_string());
  EXPECT_TRUE(l->has_address());
  EXPECT_FALSE(l->has_stack_trace());
  EXPECT_FALSE(l->has_blob());
}

TEST(CrashDataTest, LeafGetStackTrace) {
  Value v;
  Leaf* l = ValueGetLeaf(&v);

  StackTrace* st = LeafGetStackTrace(l);
  EXPECT_EQ(Leaf_Type_STACK_TRACE, l->type());
  EXPECT_EQ(st, l->mutable_stack_trace());

  EXPECT_FALSE(l->has_integer());
  EXPECT_FALSE(l->has_unsigned_integer());
  EXPECT_FALSE(l->has_real());
  EXPECT_FALSE(l->has_string());
  EXPECT_FALSE(l->has_address());
  EXPECT_TRUE(l->has_stack_trace());
  EXPECT_FALSE(l->has_blob());
}

TEST(CrashDataTest, LeafGetBlob) {
  Value v;
  Leaf* l = ValueGetLeaf(&v);

  Blob* b = LeafGetBlob(l);
  EXPECT_EQ(Leaf_Type_BLOB, l->type());
  EXPECT_EQ(b, l->mutable_blob());

  EXPECT_FALSE(l->has_integer());
  EXPECT_FALSE(l->has_unsigned_integer());
  EXPECT_FALSE(l->has_real());
  EXPECT_FALSE(l->has_string());
  EXPECT_FALSE(l->has_address());
  EXPECT_FALSE(l->has_stack_trace());
  EXPECT_TRUE(l->has_blob());
}

}  // namespace crashdata
