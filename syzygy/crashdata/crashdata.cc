// Copyright 2014 Google Inc. All Rights Reserved.
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

// This uses 'assert' and not base DCHECKs so that it is portable.
#include <assert.h>

namespace crashdata {

Leaf* ValueGetLeaf(Value* value) {
  assert(value != nullptr);
  value->set_type(Value_Type_LEAF);
  return value->mutable_leaf();
}

ValueList* ValueGetValueList(Value* value) {
  assert(value != nullptr);
  value->set_type(Value_Type_VALUE_LIST);
  return value->mutable_list();
}

Dictionary* ValueGetDict(Value* value) {
  assert(value != nullptr);
  value->set_type(Value_Type_DICTIONARY);
  return value->mutable_dictionary();
}

Value* DictAddValue(const char* key, Dictionary* dict) {
  assert(key != nullptr);
  assert(dict != nullptr);
  KeyValue* kv = dict->add_values();
  kv->set_key(key);
  return kv->mutable_value();
}

Value* DictAddValue(const std::string& key, Dictionary* dict) {
  assert(dict != nullptr);
  return DictAddValue(key.c_str(), dict);
}

Leaf* DictAddLeaf(const char* key, Dictionary* dict) {
  assert(key != nullptr);
  assert(dict != nullptr);
  Value* v = DictAddValue(key, dict);
  Leaf* l = ValueGetLeaf(v);
  return l;
}

Leaf* DictAddLeaf(const std::string& key, Dictionary* dict) {
  assert(dict != nullptr);
  return DictAddLeaf(key.c_str(), dict);
}

Dictionary* DictAddDict(const char* key, Dictionary* dict) {
  assert(key != nullptr);
  assert(dict != nullptr);
  Value* v = DictAddValue(key, dict);
  Dictionary* d = ValueGetDict(v);
  return d;
}

Dictionary* DictAddDict(const std::string& key, Dictionary* dict) {
  assert(dict != nullptr);
  return DictAddDict(key.c_str(), dict);
}

void LeafSetInt(google::protobuf::int64 value, Leaf* leaf) {
  assert(leaf != nullptr);
  leaf->set_type(Leaf_Type_INTEGER);
  leaf->set_integer(value);
}

void LeafSetUInt(google::protobuf::uint64 value, Leaf* leaf) {
  assert(leaf != nullptr);
  leaf->set_type(Leaf_Type_UNSIGNED_INTEGER);
  leaf->set_unsigned_integer(value);
}

void LeafSetReal(double value, Leaf* leaf) {
  assert(leaf != nullptr);
  leaf->set_type(Leaf_Type_REAL);
  leaf->set_real(value);
}

std::string* LeafGetString(Leaf* leaf) {
  assert(leaf != nullptr);
  leaf->set_type(Leaf_Type_STRING);
  return leaf->mutable_string();
}

Address* LeafGetAddress(Leaf* leaf) {
  assert(leaf != nullptr);
  leaf->set_type(Leaf_Type_ADDRESS);
  return leaf->mutable_address();
}

StackTrace* LeafGetStackTrace(Leaf* leaf) {
  assert(leaf != nullptr);
  leaf->set_type(Leaf_Type_STACK_TRACE);
  return leaf->mutable_stack_trace();
}

Blob* LeafGetBlob(Leaf* leaf) {
  assert(leaf != nullptr);
  leaf->set_type(Leaf_Type_BLOB);
  return leaf->mutable_blob();
}

}  // namespace crashdata
