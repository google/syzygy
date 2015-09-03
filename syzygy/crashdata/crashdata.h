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
//
// Brings in the main crash data definitions. Serialized crash data in a
// minidump consists of a single Value object, which is an abstract base
// type. Conceptually the entire structure is analogous to JSON, with a
// few additional types for things that have special meaning in the context
// of a crash.
//
// This also contains a family of helper functions for building crash data
// protobufs.

#ifndef SYZYGY_CRASHDATA_CRASHDATA_H_
#define SYZYGY_CRASHDATA_CRASHDATA_H_

// This is a simple wrapper to the automatically generated header file.
#include "syzygy/crashdata/crashdata.pb.h"

namespace crashdata {

// @name Functions for initializing values.
// @{

// Makes the given value a leaf.
// @param value The value to be initialized.
// @returns the nested leaf object.
Leaf* ValueGetLeaf(Value* value);

// Makes the given value a list.
// @param value The value to be initialized.
// @returns the nested list object.
ValueList* ValueGetValueList(Value* value);

// Makes the given value a dictionary.
// @param value The value to be initialized.
// @returns the nested dictionary object.
Dictionary* ValueGetDict(Value* value);

// @}

// @name Functions for adding a key-value to a dict.
// @{

// Adds a value to a dictionary.
// @param key The key name.
// @param dict The dictionary to be modified.
// @returns a pointer to the created value.
Value* DictAddValue(const char* key, Dictionary* dict);
Value* DictAddValue(const std::string& key, Dictionary* dict);

// Adds a value containing a leaf to a dictionary.
// @param key The key name.
// @param dict The dictionary to be modified.
// @returns a pointer to the created leaf.
Leaf* DictAddLeaf(const char* key, Dictionary* dict);
Leaf* DictAddLeaf(const std::string& key, Dictionary* dict);

// Adds a value containing a dictionary to a dictionary.
// @param key The key name.
// @param dict The dictionary to be modified.
// @returns a pointer to the created dictionnary.
Dictionary* DictAddDict(const char* key, Dictionary* dict);
Dictionary* DictAddDict(const std::string& key, Dictionary* dict);
// @}

// @name Functions for initializing leaves.
// @{

// Makes the given leaf an integer.
// @param value The value to set.
// @param leaf The leaf to be modified.
void LeafSetInt(google::protobuf::int64 value, Leaf* leaf);

// Makes the given leaf an unsigned integer.
// @param value The value to set.
// @param leaf The leaf to be modified.
void LeafSetUInt(google::protobuf::uint64 value, Leaf* leaf);

// Makes the given leaf a real.
// @param value The value to set.
// @param leaf The leaf to be modified.
void LeafSetReal(double value, Leaf* leaf);

// Makes the given leaf a string.
// @param leaf The leaf to be initialized.
// @returns the nested string object.
std::string* LeafGetString(Leaf* leaf);

// Makes the given leaf an address.
// @param leaf The leaf to be initialized.
// @returns the nested address object.
Address* LeafGetAddress(Leaf* leaf);

// Makes the given leaf a stack-trace.
// @param leaf The leaf to be initialized.
// @returns the nested stack-trace object.
StackTrace* LeafGetStackTrace(Leaf* leaf);

// Makes the given leaf a blob.
// @param leaf The leaf to be initialized.
// @returns the nested blob object.
Blob* LeafGetBlob(Leaf* leaf);

// @}

}  // namespace crashdata

#endif  // SYZYGY_CRASHDATA_CRASHDATA_H_
