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

#ifndef SYZYGY_REFINERY_TYPES_TEST_TYPES_H_
#define SYZYGY_REFINERY_TYPES_TEST_TYPES_H_

namespace testing {

// Macro for registering the size of a type. By setting up const static
// variables these values appear in the symbol record stream and we can parse
// them and use them for testing.
#define REGISTER_SIZEOF(NAME, TYPE) \
  static const size_t kPdbCrawler##NAME##Size = sizeof(##TYPE)
#define REGISTER_SIZEOF_TYPE(TYPE) REGISTER_SIZEOF(##TYPE, ##TYPE)

// Macro for registering the offset of a member field in the same way.
#define REGISTER_OFFSETOF(TYPE, FIELD)                       \
  static const size_t kPdbCrawler##FIELD##In##TYPE##Offset = \
      offsetof(##TYPE, ##FIELD)

// Functions implemented to ensure all the test types make it into the
// associated PDB file.
void AliasTypesOne();
void AliasTypesTwo();

}  // namespace testing

#endif  // SYZYGY_REFINERY_TYPES_TEST_TYPES_H_
