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
// Protobuf config.h for MSVC.

#ifndef THIRD_PARTY_PROTOBUF_CONFIG_H_
#define THIRD_PARTY_PROTOBUF_CONFIG_H_

#define HASH_MAP_H <hash_map>

#if _MSC_VER < 1310 || _MSC_VER >= 1600
#define HASH_NAMESPACE std
#else
#define HASH_NAMESPACE stdext
#endif

#define HASH_SET_H <hash_set>

#define HAVE_HASH_MAP 1
#define HAVE_HASH_SET 1
#define HAVE_ZLIB 1

#endif  // THIRD_PARTY_PROTOBUF_CONFIG_H_
