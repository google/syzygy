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
// Declares data structures found in archive files.

#ifndef SYZYGY_AR_AR_COMMON_H_
#define SYZYGY_AR_AR_COMMON_H_

#include <map>
#include <string>
#include <vector>

#include "base/time/time.h"
#include "syzygy/common/assertions.h"

namespace ar {

extern const size_t kArFileAlignment;
extern const char kArGlobalMagic[8];
extern const char kArFileMagic[2];

// The buffer object used for reading and writing files to an archive.
typedef std::vector<uint8> DataBuffer;

// Maps symbols by their name to the index of the archived file containing
// them.
typedef std::map<std::string, uint32> SymbolIndexMap;

// The global file header.
struct ArGlobalHeader {
  char magic[8];
};
COMPILE_ASSERT_IS_POD_OF_SIZE(ArGlobalHeader, 8);

// The header that prefixes each file that is encoded in the archive.
struct ArFileHeader {
  // Name of the field member, with a terminating '/'. If it begins with a
  // slash then the following integer is an offset into the filename table.
  char name[16];
  // Number of seconds since midnight 1 Jan 1970 UTC.
  char timestamp[12];
  // Blank in MSVS.
  char owner_id[6];
  // Blank in MSVS.
  char group_id[6];
  // ST_MODE from _wstat.
  char mode[8];
  // Size in bytes.
  char size[10];
  char magic[2];
};
COMPILE_ASSERT_IS_POD_OF_SIZE(ArFileHeader, 60);

// A parsed version of the archive file header.
struct ParsedArFileHeader {
  ParsedArFileHeader()
      : timestamp(), mode(0), size(0) {
  }

  std::string name;
  base::Time timestamp;
  uint32 mode;
  uint64 size;
};

}  // namespace ar

#endif  // SYZYGY_AR_AR_COMMON_H_
