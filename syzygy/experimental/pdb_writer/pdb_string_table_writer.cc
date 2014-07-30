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
// The string table starts with a header:
//     uint32 signature: Equal to kPdbStringTableSignature.
//     uint32 version: Equal to kPdbStringTableVersion.
//     uint32 size: Size of the string table that follows, in bytes.
//
// Then, the null-terminated strings of the table are written, followed by:
//     uint32 entries_count: Number of strings in the string table.
//
// After |entries_count|, the offset of each string is found as an uint32
// (in bytes and relative to the end of the header). Finally, the table ends
// with:
//     uint32 string_count: Number of non-empty strings.

#include "syzygy/experimental/pdb_writer/pdb_string_table_writer.h"

#include "syzygy/common/assertions.h"
#include "syzygy/pdb/pdb_constants.h"
#include "syzygy/pdb/pdb_data.h"
#include "syzygy/pdb/pdb_stream.h"

namespace pdb {

bool WriteStringTable(const StringTable& strings, WritablePdbStream* stream) {
  // Write the header. The |size| field will be updated later.
  StringTableHeader header = {};
  header.signature = kPdbStringTableSignature;
  header.version = kPdbStringTableVersion;
  if (!stream->Write(header))
    return false;

  // Write the null-terminated strings.
  for (size_t i = 0; i < strings.size(); ++i)  {
    if (!stream->Write(strings[i].size() + 1, strings[i].data()))
      return false;
  }

  // Write the number of strings.
  uint32 entries_count = strings.size();
  if (!stream->Write(entries_count))
    return false;

  // Write the string offsets.
  uint32 string_offset = 0;
  uint32 num_non_empty_strings = 0;
  for (size_t i = 0; i < strings.size(); ++i) {
    if (!stream->Write(string_offset))
      return false;
    string_offset += strings[i].size() + 1;

    if (!strings[i].empty())
      ++num_non_empty_strings;
  }

  // Write the number of non-empty strings.
  if (!stream->Write(num_non_empty_strings))
    return false;

  // Save the ending position.
  size_t end_pos = stream->pos();

  // Write the size of the string table, in bytes.
  stream->set_pos(offsetof(StringTableHeader, size));
  if (!stream->Write(string_offset))
    return false;

  // Seek to the end of the string table.
  stream->set_pos(end_pos);
  return true;
}

}  // namespace pdb
