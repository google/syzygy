// Copyright 2012 Google Inc.
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

#include "syzygy/pdb/pdb_dump_util.h"

#include "syzygy/pdb/pdb_stream.h"

namespace pdb {

bool DumpUnknownBlock(FILE* out, PdbStream* stream, uint16 len) {
  uint8 buffer[32];
  size_t bytes_read = 0;
  while (bytes_read < len) {
    size_t bytes_to_read = len - bytes_read;
    if (bytes_to_read > sizeof(buffer))
      bytes_to_read = sizeof(buffer);
    size_t bytes_just_read = 0;
    if (!stream->ReadBytes(buffer, bytes_to_read, &bytes_just_read) ||
        bytes_just_read == 0) {
      LOG(ERROR) << "Unable to read stream.";
      return false;
    }
    ::fprintf(out, "\t\t");
    for (size_t i = 0; i < bytes_just_read; ++i)
      ::fprintf(out, "%X", buffer[i]);
    ::fprintf(out, "\n");
    bytes_read += bytes_just_read;
  }

  return true;
}

}  // namespace pdb
