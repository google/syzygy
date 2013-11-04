// Copyright 2012 Google Inc. All Rights Reserved.
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

#include "syzygy/experimental/pdb_dumper/pdb_dump_util.h"

#include "syzygy/experimental/pdb_dumper/cvinfo_ext.h"
#include "syzygy/pdb/pdb_stream.h"

namespace pdb {

namespace cci = Microsoft_Cci_Pdb;

// Dumps an unknown block of data in hexdump mode.
bool DumpUnknownBlock(FILE* out,
                      PdbStream* stream,
                      uint16 len,
                      uint8 indent_level) {
  DCHECK_NE(reinterpret_cast<FILE*>(NULL), out);
  DCHECK_NE(reinterpret_cast<PdbStream*>(NULL), stream);

  // This should be a power of two.
  const size_t kColumnCount = 16;
  // This should be an divisor of kColumnCount.
  const size_t kGroupSize = 8;
  COMPILE_ASSERT(kColumnCount % kGroupSize == 0,
                 kGroupSize_must_be_a_divisor_of_kColumnCount);

  uint8 buffer[kColumnCount];
  size_t bytes_read = 0;
  while (bytes_read < len) {
    size_t bytes_to_read = len - bytes_read;
    if (bytes_to_read > kColumnCount)
      bytes_to_read = kColumnCount;
    size_t bytes_just_read = 0;
    if (!stream->ReadBytes(buffer, bytes_to_read, &bytes_just_read) ||
        bytes_just_read != bytes_to_read) {
      LOG(ERROR) << "Unable to read stream.";
      return false;
    }
    DumpTabs(out, indent_level);

    // Dump the hex encoded bytes.
    for (size_t i = 0; i < kColumnCount; ++i) {
      if (i != 0 && i % kGroupSize == 0)
        ::fputc(' ', out);
      if (i < bytes_just_read) {
        ::fprintf(out, "%02X ", buffer[i]);
      } else {
        ::fprintf(out, "   ");
      }
    }
    ::fputc(' ', out);

    // Dump the ASCII printable bytes.
    for (size_t i = 0; i < bytes_just_read; ++i) {
      if (i != 0 && i % kGroupSize == 0)
        ::fputc(' ', out);
      if (buffer[i] < 32 || buffer[i] > 126) {
        ::fputc('.', out);
      } else {
        ::fputc(buffer[i], out);
      }
    }
    ::fprintf(out, "\n");

    bytes_read += bytes_just_read;
  }

  return true;
}

void DumpTabs(FILE* out, uint8 indent_level) {
  DCHECK(out != NULL);
  for (uint8 i = 0; i < indent_level;  ++i) {
    ::fprintf(out, "  ");
  }
}

void DumpIndentedText(FILE* out, uint8 indent_level, const char* format, ...) {
  DCHECK(out != NULL);
  DCHECK(format != NULL);
  DumpTabs(out, indent_level);
  va_list arguments;
  va_start(arguments, format);
  ::vfprintf(out, format, arguments);
}

}  // namespace pdb
