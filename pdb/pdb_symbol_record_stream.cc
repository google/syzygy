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

#include "syzygy/pdb/pdb_symbol_record_stream.h"

#include <string>

#include "base/stringprintf.h"
#include "syzygy/common/align.h"
#include "syzygy/pdb/pdb_reader.h"
#include "syzygy/pdb/pdb_util.h"

namespace pdb {

bool ReadSymbolRecord(PdbStream* stream, SymbolRecordVector* symbol_vector) {
  DCHECK(stream != NULL);
  DCHECK(symbol_vector != NULL);

  if (!stream->Seek(0)) {
    LOG(ERROR) << "Unable to seek to the beginning of the symbol record "
               << "stream.";
    return false;
  }
  size_t stream_end = stream->length();

  // Process each symbol present in the stream. For now we only save their
  // starting positions, their lengths and their types to be able to dump them.
  while (stream->pos() < stream_end) {
    uint16 len = 0;
    uint16 symbol_type = 0;
    if (!stream->Read(&len, 1)) {
      LOG(ERROR) << "Unable to read a symbol record length.";
      return false;
    }
    size_t symbol_start = stream->pos();
    if (!stream->Read(&symbol_type, 1))  {
      LOG(ERROR) << "Unable to read a symbol record type.";
      return false;
    }
    SymbolRecord sym_record;
    sym_record.type = symbol_type;
    sym_record.start_position = stream->pos();
    sym_record.len = len - sizeof(symbol_type);
    symbol_vector->push_back(sym_record);
    if (!stream->Seek(symbol_start + len)) {
      LOG(ERROR) << "Unable to seek to the end of the symbol record.";
      return false;
    }
  }

  return true;
}

}  // namespace pdb
