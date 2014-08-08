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

#include "syzygy/pdb/pdb_symbol_record.h"

#include <string>

#include "base/strings/stringprintf.h"
#include "syzygy/common/align.h"
#include "syzygy/pdb/pdb_reader.h"
#include "syzygy/pdb/pdb_util.h"
#include "third_party/cci/Files/CvInfo.h"

namespace cci = Microsoft_Cci_Pdb;

namespace pdb {

bool ReadSymbolRecord(PdbStream* stream,
                      size_t symbol_table_size,
                      SymbolRecordVector* symbol_vector) {
  DCHECK(stream != NULL);
  DCHECK(symbol_vector != NULL);

  size_t stream_end = stream->pos() + symbol_table_size;
  if (stream_end > stream->length()) {
    LOG(ERROR) << "The specified symbol table size exceeds the size of the "
               << "stream.";
    return false;
  }

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
    if (stream->pos() != stream_end && !stream->Seek(symbol_start + len)) {
      LOG(ERROR) << "Unable to seek to the end of the symbol record.";
      return false;
    }
  }

  return true;
}

// Reads symbols from the given symbol stream until the end of the stream.
bool VisitSymbols(VisitSymbolsCallback callback,
                  size_t symbol_table_size,
                  bool has_header,
                  PdbStream* symbols) {
  DCHECK(symbols != NULL);

  size_t symbol_table_end = symbols->pos() + symbol_table_size;
  if (symbol_table_end > symbols->length()) {
    LOG(ERROR) << "Symbol table size provided exceeds stream length.";
    return false;
  }

  if (has_header) {
    uint32 stream_type = 0;
    if (!symbols->Read(&stream_type, 1)) {
      LOG(ERROR) << "Unable to read symbol stream type.";
      return false;
    }
    if (stream_type != cci::C13) {
      LOG(ERROR) << "Unexpected symbol stream type (" << stream_type
                 << ").";
      return false;
    }
  }

  // Read the symbols from the linker symbol stream. We try to read at least
  // one symbol without checking the stream position.
  while (symbols->pos() < symbol_table_end) {
    uint16 symbol_length = 0;
    if (!symbols->Read(&symbol_length, 1)) {
      LOG(ERROR) << "Unable to read symbol length from symbol stream.";
      return false;
    }
    // We can see empty symbols in the symbol stream.
    if (symbol_length == 0) {
      // TODO(chrisha): I've only seen these as terminators thus far. Validate
      //     this fact for all symbol streams. If we find this to be true, we
      //     can break here and double check that we've consumed the entire
      //     stream content.
      continue;
    }

    if (symbol_length < 2) {
      LOG(ERROR) << "Symbol length too short to hold symbol type.";
      return false;
    }

    // Remember the position in the stream where the next symbol lies. This is
    // to be used for seeking later.
    size_t symbol_end = symbols->pos() + symbol_length;

    uint16 symbol_type = 0;
    if (!symbols->Read(&symbol_type, 1)) {
      LOG(ERROR) << "Failed to read symbol type from symbol stream.";
      return false;
    }

    if (symbol_end > symbol_table_end) {
      LOG(ERROR) << "Encountered symbol length that exceeds table size.";
      return false;
    }

    // We provide the length of the symbol data to the callback, exclusive of
    // the symbol type header.
    if (!callback.Run(symbol_length - 2, symbol_type, symbols))
      return false;

    if (!symbols->Seek(symbol_end)) {
      LOG(ERROR) << "Failed to seek past symbol in symbol stream.";
      return false;
    }
  }

  return true;
}

}  // namespace pdb
