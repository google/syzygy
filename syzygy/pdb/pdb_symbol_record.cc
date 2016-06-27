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
#include "syzygy/pdb/pdb_stream_reader.h"
#include "syzygy/pdb/pdb_util.h"
#include "third_party/cci/Files/CvInfo.h"

namespace cci = Microsoft_Cci_Pdb;

namespace pdb {

bool ReadSymbolRecord(PdbStream* stream,
                      size_t symbol_table_offset,
                      size_t symbol_table_size,
                      SymbolRecordVector* symbol_vector) {
  DCHECK(stream != NULL);
  DCHECK(symbol_vector != NULL);

  size_t stream_end = symbol_table_offset + symbol_table_size;
  if (stream_end > stream->length()) {
    LOG(ERROR) << "The specified symbol table size exceeds the size of the "
               << "stream.";
    return false;
  }

  pdb::PdbStreamReaderWithPosition reader(symbol_table_offset,
                                          symbol_table_size, stream);
  common::BinaryStreamParser parser(&reader);

  // Process each symbol present in the stream. For now we only save their
  // starting positions, their lengths and their types to be able to dump them.
  while (!reader.AtEnd()) {
    uint16_t len = 0;
    uint16_t symbol_type = 0;
    if (!parser.Read(&len)) {
      LOG(ERROR) << "Unable to read a symbol record length.";
      return false;
    }
    if (!parser.Read(&symbol_type)) {
      LOG(ERROR) << "Unable to read a symbol record type.";
      return false;
    }
    SymbolRecord sym_record;
    sym_record.type = symbol_type;
    sym_record.start_position = symbol_table_offset + reader.Position();
    sym_record.len = len - sizeof(symbol_type);
    symbol_vector->push_back(sym_record);
    if (!reader.AtEnd() && !reader.Consume(len - sizeof(symbol_type))) {
      LOG(ERROR) << "Unable to seek to the end of the symbol record.";
      return false;
    }
  }

  return true;
}

// Reads symbols from the given symbol stream until the end of the stream.
bool VisitSymbols(VisitSymbolsCallback callback,
                  size_t symbol_table_offset,
                  size_t symbol_table_size,
                  bool has_header,
                  PdbStream* symbols) {
  DCHECK(symbols != NULL);

  size_t symbol_table_end = symbol_table_offset + symbol_table_size;

  if (symbol_table_end > symbols->length()) {
    LOG(ERROR) << "Symbol table size provided exceeds stream length.";
    return false;
  }

  pdb::PdbStreamReaderWithPosition stream_reader(symbol_table_offset,
                                                 symbol_table_size, symbols);
  common::BinaryStreamParser stream_parser(&stream_reader);
  if (has_header) {
    uint32_t stream_type = 0;
    if (!stream_parser.Read(&stream_type)) {
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
  while (stream_reader.Position() < symbol_table_end) {
    uint16_t symbol_length = 0;
    if (!stream_parser.Read(&symbol_length)) {
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
    size_t symbol_end = stream_reader.Position() + symbol_length;

    uint16_t symbol_type = 0;
    if (!stream_parser.Read(&symbol_type)) {
      LOG(ERROR) << "Failed to read symbol type from symbol stream.";
      return false;
    }

    if (symbol_end > symbol_table_end) {
      LOG(ERROR) << "Encountered symbol length that exceeds table size.";
      return false;
    }

    // Subtract the length of the type we already read.
    symbol_length -= sizeof(symbol_type);

    // We provide the length of the symbol data to the callback, exclusive of
    // the symbol type header.
    size_t symbol_start = symbol_table_offset + stream_reader.Position();
    pdb::PdbStreamReaderWithPosition symbol_reader(symbol_start, symbol_length,
                                                   symbols);
    if (!callback.Run(symbol_length, symbol_type, &symbol_reader))
      return false;

    if (!stream_reader.Consume(symbol_length)) {
      LOG(ERROR) << "Failed to seek past symbol in symbol stream.";
      return false;
    }
  }

  return true;
}

}  // namespace pdb
