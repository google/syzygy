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

#include "syzygy/experimental/pdb_writer/pdb_public_stream_writer.h"

#include <algorithm>

#include "syzygy/core/section_offset_address.h"
#include "syzygy/experimental/pdb_writer/symbols/image_symbol.h"
#include "syzygy/pdb/pdb_constants.h"
#include "syzygy/pdb/pdb_data.h"
#include "syzygy/pdb/pdb_stream.h"
#include "syzygy/pdb/pdb_util.h"

namespace pdb {

namespace {

// The value we've observed for the |unknown| field of the public stream header.
const uint32 kPublicStreamUnknownValue = -1;

// The value we've observed for the |unknown| field of PublicStreamSymbolOffset.
const uint32 kPublicStreamSymbolOffsetUnknownValue = 1;

// The size of the bit set found in the public stream, in bits. The size is
// constant even when there is more than 4096 public symbols defined in the PDB.
const uint32 kPublicStreamHashTableBitSetSize = 512 * 8;

// Number by which indexes of public symbols are multiplied before being written
// in the hash table of the public stream.
// TODO(fdoray): Determine whether it corresponds to the size of a known struct.
const uint32 kPublicStreamHashTableIndexMultiplier = 12;

// Contains the address of a symbol with the offset at which it has been written
// in the symbol record stream. Is used to generate the sorted table of symbols
// found at the end of the public stream.
struct SymbolWithRecordOffset {
  // Address of the symbol in the PE file.
  core::SectionOffsetAddress address;

  // Offset of the symbol in the symbol record stream.
  uint32 record_offset;

  bool operator<(const SymbolWithRecordOffset& other) const {
    return address < other.address;
  }
};

bool SymbolIsPublic(const Symbol& symbol) {
  return symbol.GetType() == Microsoft_Cci_Pdb::S_PUB32;
}

bool WritePublicStreamHashTable(const SymbolVector& symbols,
                                const SymbolOffsets& symbol_offsets,
                                WritablePdbStream* stream) {
  DCHECK_EQ(symbols.size(), symbol_offsets.size());
  DCHECK_NE(static_cast<WritablePdbStream*>(NULL), stream);

  // A vector that contains the indexes of symbols that were first in their
  // buckets.
  std::vector<uint32> hash_table_representatives;

  // Write a bit set with ones for buckets that contain at least one public
  // symbol.
  pdb::PdbBitSet bits;
  bits.Resize(kPublicStreamHashTableBitSetSize);

  for (size_t i = 0; i < symbols.size(); ++i) {
    if (!SymbolIsPublic(*symbols[i]))
      continue;

    symbols::ImageSymbol* public_symbol =
        reinterpret_cast<symbols::ImageSymbol*>(symbols[i].get());

    uint16 bucket =
        HashString(public_symbol->name()) % kPublicStreamHashTableBitSetSize;

    if (!bits.IsSet(bucket)) {
      hash_table_representatives.push_back(i);
      bits.Set(bucket);
    }
  }

  if (!bits.Write(stream, false))
    return false;

  // Write a 0 at the end of the bit set.
  if (!stream->Write(static_cast<uint32>(0)))
    return false;

  // Write a table with the value
  // (|index| * |kPublicStreamHashTableIndexMultiplier|) for each symbol that
  // was the first to be inserted in its bucket.
  for (size_t i = 0; i < hash_table_representatives.size(); ++i) {
    if (!stream->Write(static_cast<uint32>(
            hash_table_representatives[i] *
            kPublicStreamHashTableIndexMultiplier))) {
      return false;
    }
  }

  return true;
}

}  // namespace

bool WritePublicStream(const SymbolVector& symbols,
                       const SymbolOffsets& symbol_offsets,
                       WritablePdbStream* stream) {
  DCHECK_EQ(symbols.size(), symbol_offsets.size());
  DCHECK_NE(static_cast<WritablePdbStream*>(NULL), stream);

  // Reserve space for the public stream header.
  stream->set_pos(sizeof(PublicStreamHeader));

  // Write a table of public symbol offsets. The offsets of the public symbols
  // are incremented by one and listed in the order of their definition in the
  // symbol record stream.
  size_t num_public_symbols = 0;

  for (size_t i = 0; i < symbols.size(); ++i) {
    if (!SymbolIsPublic(*symbols[i]))
      continue;

    PublicStreamSymbolOffset symbol_offset;
    symbol_offset.offset = symbol_offsets[i] + 1;
    symbol_offset.unknown = kPublicStreamSymbolOffsetUnknownValue;
    if (!stream->Write(symbol_offset))
      return false;

    ++num_public_symbols;
  }

  // Write a hash table in which keys are symbol names.
  size_t hash_table_offset = stream->pos();
  if (num_public_symbols > 0 &&
      !WritePublicStreamHashTable(symbols, symbol_offsets, stream)) {
    return false;
  }

  // Write a table with offsets of symbol records sorted by symbol addresses.
  size_t sorted_symbols_offset = stream->pos();

  std::vector<SymbolWithRecordOffset> symbols_with_offsets;
  for (size_t i = 0; i < symbols.size(); ++i) {
    if (!SymbolIsPublic(*symbols[i]))
      continue;

    symbols::ImageSymbol* public_symbol =
        reinterpret_cast<symbols::ImageSymbol*>(symbols[i].get());

    SymbolWithRecordOffset symbol_with_offset;
    symbol_with_offset.address = public_symbol->address();
    symbol_with_offset.record_offset = symbol_offsets[i];
    symbols_with_offsets.push_back(symbol_with_offset);
  }
  std::sort(symbols_with_offsets.begin(), symbols_with_offsets.end());

  for (size_t i = 0; i < symbols_with_offsets.size(); ++i) {
    if (!stream->Write(symbols_with_offsets[i].record_offset))
      return false;
  }

  // Write the header of the public stream.
  PublicStreamHeader header = {};
  header.sorted_symbols_offset =
      sorted_symbols_offset - offsetof(PublicStreamHeader, unknown);
  header.sorted_symbols_size = sizeof(uint32) * num_public_symbols;
  header.unknown = kPublicStreamUnknownValue;
  header.signature = kPublicStreamSignature;
  header.offset_table_size =
      sizeof(PublicStreamSymbolOffset)* num_public_symbols;
  header.hash_table_size = sorted_symbols_offset - hash_table_offset;

  stream->set_pos(0);
  if (!stream->Write(header))
    return false;

  return true;
}

}  // namespace pdb
