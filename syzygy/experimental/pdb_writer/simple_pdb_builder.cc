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

#include "syzygy/experimental/pdb_writer/simple_pdb_builder.h"

#include "base/logging.h"
#include "syzygy/experimental/pdb_writer/pdb_debug_info_stream_writer.h"
#include "syzygy/experimental/pdb_writer/pdb_header_stream_writer.h"
#include "syzygy/experimental/pdb_writer/pdb_public_stream_writer.h"
#include "syzygy/experimental/pdb_writer/pdb_section_header_stream_writer.h"
#include "syzygy/experimental/pdb_writer/pdb_string_table_writer.h"
#include "syzygy/experimental/pdb_writer/pdb_symbol_record_writer.h"
#include "syzygy/experimental/pdb_writer/pdb_type_info_stream_writer.h"
#include "syzygy/pdb/pdb_byte_stream.h"
#include "syzygy/pdb/pdb_constants.h"
#include "syzygy/pdb/pdb_file.h"
#include "syzygy/pe/pdb_info.h"
#include "syzygy/pe/pe_file.h"

namespace pdb {

namespace {

// Index at which streams that don't have a fixed index are written.
// The values are written in the header stream or the debug info stream so that
// a PDB reader knows where to find the associated streams. The values have been
// chosen arbitrarily.
const size_t kNamesStreamIndex = kDbiStream + 1;
const size_t kSectionHeaderStreamIndex = kNamesStreamIndex + 1;
const size_t kSymbolRecordStreamIndex = kSectionHeaderStreamIndex + 1;
const size_t kPublicStreamIndex = kSymbolRecordStreamIndex + 1;

}  // namespace

bool BuildSimplePdb(const pe::PEFile& pe_file,
                    const SymbolVector& symbols,
                    PdbFile* pdb_file) {
  DCHECK_NE(static_cast<PdbFile*>(NULL), pdb_file);

  // Build the old directory stream.
  // The stream can be empty without invalidating the PDB.
  pdb_file->SetStream(kPdbOldDirectoryStream, NULL);

  // Build the header stream.
  pe::PdbInfo pdb_info;
  if (!pdb_info.Init(pe_file))
    return false;

  scoped_refptr<PdbStream> header_stream(new PdbByteStream);
  if (!WriteHeaderStream(pdb_info,
                         kNamesStreamIndex,
                         header_stream->GetWritablePdbStream())) {
    return false;
  }
  pdb_file->SetStream(kPdbHeaderInfoStream, header_stream);

  // Build the Type Info stream.
  scoped_refptr<PdbStream> type_info_stream(new PdbByteStream);
  if (!WriteEmptyTypeInfoStream(type_info_stream->GetWritablePdbStream()))
    return false;
  pdb_file->SetStream(kTpiStream, type_info_stream);

  // Build the Debug Info stream.
  scoped_refptr<PdbStream> debug_info_stream(new PdbByteStream);
  if (!WriteDebugInfoStream(pdb_info.pdb_age(),
                            kSymbolRecordStreamIndex,
                            kPublicStreamIndex,
                            kSectionHeaderStreamIndex,
                            debug_info_stream->GetWritablePdbStream())) {
    return false;
  }
  pdb_file->SetStream(kDbiStream, debug_info_stream);

  // Build an empty Name Table stream.
  scoped_refptr<PdbStream> names_stream(new PdbByteStream);
  WriteStringTable(StringTable(), names_stream->GetWritablePdbStream());
  pdb_file->SetStream(kNamesStreamIndex, names_stream.get());

  // Build the Section Header stream.
  scoped_refptr<PdbStream> section_header_stream(new PdbByteStream);
  if (!WriteSectionHeaderStream(
          pe_file, section_header_stream->GetWritablePdbStream())) {
    return false;
  }
  pdb_file->SetStream(kSectionHeaderStreamIndex, section_header_stream);

  // Build the Symbol Record stream.
  scoped_refptr<PdbStream> symbol_record_stream(new PdbByteStream);
  SymbolOffsets symbol_offsets;
  if (!WriteSymbolRecords(symbols,
                          &symbol_offsets,
                          symbol_record_stream->GetWritablePdbStream())) {
    return false;
  }
  pdb_file->SetStream(kSymbolRecordStreamIndex, symbol_record_stream);

  // Build the Public stream.
  scoped_refptr<PdbStream> public_stream(new PdbByteStream);
  if (!WritePublicStream(symbols,
                         symbol_offsets,
                         public_stream->GetWritablePdbStream())) {
    return false;
  }
  pdb_file->SetStream(kPublicStreamIndex, public_stream);

  return true;
}

}  // namespace pdb
