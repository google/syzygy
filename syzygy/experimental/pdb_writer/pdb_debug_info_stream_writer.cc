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

#include "syzygy/experimental/pdb_writer/pdb_debug_info_stream_writer.h"

#include "syzygy/experimental/pdb_writer/pdb_string_table_writer.h"
#include "syzygy/pdb/pdb_constants.h"
#include "syzygy/pdb/pdb_data.h"
#include "syzygy/pdb/pdb_stream.h"

namespace pdb {

namespace {

// The value we've observed for the |flags| field of the Dbi Header.
// The value 1 also works.
// TODO(fdoray): Figure out what this means.
const uint16 kDbiGeneratedFlags = 2;

}  // namespace

bool WriteDebugInfoStream(uint32 pdb_age,
                          size_t symbol_record_stream_index,
                          size_t public_stream_index,
                          size_t section_header_stream_index,
                          WritablePdbStream* stream) {
  // Write the Dbi Header.
  DbiHeader dbi_header = {};
  dbi_header.signature = -1;
  dbi_header.version = kDbiStreamVersion;
  dbi_header.age = pdb_age,
  dbi_header.global_symbol_info_stream = -1;
  dbi_header.pdb_dll_version = 1;
  dbi_header.public_symbol_info_stream = public_stream_index;

  // This field can have any value.
  // TODO(fdoray): Find out whether there is a better way to choose this value.
  dbi_header.pdb_dll_build_major = 1;

  dbi_header.symbol_record_stream = symbol_record_stream_index;

  // This field can have any value.
  // TODO(fdoray): Find out whether there is a better way to choose this value.
  dbi_header.pdb_dll_build_minor = 0;

  dbi_header.gp_modi_size = 0;
  dbi_header.section_contribution_size = sizeof(uint32);
  dbi_header.section_map_size = 2 * sizeof(uint16);
  dbi_header.file_info_size = 2 * sizeof(uint16);
  dbi_header.ts_map_size = 0;
  dbi_header.mfc_index = 0;
  dbi_header.dbg_header_size = sizeof(DbiDbgHeader);
  dbi_header.ec_info_size = 0;  // Will be updated later.
  dbi_header.flags = kDbiGeneratedFlags;
  dbi_header.machine = IMAGE_FILE_MACHINE_I386;
  dbi_header.reserved = 0;

  if (!stream->Write(dbi_header))
    return false;

  // Write an empty Section Contribs header.
  if (!stream->Write(kPdbDbiSectionContribsSignature))
    return false;

  // Write an empty Section Map header.
  // The number of section map structure seems to be written twice.
  uint16 section_map_count = 0;

  if (!stream->Write(section_map_count) || !stream->Write(section_map_count))
    return false;

  // Write an empty File info header.
  uint16 file_info_blocks_count = 0;
  uint16 file_info_offsets_count = 0;

  if (!stream->Write(file_info_blocks_count) ||
      !stream->Write(file_info_offsets_count)) {
    return false;
  }

  // Write the EC info header.
  size_t ec_info_offset = stream->pos();
  if (!WriteStringTable(StringTable(), stream))
    return false;
  uint32 ec_info_size = stream->pos() - ec_info_offset;

  // Write the Dbg Header.
  DbiDbgHeader dbg_header = {};
  dbg_header.fpo = -1;
  dbg_header.exception = -1;
  dbg_header.fixup = -1;
  dbg_header.omap_to_src = -1;
  dbg_header.omap_from_src = -1;
  dbg_header.section_header = section_header_stream_index;
  dbg_header.token_rid_map = -1;
  dbg_header.x_data = -1;
  dbg_header.p_data = -1;
  dbg_header.new_fpo = -1;
  dbg_header.section_header_origin = -1;

  if (!stream->Write(dbg_header))
    return false;

  // Update the size of the EC info header.
  stream->set_pos(offsetof(DbiHeader, ec_info_size));
  if (!stream->Write(ec_info_size))
    return false;

  return true;
}

}  // namespace pdb
