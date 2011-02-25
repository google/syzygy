// Copyright 2011 Google Inc.
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
#ifndef SYZYGY_PDB_PDB_DATA_H_
#define SYZYGY_PDB_PDB_DATA_H_

#include "base/basictypes.h"

namespace pdb {

// Pdb Info Stream Header, this is at the start of stream #1.
struct PdbInfoHeader70 {
  // Equal to kPdbCurrentVersion for PDBs seen from VS 9.0.
  uint32 version;
  // This looks to be the time of the PDB file creation.
  uint32 timetamp;
  // Updated every time the PDB file is written.
  uint32 pdb_age;
  // This must match the GUID stored off the image's debug directory.
  GUID signature;
};

// Dbi Info Stream Header, this is at the start of stream #3.
// See http://code.google.com/p/pdbparser/wiki/DBI_Format
struct DbiHeader {
  int32 signature;
  uint32 version;
  uint32 age;
  int16 global_symbol_info_stream;
  uint16 pdb_dll_version;
  int16 public_symbol_info_stream;
  uint16 pdb_dll_build_major;
  int16 symbol_record_stream;
  uint16 pdb_dll_build_minor;
  uint32 gp_modi_size;
  uint32 section_contribution_size;
  uint32 section_map_size;
  uint32 file_info_size;
  uint32 ts_map_size;
  uint32 mfc_index;
  uint32 dbg_header_size;
  uint32 ec_info_size;
  uint16 flags;
  uint16 machine;
  uint32 reserved;
};

// Dbi Debug Header
// See http://ccimetadata.codeplex.com/SourceControl/changeset/view/52123#96529
// From introspection, it looks like these are stream numbers or -1 if not
// defined.
struct DbiDbgHeader {
  int16 fpo;
  int16 exception;
  int16 fixup;
  int16 omap_to_src;
  int16 omap_from_src;
  int16 section_header;
  int16 token_rid_map;
  int16 x_data;
  int16 p_data;
  int16 new_fpo;
  int16 section_header_origin;
};

// Multi-Stream Format (MSF) Header
// See http://code.google.com/p/pdbparser/wiki/MSF_Format
struct PdbHeader {
  uint8 magic_string[32];
  uint32 page_size;
  uint32 free_page_map;
  uint32 num_pages;
  uint32 directory_size;
  uint32 reserved;
  uint32 root_pages[73];
};

}  // namespace

#endif  // SYZYGY_PDB_PDB_DATA_H_
