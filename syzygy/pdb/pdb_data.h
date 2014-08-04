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

#ifndef SYZYGY_PDB_PDB_DATA_H_
#define SYZYGY_PDB_PDB_DATA_H_

#include <windows.h>

#include <map>
#include <string>
#include <vector>

#include "base/basictypes.h"
#include "syzygy/common/assertions.h"
#include "syzygy/pdb/pdb_constants.h"

namespace pdb {

// Pdb Info Stream Header, this is at the start of stream #1.
struct PdbInfoHeader70 {
  // Equal to kPdbCurrentVersion for PDBs seen from VS 9.0.
  uint32 version;
  // This looks to be the time of the PDB file creation.
  uint32 timestamp;
  // Updated every time the PDB file is written.
  uint32 pdb_age;
  // This must match the GUID stored off the image's debug directory.
  GUID signature;
};
COMPILE_ASSERT_IS_POD_OF_SIZE(PdbInfoHeader70, 28);

// A structure that we find in the type info hash header, this is not totally
// deciphered yet.
struct OffsetCb {
  uint32 offset;
  uint32 cb;
};
COMPILE_ASSERT_IS_POD_OF_SIZE(OffsetCb, 8);

// Type Info Stream Hash, this is contained in the type info header. This part
// hasn't been deciphered yet (the field names are known but we still need to
// find out what their content mean).
struct TypeInfoHashHeader {
  uint16 stream_number;
  uint16 padding;
  uint32 hash_key;
  uint32 cb_hash_buckets;
  OffsetCb offset_cb_hash_vals;
  OffsetCb offset_cb_type_info_offset;
  OffsetCb offset_cb_hash_adj;
};
COMPILE_ASSERT_IS_POD_OF_SIZE(TypeInfoHashHeader, 36);

// Type Info Stream Header, this is at the beginning of stream #2.
// See http://moyix.blogspot.ca/2007_10_01_archive.html
struct TypeInfoHeader {
  uint32 version;
  uint32 len;
  uint32 type_min;
  uint32 type_max;
  uint32 type_info_data_size;
  TypeInfoHashHeader type_info_hash;
};
// We coerce a stream of bytes to this structure, so we require it to be
// exactly 56 bytes in size.
COMPILE_ASSERT_IS_POD_OF_SIZE(TypeInfoHeader, 56);

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
// We coerce a stream of bytes to this structure, so we require it to be
// exactly 64 bytes in size.
COMPILE_ASSERT_IS_POD_OF_SIZE(DbiHeader, 64);

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
// We coerce a stream of bytes to this structure, so we require it to be
// exactly 22 bytes in size.
COMPILE_ASSERT_IS_POD_OF_SIZE(DbiDbgHeader, 22);

// Dbi Section Contrib
// Represent an element for the section contrib substream of the Dbi stream.
struct DbiSectionContrib {
  int16 section;
  int16 pad1;
  int32 offset;
  int32 size;
  uint32 flags;
  int16 module;
  int16 pad2;
  uint32 data_crc;
  uint32 reloc_crc;
};
// We coerce a stream of bytes to this structure, so we require it to be
// exactly 28 bytes in size.
COMPILE_ASSERT_IS_POD_OF_SIZE(DbiSectionContrib, 28);

// Dbi Module Info
// Represent an element for the module info substream of the Dbi stream. This
// struct doesn't contain the full module and object name.
struct DbiModuleInfoBase {
  uint32 opened;
  DbiSectionContrib section;
  uint16 flags;
  int16 stream;
  uint32 symbol_bytes;
  uint32 old_lines_bytes;
  uint32 lines_bytes;
  int16 num_files;
  uint16 padding;
  uint32 offsets;
  uint32 num_source;
  uint32 num_compiler;
  // There are two trailing null-terminated 8-bit strings, the first being the
  // module_name and the second being the object_name. Then this structure is
  // padded with zeros to have a length that is a multiple of 4.
};
// We coerce a stream of bytes to this structure, so we require it to be
// exactly 64 bytes in size.
COMPILE_ASSERT_IS_POD_OF_SIZE(DbiModuleInfoBase, 64);

// Dbi Section Map
// Represent an element for the section map substream of the Dbi stream.
struct DbiSectionMapItem {
  uint8 flags;
  uint8 section_type;
  // This field hasn't been deciphered but it is always 0x00000000 or 0xFFFFFFFF
  // and modifying it doesn't seem to invalidate the PDB.
  uint16 unknown_data_1[2];
  uint16 section_number;
  // Same thing as for unknown_data_1.
  uint16 unknown_data_2[2];
  // Value added to the address offset when calculating the RVA.
  uint32 rva_offset;
  uint32 section_length;
};
// We coerce a stream of bytes to this structure, so we require it to be
// exactly 20 bytes in size.
COMPILE_ASSERT_IS_POD_OF_SIZE(DbiSectionMapItem, 20);

// Header of the string table found in the name stream and in the EC info header
// of the debug info stream.
struct StringTableHeader {
  // The signature, which is |kPdbStringTableSignature|.
  uint32 signature;

  // The version, which is |kPdbStringTableVersion|.
  uint32 version;

  // The size of the concatenated null-terminated strings that follow,
  // in bytes.
  uint32 size;
};
COMPILE_ASSERT_IS_POD_OF_SIZE(StringTableHeader, 12);

// Header of a symbol record from the symbol record stream.
struct SymbolRecordHeader {
  // Length of the symbol record in bytes, without this field. The length
  // including this field is always a multiple of 4.
  uint16 length;

  // Type of the symbol record. If must be a value from Microsoft_Cci_Pdb::SYM.
  uint16 type;
};
COMPILE_ASSERT_IS_POD_OF_SIZE(SymbolRecordHeader, 4);

// Multi-Stream Format (MSF) Header
// See http://code.google.com/p/pdbparser/wiki/MSF_Format
struct PdbHeader {
  uint8 magic_string[kPdbHeaderMagicStringSize];
  uint32 page_size;
  uint32 free_page_map;
  uint32 num_pages;
  uint32 directory_size;
  uint32 reserved;
  uint32 root_pages[kPdbMaxDirPages];
};
COMPILE_ASSERT_IS_POD_OF_SIZE(PdbHeader, 344);

// This is for parsing the FIXUP stream in PDB files generated with the
// '/PROFILE' flag. The form of this struct was inferred from looking at
// binary dumps of FIXUP streams and correlating them with the disassembly
// of the image they refer to. These efforts are documented here:
// http://go/syzygy-fixups
struct PdbFixup {
  enum Type {
    TYPE_ABSOLUTE = 0x6,
    TYPE_RELATIVE = 0x7,
    TYPE_OFFSET_32BIT = 0xB,
    TYPE_OFFSET_8BIT = 0xD,
    TYPE_PC_RELATIVE = 0x14,
  };

  enum Flags {
    FLAG_IS_DATA = 0x4000,
    FLAG_REFERS_TO_CODE = 0x8000,
    FLAG_UNKNOWN = 0x3fff,
  };

  // The fixup header.
  union {
    uint32 header;
    struct {
      Type type:16;
      unsigned int flags:16;
    };
  };
  // The location of the reference in the image, stored as an RVA. The reference
  // will always take 4-bytes in the image.
  uint32 rva_location;
  // The base to which this reference is tied, stored as an RVA.
  uint32 rva_base;

  // This validates that the fixup is of a known type. Any FIXUP that does not
  // conform to a type that we have already witnessed in sample data will cause
  // this to return false.
  bool ValidHeader() const;

  // Refers to code as opposed to data.
  bool refers_to_code() const { return (flags & FLAG_REFERS_TO_CODE) != 0; }

  // Is stored in data as opposed to being part of an instruction. This is
  // not always reported properly, as immediate operands to 'jmp'
  // instructions in thunks (__imp__function_name) set this bit.
  bool is_data() const { return (flags & FLAG_IS_DATA) != 0; }

  // Returns true if the fixup is an offset from some address.
  bool is_offset() const;

  // This function returns the size of the reference as encoded at the
  // address 'rva_location'.
  size_t size() const;
};
// We coerce a stream of bytes to this structure, so we require it to be
// exactly 12 bytes in size.
COMPILE_ASSERT_IS_POD_OF_SIZE(PdbFixup, 12);

}  // namespace pdb

#endif  // SYZYGY_PDB_PDB_DATA_H_
