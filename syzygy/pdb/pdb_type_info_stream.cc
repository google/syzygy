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

#include "syzygy/pdb/pdb_type_info_stream.h"

#include "base/stringprintf.h"
#include "syzygy/common/align.h"
#include "syzygy/pdb/cvinfo_ext.h"
#include "syzygy/pdb/pdb_dump_util.h"
#include "syzygy/pdb/pdb_stream.h"
#include "syzygy/pdb/pdb_util.h"

namespace pdb {

namespace cci = Microsoft_Cci_Pdb;

namespace {

// Return the string value associated with a type info leaf.
const char* LeafName(uint16 leaf_type) {
  switch (leaf_type) {
// Just return the name of the enum.
#define LEAF_TYPE_NAME(record_type, unused) \
    case cci::record_type: { \
      return #record_type; \
    }
    LEAF_CASE_TABLE(LEAF_TYPE_NAME);
#undef LEAF_TYPE_NAME
    default :
      return NULL;
  }
}

// Return the string value associated with a special type.
const char* SpecialTypeName(uint16 special_type) {
  switch (special_type) {
// Just return the name of the enum.
#define SPECIAL_TYPE_NAME(record_type) \
    case cci::record_type: { \
      return #record_type; \
    }
    SPECIAL_TYPE_CASE_TABLE(SPECIAL_TYPE_NAME);
#undef SPECIAL_TYPE_NAME
    default :
      return NULL;
  }
}

// Dump the name associated with a index type field in a leaf.
bool DumpTypeIndexName(uint16 type_value,
                       const TypeInfoRecordMap& type_map,
                       FILE* out) {
  const char* special_type_name = SpecialTypeName(type_value);
  if (special_type_name != NULL) {
    ::fprintf(out, "%s.\n", special_type_name);
  } else {
    // If the special type name is null it means that we refer to another type
    // info record.
    if (type_value >= cci::CV_PRIMITIVE_TYPE::CV_FIRST_NONPRIM &&
        type_map.find(type_value) != type_map.end()) {
      ::fprintf(out, "Reference to another type info.\n");
    } else {
      LOG(ERROR) << "Reference to an unknown type index: "
                 << StringPrintf("0x%04X.", type_value);
      return false;
    }
  }
  return true;
}

bool DumpLeafVTShape(const TypeInfoRecordMap& type_map,
                     FILE* out,
                     PdbStream* stream,
                     uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafCobol1(const TypeInfoRecordMap& type_map,
                    FILE* out,
                    PdbStream* stream,
                    uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafLabel(const TypeInfoRecordMap& type_map,
                   FILE* out,
                   PdbStream* stream,
                   uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafEndPreComp(const TypeInfoRecordMap& type_map,
                        FILE* out,
                        PdbStream* stream,
                        uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafList(const TypeInfoRecordMap& type_map,
                     FILE* out,
                     PdbStream* stream,
                     uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafRefSym(const TypeInfoRecordMap& type_map,
                     FILE* out,
                     PdbStream* stream,
                     uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafModifier(const TypeInfoRecordMap& type_map,
                     FILE* out,
                     PdbStream* stream,
                     uint16 len) {
  cci::LeafModifier type_info = {};
  uint16 modifier_attributes;
  // We need to read the attribute field separately because if we read it
  // directly (by reading the struct) we'll read it as a 32-bit field (it's an
  // enum) but it's in fact a 16-bits value and the following data is just
  // padding.
  size_t to_read = offsetof(cci::LeafModifier, attr);
  size_t bytes_read = 0;
  if (!stream->ReadBytes(&type_info, to_read, &bytes_read) ||
      !stream->Read(&modifier_attributes, 1) ||
      bytes_read != to_read) {
    LOG(ERROR) << "Unable to read type info record.";
    return false;
  }
  ::fprintf(out, "\t\tModifier type index : 0x%08X, ", type_info.type);
  if (!DumpTypeIndexName(type_info.type, type_map, out))
    return false;
  switch (modifier_attributes) {
    case cci::MOD_const:
      ::fprintf(out, "const\n");
      break;
    case cci::MOD_volatile:
      ::fprintf(out, "volatile\n");
      break;
    case cci::MOD_unaligned:
      ::fprintf(out, "unaligned\n");
      break;
    default:
      ::fprintf(out, "undefined modifier attribute: 0x%04X\n",
                modifier_attributes);
      break;
  }
  return true;
}

bool DumpLeafPointer(const TypeInfoRecordMap& type_map,
                     FILE* out,
                     PdbStream* stream,
                     uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafMFunc(const TypeInfoRecordMap& type_map,
                   FILE* out,
                   PdbStream* stream,
                   uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafCobol0(const TypeInfoRecordMap& type_map,
                    FILE* out,
                    PdbStream* stream,
                    uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafBArray(const TypeInfoRecordMap& type_map,
                    FILE* out,
                    PdbStream* stream,
                    uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafVFTPath(const TypeInfoRecordMap& type_map,
                     FILE* out,
                     PdbStream* stream,
                     uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafOEM(const TypeInfoRecordMap& type_map,
                 FILE* out,
                 PdbStream* stream,
                 uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafOEM2(const TypeInfoRecordMap& type_map,
                  FILE* out,
                  PdbStream* stream,
                  uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafSkip(const TypeInfoRecordMap& type_map,
                  FILE* out,
                  PdbStream* stream,
                  uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafArgList(const TypeInfoRecordMap& type_map,
                     FILE* out,
                     PdbStream* stream,
                     uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafFieldList(const TypeInfoRecordMap& type_map,
                       FILE* out,
                       PdbStream* stream,
                       uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafDerived(const TypeInfoRecordMap& type_map,
                     FILE* out,
                     PdbStream* stream,
                     uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafBitfield(const TypeInfoRecordMap& type_map,
                      FILE* out,
                      PdbStream* stream,
                      uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafMethodList(const TypeInfoRecordMap& type_map,
                        FILE* out,
                        PdbStream* stream,
                        uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafDimCon(const TypeInfoRecordMap& type_map,
                    FILE* out,
                    PdbStream* stream,
                    uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}


bool DumpLeafDimVar(const TypeInfoRecordMap& type_map,
                    FILE* out,
                    PdbStream* stream,
                    uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafBClass(const TypeInfoRecordMap& type_map,
                    FILE* out,
                    PdbStream* stream,
                    uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafVBClass(const TypeInfoRecordMap& type_map,
                     FILE* out,
                     PdbStream* stream,
                     uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafIndex(const TypeInfoRecordMap& type_map,
                   FILE* out,
                   PdbStream* stream,
                   uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafVFuncTab(const TypeInfoRecordMap& type_map,
                      FILE* out,
                      PdbStream* stream,
                      uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafVFuncOff(const TypeInfoRecordMap& type_map,
                      FILE* out,
                      PdbStream* stream,
                      uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafTypeServer(const TypeInfoRecordMap& type_map,
                        FILE* out,
                        PdbStream* stream,
                        uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafEnumerate(const TypeInfoRecordMap& type_map,
                       FILE* out,
                       PdbStream* stream,
                       uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafArray(const TypeInfoRecordMap& type_map,
                   FILE* out,
                   PdbStream* stream,
                   uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafClass(const TypeInfoRecordMap& type_map,
                   FILE* out,
                   PdbStream* stream,
                   uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafUnion(const TypeInfoRecordMap& type_map,
                   FILE* out,
                   PdbStream* stream,
                   uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafEnum(const TypeInfoRecordMap& type_map,
                  FILE* out,
                  PdbStream* stream,
                  uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafDimArray(const TypeInfoRecordMap& type_map,
                      FILE* out,
                      PdbStream* stream,
                      uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafPreComp(const TypeInfoRecordMap& type_map,
                     FILE* out,
                     PdbStream* stream,
                     uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafAlias(const TypeInfoRecordMap& type_map,
                   FILE* out,
                   PdbStream* stream,
                   uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafDefArg(const TypeInfoRecordMap& type_map,
                    FILE* out,
                    PdbStream* stream,
                    uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafFriendFcn(const TypeInfoRecordMap& type_map,
                       FILE* out,
                       PdbStream* stream,
                       uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafMember(const TypeInfoRecordMap& type_map,
                    FILE* out,
                    PdbStream* stream,
                    uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafSTMember(const TypeInfoRecordMap& type_map,
                      FILE* out,
                      PdbStream* stream,
                      uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafMethod(const TypeInfoRecordMap& type_map,
                    FILE* out,
                    PdbStream* stream,
                    uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafNestType(const TypeInfoRecordMap& type_map,
                      FILE* out,
                      PdbStream* stream,
                      uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafOneMethod(const TypeInfoRecordMap& type_map,
                       FILE* out,
                       PdbStream* stream,
                       uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafNestTypeEx(const TypeInfoRecordMap& type_map,
                        FILE* out,
                        PdbStream* stream,
                        uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafMemberModify(const TypeInfoRecordMap& type_map,
                          FILE* out,
                          PdbStream* stream,
                          uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafManaged(const TypeInfoRecordMap& type_map,
                     FILE* out,
                     PdbStream* stream,
                     uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafTypeServer2(const TypeInfoRecordMap& type_map,
                         FILE* out,
                         PdbStream* stream,
                         uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafVarString(const TypeInfoRecordMap& type_map,
                       FILE* out,
                       PdbStream* stream,
                       uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafProc(const TypeInfoRecordMap& type_map,
                  FILE* out,
                  PdbStream* stream,
                  uint16 len) {
  cci::LeafProc type_info = {};
  if (!stream->Read(&type_info, 1)) {
    LOG(ERROR) << "Unable to read type info record.";
    return false;
  }
  ::fprintf(out, "\t\tReturn value type index : 0x%08X\n", type_info.rvtype);
  ::fprintf(out, "\t\tCalling convention: %d\n", type_info.calltype);
  ::fprintf(out, "\t\tNumber of parameters: %d\n", type_info.parmcount);
  ::fprintf(out, "\t\tArgument list type index: 0x%08X\n", type_info.arglist);
  return true;
}

// Hexdump the data of the undeciphered type info.
bool DumpUnknown(const TypeInfoRecordMap& type_map,
                 FILE* out,
                 PdbStream* stream,
                 uint16 len) {
  ::fprintf(out, "\t\tUnsupported type info. Data:\n");
  return DumpUnknownBlock(out, stream, len);
}

}  //  namespace

bool ReadTypeInfoStream(PdbStream* stream,
                        TypeInfoHeader* type_info_header,
                        TypeInfoRecordMap* type_info_record_map) {
  DCHECK(stream != NULL);
  DCHECK(type_info_header != NULL);
  DCHECK(type_info_record_map != NULL);

  // Reads the header of the stream.
  if (!stream->Seek(0) || !stream->Read(type_info_header, 1)) {
    LOG(ERROR) << "Unable to read the type info stream header.";
    return false;
  }

  if (stream->pos() != type_info_header->len) {
    LOG(ERROR) << "Unexpected length for the type info stream header (expected "
               << type_info_header->len << ", read " << stream->pos() << ").";
    return false;
  }

  size_t type_info_data_end =
      type_info_header->len + type_info_header->type_info_data_size;

  if (type_info_data_end != stream->length()) {
    LOG(ERROR) << "The type info stream is not valid.";
    return false;
  }

  // The type ID of each entry is not present in the stream, instead of that we
  // know the first and the last type ID and we know that the type records are
  // ordered in increasing order in the stream.
  uint32 current_type_id = type_info_header->type_min;
  // Process each type record present in the stream. For now we only save their
  // starting positions, their lengths and their types to be able to dump them.
  while (stream->pos() < type_info_data_end) {
    uint16 len = 0;
    uint16 record_type = 0;
    if (!stream->Read(&len, 1)) {
      LOG(ERROR) << "Unable to read a type info record length.";
      return false;
    }
    size_t symbol_start = stream->pos();
    if (!stream->Read(&record_type, 1))  {
      LOG(ERROR) << "Unable to read a type info record type.";
      return false;
    }
    TypeInfoRecord type_record;
    type_record.type = record_type;
    type_record.start_position = stream->pos();
    type_record.len = len - sizeof(record_type);

    type_info_record_map->insert(std::make_pair(current_type_id, type_record));
    if (!stream->Seek(symbol_start + len)) {
      LOG(ERROR) << "Unable to seek to the end of the type info record.";
      return false;
    }
    current_type_id++;
  }

  if (current_type_id != type_info_header->type_max) {
    LOG(ERROR) << "Unexpected number of type info records in the type info "
               << "stream (expected " << type_info_header->type_max
               - type_info_header->type_min << ", read " << current_type_id
               - type_info_header->type_min << ").";
  }

  return true;
}

void DumpTypeInfoStream(FILE* out,
                        PdbStream* stream,
                        const TypeInfoHeader& type_info_header,
                        const TypeInfoRecordMap& type_info_record_map) {
  DCHECK(stream != NULL);

  ::fprintf(out, "%d type info record in the stream:\n",
            type_info_record_map.size());
  TypeInfoRecordMap::const_iterator type_info_iter =
      type_info_record_map.begin();
  // Dump each symbol contained in the vector.
  for (; type_info_iter != type_info_record_map.end(); type_info_iter++) {
    if (!stream->Seek(type_info_iter->second.start_position)) {
      LOG(ERROR) << "Unable to seek to type info record at position "
                 << StringPrintf("0x%08X.",
                                 type_info_iter->second.start_position);
      return;
    }
    const char* leaf_type_text = LeafName(type_info_iter->second.type);
    if (leaf_type_text != NULL) {
      ::fprintf(out, "\tType info 0x%04X, Leaf type: 0x%04X %s\n",
                type_info_iter->first,
                type_info_iter->second.type,
                leaf_type_text);
    } else {
      ::fprintf(out, "\tUnknown leaf type: 0x%04X\n",
                type_info_iter->second.type);
    }
    bool success = false;
    switch (type_info_iter->second.type) {
// Call a function to dump a specific (struct_type) kind of structure.
#define LEAF_TYPE_DUMP(leaf_type, struct_type) \
    case cci::leaf_type: { \
      success = Dump ## struct_type(type_info_record_map, \
                                    out, \
                                    stream, \
                                    type_info_iter->second.len); \
      break; \
    }
      LEAF_CASE_TABLE(LEAF_TYPE_DUMP);
#undef LEAF_TYPE_DUMP
    }

    if (!success) {
      // In case of failure we just dump the hex data of this type info.
      if (!stream->Seek(type_info_iter->second.start_position)) {
        LOG(ERROR) << "Unable to seek to type info record at position "
                   << StringPrintf("0x%08X.",
                                   type_info_iter->second.start_position);
        return;
      }
      DumpUnknown(type_info_record_map,
                  out,
                  stream,
                  type_info_iter->second.len);
    }
    stream->Seek(common::AlignUp(stream->pos(), 4));
    size_t expected_position = type_info_iter->second.start_position
        + type_info_iter->second.len;
    if (stream->pos() != expected_position) {
      LOG(ERROR) << "Type info stream is not valid.";
      return;
    }
  }
}

}  // namespace pdb
