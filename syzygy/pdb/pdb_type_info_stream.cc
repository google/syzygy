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

// Return the string value associated with a type info.
const char* TypeInfoName(uint16 type_info_type) {
  switch (type_info_type) {
// Just print the name of the enum.
#define TYPE_INFO_TYPE_NAME(record_type, unused) \
    case cci::record_type: { \
      return #record_type; \
    }
    TYPE_INFO_CASE_TABLE(TYPE_INFO_TYPE_NAME);
#undef TYPE_INFO_TYPE_NAME
    default :
      return NULL;
  }
}

// Hexdump the data of the undeciphered type info.
bool DumpUnknown(FILE* out, PdbStream* stream, uint16 len) {
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
    const char* type_info_type_text = TypeInfoName(type_info_iter->second.type);
    if (type_info_type_text != NULL) {
      ::fprintf(out, "\tType info 0x%04X, Type: 0x%04X %s\n",
                type_info_iter->first,
                type_info_iter->second.type,
                type_info_type_text);
    } else {
      ::fprintf(out, "\tUnknown type info type: 0x%04X\n",
                type_info_iter->second.type);
    }
    bool success = false;
    switch (type_info_iter->second.type) {
// Call a function to dump a specific (struct_type) kind of structure.
#define TYPE_INFO_TYPE_DUMP(type_info_type, struct_type) \
    case cci::type_info_type: { \
      success = Dump ## struct_type(out, stream, type_info_iter->second.len); \
      break; \
    }
      TYPE_INFO_CASE_TABLE(TYPE_INFO_TYPE_DUMP);
#undef TYPE_INFO_TYPE_DUMP
    }

    if (!success) {
      // In case of failure we just dump the hex data of this type info.
      if (!stream->Seek(type_info_iter->second.start_position)) {
        LOG(ERROR) << "Unable to seek to type info record at position "
                   << StringPrintf("0x%08X.",
                                   type_info_iter->second.start_position);
        return;
      }
      DumpUnknown(out, stream, type_info_iter->second.len);
    }
    stream->Seek(common::AlignUp(stream->pos(), 4));
    if (stream->pos() != type_info_iter->second.start_position
        + type_info_iter->second.len) {
      LOG(ERROR) << "Type info stream is not valid.";
      return;
    }
  }
}

}  // namespace pdb
