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
#include "syzygy/pdb/pdb_leaf.h"
#include "syzygy/pdb/pdb_stream.h"
#include "syzygy/pdb/pdb_util.h"

namespace pdb {

namespace cci = Microsoft_Cci_Pdb;

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
  uint8 level_of_indent = 1;
  // Dump each symbol contained in the vector.
  for (; type_info_iter != type_info_record_map.end(); type_info_iter++) {
    if (!stream->Seek(type_info_iter->second.start_position)) {
      LOG(ERROR) << "Unable to seek to type info record at position "
                 << StringPrintf("0x%08X.",
                                 type_info_iter->second.start_position);
      return;
    }
    DumpTabs(out, level_of_indent);
    ::fprintf(out, "Type info 0x%04X:\n", type_info_iter->first);
    bool success = DumpLeaf(type_info_record_map,
                            type_info_iter->second.type,
                            out,
                            stream,
                            type_info_iter->second.len,
                            level_of_indent + 1);

    if (!success) {
      // In case of failure we just dump the hex data of this type info.
      if (!stream->Seek(type_info_iter->second.start_position)) {
        LOG(ERROR) << "Unable to seek to type info record at position "
                   << StringPrintf("0x%08X.",
                                   type_info_iter->second.start_position);
        return;
      }
      DumpUnknownLeaf(type_info_record_map,
                      out,
                      stream,
                      type_info_iter->second.len,
                      level_of_indent + 1);
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
