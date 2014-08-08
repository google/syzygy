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

#include "syzygy/experimental/pdb_dumper/pdb_type_info_stream_dumper.h"

#include "base/strings/stringprintf.h"
#include "syzygy/common/align.h"
#include "syzygy/experimental/pdb_dumper/pdb_dump_util.h"
#include "syzygy/experimental/pdb_dumper/pdb_leaf.h"
#include "syzygy/pdb/pdb_stream.h"
#include "syzygy/pdb/pdb_util.h"
#include "syzygy/pe/cvinfo_ext.h"

namespace pdb {

namespace cci = Microsoft_Cci_Pdb;

void DumpTypeInfoStream(FILE* out,
                        PdbStream* stream,
                        const TypeInfoHeader& type_info_header,
                        const TypeInfoRecordMap& type_info_record_map) {
  DCHECK(stream != NULL);

  DumpIndentedText(out, 0, "Type Info Header:\n");
  DumpIndentedText(out, 1, "version: 0x%08X\n", type_info_header.version);
  DumpIndentedText(out, 1, "len: 0x%08X\n", type_info_header.len);
  DumpIndentedText(out, 1, "type_min: 0x%08X\n", type_info_header.type_min);
  DumpIndentedText(out, 1, "type_max: 0x%08X\n", type_info_header.type_max);
  DumpIndentedText(out, 1, "type_info_data_size: 0x%08X\n",
                   type_info_header.type_info_data_size);

  const TypeInfoHashHeader& type_info_hash = type_info_header.type_info_hash;

  DumpIndentedText(out, 0, "Type Info Header Hash:\n");
  DumpIndentedText(out, 1, "stream_number: 0x%04X\n",
                   type_info_hash.stream_number);
  DumpIndentedText(out, 1, "padding: 0x%04X\n", type_info_hash.padding);
  DumpIndentedText(out, 1, "hash_key: 0x%08X\n", type_info_hash.hash_key);
  DumpIndentedText(out, 1, "cb_hash_buckets: 0x%08X\n",
                   type_info_hash.cb_hash_buckets);

  DumpIndentedText(out, 1, "offset_cb_hash_vals: 0x%08X, 0x%08x\n",
            type_info_hash.offset_cb_hash_vals.offset,
            type_info_hash.offset_cb_hash_vals.cb);
  DumpIndentedText(out, 1, "offset_cb_type_info_offset: 0x%08X, 0x%08x\n",
            type_info_hash.offset_cb_type_info_offset.offset,
            type_info_hash.offset_cb_type_info_offset.cb);
  DumpIndentedText(out, 1, "offset_cb_hash_adj: 0x%08X, 0x%08x\n",
            type_info_hash.offset_cb_hash_adj.offset,
            type_info_hash.offset_cb_hash_adj.cb);

  DumpIndentedText(out, 0, "%d type info records in the stream:\n",
            type_info_record_map.size());
  TypeInfoRecordMap::const_iterator type_info_iter =
      type_info_record_map.begin();
  uint8 indent_level = 1;
  // Dump each symbol contained in the vector.
  for (; type_info_iter != type_info_record_map.end(); ++type_info_iter) {
    if (!stream->Seek(type_info_iter->second.start_position)) {
      LOG(ERROR) << "Unable to seek to type info record at position "
                 << base::StringPrintf("0x%08X.",
                                       type_info_iter->second.start_position);
      return;
    }
    // The location in the map is the start of the leaf, which points
    // past the size/type pair.
    DumpIndentedText(out, indent_level, "Type info 0x%04X (at 0x%04X):\n",
        type_info_iter->first,
        type_info_iter->second.start_position - sizeof(cci::SYMTYPE));
    bool success = DumpLeaf(type_info_record_map,
                            type_info_iter->second.type,
                            out,
                            stream,
                            type_info_iter->second.len,
                            indent_level + 1);

    if (!success) {
      // In case of failure we just dump the hex data of this type info.
      if (!stream->Seek(type_info_iter->second.start_position)) {
        LOG(ERROR) << "Unable to seek to type info record at position "
                   << base::StringPrintf("0x%08X.",
                                         type_info_iter->second.start_position);
        return;
      }
      DumpUnknownLeaf(type_info_record_map,
                      out,
                      stream,
                      type_info_iter->second.len,
                      indent_level + 1);
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
