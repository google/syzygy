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
#include "syzygy/common/binary_stream.h"
#include "syzygy/experimental/pdb_dumper/pdb_dump_util.h"
#include "syzygy/experimental/pdb_dumper/pdb_leaf.h"
#include "syzygy/pdb/pdb_stream.h"
#include "syzygy/pdb/pdb_stream_reader.h"
#include "syzygy/pdb/pdb_util.h"
#include "syzygy/pe/cvinfo_ext.h"

namespace pdb {

namespace cci = Microsoft_Cci_Pdb;

void DumpTypeInfoStream(FILE* out, TypeInfoEnumerator& type_info_enum) {
  // Read type info stream header.
  const TypeInfoHeader& type_info_header = type_info_enum.type_info_header();

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

  // TODO(mopler): Remove this type info record map from the implementation.
  TypeInfoRecordMap type_info_record_map;
  uint8_t indent_level = 1;

  // Dump each symbol contained in the vector.
  while (!type_info_enum.EndOfStream()) {
    if (!type_info_enum.NextTypeInfoRecord()) {
      LOG(ERROR) << "Unable to read type info stream.";
      return;
    }

    // Add new record to the map.
    TypeInfoRecord type_record;
    type_record.type = type_info_enum.type();
    type_record.start_position = type_info_enum.start_position();
    type_record.len = type_info_enum.len();

    type_info_record_map.insert(
        std::make_pair(type_info_enum.type_id(), type_record));

    // The location in the map is the start of the leaf, which points
    // past the size/type pair.
    DumpIndentedText(out, indent_level, "Type info 0x%04X (at 0x%04X):\n",
                     type_info_enum.type_id(),
                     type_record.start_position - sizeof(cci::SYMTYPE));

    TypeInfoEnumerator::BinaryTypeRecordReader reader(
        type_info_enum.CreateRecordReader());
    common::BinaryStreamParser parser(&reader);
    bool success = DumpLeaf(type_info_record_map, type_record.type, out,
                            &parser, type_record.len, indent_level + 1);

    if (!success) {
      // In case of failure we just dump the hex data of this type info.
      TypeInfoEnumerator::BinaryTypeRecordReader raw_reader(
          type_info_enum.CreateRecordReader());
      common::BinaryStreamParser raw_parser(&reader);
      DumpUnknownLeaf(type_info_record_map, out, &parser, type_record.len,
                      indent_level + 1);
    }
  }
}

}  // namespace pdb
