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

#include "syzygy/experimental/pdb_writer/pdb_type_info_stream_writer.h"

#include "syzygy/pdb/pdb_constants.h"
#include "syzygy/pdb/pdb_data.h"
#include "syzygy/pdb/pdb_stream.h"

namespace pdb {

bool WriteEmptyTypeInfoStream(WritablePdbStream* stream) {
  TypeInfoHeader header;
  header.version = kTpiStreamVersion;
  header.len = sizeof(TypeInfoHeader);
  header.type_min = kTpiStreamFirstUserTypeIndex;
  header.type_max = kTpiStreamFirstUserTypeIndex;
  header.type_info_data_size = 0;
  header.type_info_hash.stream_number = -1;
  header.type_info_hash.padding = -1;
  header.type_info_hash.hash_key = kTpiStreamEmptyHashKey;
  header.type_info_hash.cb_hash_buckets = kTpiStreamEmptyHashBuckets;

  header.type_info_hash.offset_cb_hash_vals.offset = 0;
  header.type_info_hash.offset_cb_hash_vals.cb = -1;

  header.type_info_hash.offset_cb_type_info_offset.offset = 0;
  header.type_info_hash.offset_cb_type_info_offset.cb = -1;

  header.type_info_hash.offset_cb_hash_adj.offset = 0;
  header.type_info_hash.offset_cb_hash_adj.cb = -1;

  return stream->Write(header);
}

}  // namespace pdb
