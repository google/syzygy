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

#include "syzygy/experimental/pdb_writer/pdb_header_stream_writer.h"

#include "syzygy/pdb/pdb_data.h"
#include "syzygy/pdb/pdb_stream.h"
#include "syzygy/pdb/pdb_util.h"

namespace pdb {

bool WriteHeaderStream(const pe::PdbInfo& pdb_info,
                       size_t names_stream_index,
                       WritablePdbStream* stream) {
  PdbInfoHeader70 info_header = {};
  info_header.version = kPdbCurrentVersion;
  info_header.timestamp = static_cast<uint32>(time(NULL));
  info_header.pdb_age = pdb_info.pdb_age();
  info_header.signature = pdb_info.signature();

  NameStreamMap name_stream_map;
  name_stream_map["/names"] = names_stream_index;

  return WriteHeaderInfoStream(info_header, name_stream_map, stream);
}

}  // namespace pdb
