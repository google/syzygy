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

#include "syzygy/pdb/pdb_type_info_stream.h"

#include "base/strings/stringprintf.h"
#include "syzygy/common/align.h"
#include "syzygy/pdb/pdb_stream.h"
#include "syzygy/pdb/pdb_type_info_stream_enum.h"
#include "syzygy/pdb/pdb_util.h"

namespace pdb {

bool ReadTypeInfoStream(PdbStream* stream,
                        TypeInfoHeader* type_info_header,
                        TypeInfoRecordMap* type_info_record_map) {
  DCHECK(stream != NULL);
  DCHECK(type_info_header != NULL);
  DCHECK(type_info_record_map != NULL);

  TypeInfoEnumerator enumerator(stream);

  if (!enumerator.ReadTypeInfoHeader(type_info_header)) {
    return false;
  }

  // Process each type record present in the stream. For now we only save their
  // starting positions, their lengths and their types to be able to dump them.
  while (!enumerator.EndOfStream()) {
    if (!enumerator.NextTypeInfoRecord()) {
      return false;
    }
    TypeInfoRecord type_record;
    type_record.type = enumerator.type();
    type_record.start_position = enumerator.start_position();
    type_record.len = enumerator.len();

    type_info_record_map->insert(
        std::make_pair(enumerator.type_id(), type_record));
  }

  return true;
}

}  // namespace pdb
