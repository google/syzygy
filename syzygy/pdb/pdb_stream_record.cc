// Copyright 2015 Google Inc. All Rights Reserved.
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

#include "syzygy/pdb/pdb_stream_record.h"

#include "base/strings/utf_string_conversions.h"
#include "syzygy/pdb/pdb_stream.h"
#include "syzygy/pdb/pdb_util.h"
#include "syzygy/pe/cvinfo_ext.h"

namespace pdb {

bool ReadWideString(PdbStream* stream, base::string16* string_field) {
  DCHECK(stream);
  DCHECK(string_field);

  std::string narrow_string;
  if (!ReadString(stream, &narrow_string))
    return false;
  *string_field = base::UTF8ToWide(narrow_string);
  return true;
}

bool ReadUnsignedNumeric(PdbStream* stream, uint64_t* data_field) {
  DCHECK(stream);
  DCHECK(data_field);

  uint16_t value_type = 0;
  bool success = stream->Read(&value_type, 1);

  // If the type is unsigned and less than 64 bits long set the value.
  if (value_type < Microsoft_Cci_Pdb::LF_NUMERIC) {
    *data_field = value_type;
  } else if (value_type == Microsoft_Cci_Pdb::LF_USHORT) {
    uint16_t value = 0;
    success &= stream->Read(&value, 1);
    *data_field = value;
  } else if (value_type == Microsoft_Cci_Pdb::LF_ULONG) {
    uint32_t value = 0;
    success &= stream->Read(&value, 1);
    *data_field = value;
  } else if (value_type == Microsoft_Cci_Pdb::LF_UQUADWORD) {
    uint64_t value = 0;
    success &= stream->Read(&value, 1);
    *data_field = value;
  } else {
    success = false;
  }

  return success;
}

}  // namespace pdb
