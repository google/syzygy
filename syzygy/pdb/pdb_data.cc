// Copyright 2011 Google Inc. All Rights Reserved.
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

#include "syzygy/pdb/pdb_data.h"

#include "base/logging.h"

namespace pdb {

// Here is a translation from our types to
bool PdbFixup::ValidHeader() const {
  switch (type) {
    case TYPE_ABSOLUTE:
    case TYPE_RELATIVE:
    case TYPE_PC_RELATIVE: {
      // Ensure that no unknown flags are set.
      return (flags & FLAG_UNKNOWN) == 0;
    }

    case TYPE_OFFSET_32BIT:
    case TYPE_OFFSET_8BIT: {
      return (flags & ~FLAG_OFFSET_32BIT_VS2017) == 0;
    }

    default: {
      return false;
    }
  }
}

size_t PdbFixup::size() const {
  switch (type) {
    case TYPE_ABSOLUTE: return 4;
    case TYPE_RELATIVE: return 4;
    case TYPE_OFFSET_32BIT: return 4;
    case TYPE_OFFSET_8BIT: return 1;
    case TYPE_PC_RELATIVE: return 4;

    default: {
      NOTREACHED() << "Invalid PdbFixup::Type: " << type << ".";
    }
  }

  return 0;
}

bool PdbFixup::is_offset() const {
  return type == TYPE_OFFSET_32BIT ||
      type == TYPE_OFFSET_8BIT;
}

}  // namespace pdb
