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

#include "syzygy/experimental/pdb_writer/pdb_symbol_record_writer.h"

#include "base/logging.h"
#include "syzygy/pdb/pdb_stream.h"

namespace pdb {

bool WriteSymbolRecords(const SymbolVector& symbols,
                        SymbolOffsets* symbol_offsets,
                        WritablePdbStream* stream) {
  DCHECK_NE(static_cast<SymbolOffsets*>(NULL), symbol_offsets);
  DCHECK(symbol_offsets->empty());
  DCHECK_NE(static_cast<WritablePdbStream*>(NULL), stream);

  for (SymbolVector::const_iterator it = symbols.begin();
       it != symbols.end();
       ++it) {
    symbol_offsets->push_back(stream->pos());
    if (!(*it)->Write(stream))
      return false;
  }

  return true;
}

}  // namespace pdb
