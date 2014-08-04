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

#include "syzygy/experimental/pdb_writer/symbol.h"

#include "base/basictypes.h"
#include "base/logging.h"
#include "syzygy/pdb/pdb_data.h"
#include "syzygy/pdb/pdb_stream.h"

namespace pdb {

bool SymbolBaseImpl::Write(WritablePdbStream* stream) const {
  DCHECK(stream);

  size_t start_pos = stream->pos();

  // Write the header of the symbol record. The |length| field will be updated
  // later.
  SymbolRecordHeader header = {};
  header.type = GetType();
  if (!stream->Write(header))
    return false;

  // Write the payload of the symbol record.
  if (!WritePayload(stream))
    return false;
  DCHECK_EQ(stream->pos(), stream->length());

  // Add padding.
  if (!stream->Align(sizeof(SymbolRecordHeader)))
    return false;
  size_t end_pos = stream->pos();

  // Update the |length| field.
  stream->set_pos(start_pos + offsetof(SymbolRecordHeader, length));
  if (!stream->Write(
      static_cast<uint16>(end_pos - start_pos - sizeof(header.length)))) {
    return false;
  }

  // Seek to the end of the written symbol.
  stream->set_pos(end_pos);

  return true;
}

TypedSymbolImpl::TypedSymbolImpl(Microsoft_Cci_Pdb::SYM type) : type_(type) { }

Microsoft_Cci_Pdb::SYM TypedSymbolImpl::GetType() const {
  return type_;
}

}  // namespace pdb
