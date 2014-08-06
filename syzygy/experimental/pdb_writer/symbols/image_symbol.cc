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

#include "syzygy/experimental/pdb_writer/symbols/image_symbol.h"

#include "base/logging.h"
#include "syzygy/pdb/pdb_stream.h"

namespace pdb {
namespace symbols {

namespace {

namespace cci = Microsoft_Cci_Pdb;

// Size of the DatasSym32 struct without the |name| field.
const size_t kDatasSym32StructSize = offsetof(cci::DatasSym32, name);

}  // namespace

ImageSymbol::ImageSymbol(cci::SYM type,
                         const core::SectionOffsetAddress& address,
                         uint32 content_type,
                         const std::string& name)
    : TypedSymbolImpl(type),
      address_(address),
      content_type_(content_type),
      name_(name) {
  DCHECK(type == cci::S_LDATA32 || type == cci::S_GDATA32 ||
         type == cci::S_PUB32 || type == cci::S_LMANDATA ||
         type == cci::S_GMANDATA);
}

bool ImageSymbol::WritePayload(WritablePdbStream* stream) const {
  DCHECK(stream);

  cci::DatasSym32 payload = {};
  payload.typind = content_type_;
  payload.off = address_.offset();
  payload.seg = address_.section_id();

  if (!stream->Write(kDatasSym32StructSize,
                     reinterpret_cast<const char*>(&payload)) ||
      !stream->WriteString(name_)) {
    return false;
  }

  return true;
}

}  // namespace symbols
}  // namespace pdb
