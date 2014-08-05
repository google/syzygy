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
//
// Declares a Symbol that associates a name and a type with a location in an
// image. The type of these symbols in PDB files is one of S_LDATA32, S_GDATA32,
// S_PUB32, S_LMANDATA or S_GMANDATA.

#ifndef SYZYGY_EXPERIMENTAL_PDB_WRITER_SYMBOLS_IMAGE_SYMBOL_H_
#define SYZYGY_EXPERIMENTAL_PDB_WRITER_SYMBOLS_IMAGE_SYMBOL_H_

#include <string>

#include "syzygy/core/section_offset_address.h"
#include "syzygy/experimental/pdb_writer/symbol.h"

namespace pdb {
namespace symbol {

// Represents a symbol that associates a name and a type with a location in an
// image.
class ImageSymbol : public TypedSymbolImpl {
 public:
  // @param type the type of the symbol record. Must be one of S_LDATA32,
  //     S_GDATA32, S_PUB32, S_LMANDATA or S_GMANDATA.
  // @param address the address of the symbol.
  // @param content_type the type of the code or data pointed by the symbol.
  //     This is either a value from TYPE_ENUM or a type index defined in the
  //     PDB type stream.
  // @param name the name of the symbol.
  ImageSymbol(Microsoft_Cci_Pdb::SYM type,
              const core::SectionOffsetAddress& address,
              uint32 content_type,
              const std::string& name);

  // @name Accessors.
  // @{
  const core::SectionOffsetAddress& address() const { return address_; }
  const std::string& name() const { return name_; }
  // @}

 private:
  // @name SymbolBaseImpl functions.
  // @{
  virtual bool WritePayload(WritablePdbStream* stream) const OVERRIDE;
  // @}

  // Address of the symbol.
  core::SectionOffsetAddress address_;

  // Type of the code or data pointed by the symbol. This is either a value from
  // TYPE_ENUM or a type index defined in the PDB type stream.
  uint32 content_type_;

  // Name of the symbol.
  std::string name_;
};

}  // namespace symbol
}  // namespace pdb

#endif  // SYZYGY_EXPERIMENTAL_PDB_WRITER_SYMBOLS_IMAGE_SYMBOL_H_
