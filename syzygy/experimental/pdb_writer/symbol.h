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

#ifndef SYZYGY_EXPERIMENTAL_PDB_WRITER_SYMBOL_H_
#define SYZYGY_EXPERIMENTAL_PDB_WRITER_SYMBOL_H_

#include <windows.h>

#include "base/basictypes.h"
#include "base/compiler_specific.h"
#include "third_party/cci/Files/CvInfo.h"

namespace pdb {

// Forward declaration.
class WritablePdbStream;

// Interface for a symbol that can be written to the PDB symbol record stream.
class Symbol {
 public:
  virtual ~Symbol() { }

  // @returns the symbol type.
  virtual Microsoft_Cci_Pdb::SYM GetType() const = 0;

  // Writes the symbol to |stream| at the current position.
  // @param stream symbol record stream in which to write the symbol.
  // @returns true in case of success, false otherwise.
  virtual bool Write(WritablePdbStream* stream) const = 0;
};

// Implements the functionnality of writing the symbol header to a stream.
// Derived class must override WritePayload() to write the payload that follows
// the header. This is a partial implementation which leaves Symbol::GetType()
// unimplemented.
class SymbolBaseImpl : public Symbol {
 public:
  // @name Symbol functions.
  // @{
  virtual bool Write(WritablePdbStream* stream) const OVERRIDE;
  // @}

 private:
  // Writes the payload specific to a symbol type. It is expected that the
  // stream position is after the written symbol when the function returns.
  // @param stream symbol record stream in which to write the symbol.
  // @returns true in case of success, false otherwise.
  virtual bool WritePayload(WritablePdbStream* stream) const = 0;
};

// Implements a symbol with a type that is specified at construction time.
// This is a partial implementation which leaves SymbolBaseImpl::WritePayload()
// unimplemented.
class TypedSymbolImpl : public SymbolBaseImpl {
 public:
  explicit TypedSymbolImpl(Microsoft_Cci_Pdb::SYM type);

  // @name Symbol functions.
  // @{
  virtual Microsoft_Cci_Pdb::SYM GetType() const OVERRIDE;
  // @}

 private:
  // The symbol type.
   Microsoft_Cci_Pdb::SYM type_;
};

}  // namespace pdb

#endif  // SYZYGY_EXPERIMENTAL_PDB_WRITER_SYMBOL_H_
