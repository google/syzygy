// Copyright 2011 Google Inc.
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
// Given a Reorderer generated Order, creates an MS LINKER compatible COMDAT
// ORDER file for LINK time reordering.
#ifndef SYZYGY_REORDER_COMDAT_ORDER_H_
#define SYZYGY_REORDER_COMDAT_ORDER_H_

#include "base/file_path.h"
#include "base/win/scoped_comptr.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/dia_browser.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/reorder/reorderer.h"

namespace reorder {

// Utility class for creating MS LINKER COMDAT ORDER files from Order objects.
// Uses COM, so CoInitialize should be called prior to using an instance of this
// object.
class ComdatOrder {
 public:

  // Creates a ComdatOrder object using the provided DLL/EXE. The PDB file
  // will be auto-located from the module.
  explicit ComdatOrder(const FilePath& input_dll);

  // Loads the symbols from the input module.
  bool LoadSymbols();

  // Given an Order, outputs an equivalent COMDAT ORDER file. LoadSymbols
  // must have been called previously.
  bool OutputOrder(const FilePath& path,
                   const Reorderer::Order& order);

 protected:
  // Used by unit tests.
  ComdatOrder();
  pe::PEFile& image_file() { return image_file_; }

  // Used as a callback to grep PublicSymbols from the associated PDB file.
  void OnPublicSymbol(const pe::DiaBrowser& dia_browser,
                      const pe::DiaBrowser::SymTagVector& sym_tags,
                      const pe::DiaBrowser::SymbolPtrVector& symbols,
                      pe::DiaBrowser::BrowserDirective* directive);

 private:
  // Initializes DIA.
  bool InitDia();

  // Stores the path of the DLL for which we are generating an order.
  FilePath input_dll_;
  // Stores the headers of the image DLL. These are populated during
  // LoadSymbols.
  pe::PEFile image_file_;
  // Stores DIA interface pointers.
  base::win::ScopedComPtr<IDiaDataSource> dia_source_;
  base::win::ScopedComPtr<IDiaSession> dia_session_;
  base::win::ScopedComPtr<IDiaSymbol> dia_global_;
  // Stores all COMDAT names and keyed by their address.
  typedef std::pair<std::string, bool> StringBool;
  typedef std::map<RelativeAddress, StringBool> ComdatMap;
  ComdatMap comdats_;

  DISALLOW_COPY_AND_ASSIGN(ComdatOrder);
};

}  // namespace reorder

#endif  // SYZYGY_REORDER_COMDAT_ORDER_H_
