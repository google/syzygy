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

#ifndef SYZYGY_REFINERY_TYPES_PDB_CRAWLER_H_
#define SYZYGY_REFINERY_TYPES_PDB_CRAWLER_H_

#include <windows.h>  // NOLINT
#include <dbghelp.h>
#include <memory>
#include <vector>

#include "base/containers/hash_tables.h"
#include "base/files/file_path.h"
#include "syzygy/common/binary_stream.h"
#include "syzygy/pdb/pdb_dbi_stream.h"
#include "syzygy/pdb/pdb_stream.h"
#include "syzygy/refinery/core/address.h"

namespace refinery {
// Forward declaration.
class TypeRepository;

// A worker class to scrape types from PDB symbols using type info enumerator.
// TODO(manzagop): ensure duplicate types are properly dealt with. The current
// implementation generates equivalent types due to:
// - basic types that are mapped to the same type (eg T_LONG and T_INT4)
// - UDTs that are identical up to extra LF_NESTTYPE (which do not make it to
//   our type representation)
// - pointers: Foo* and Foo*const will lead to the creation of 2 Foo* types.
class PdbCrawler {
 public:
  PdbCrawler();
  ~PdbCrawler();

  // Initializes this crawler for the file at @p path.
  // @param path the image file whose symbols to crawl for types.
  bool InitializeForFile(const base::FilePath& path);

  // Retrieves all @p types associated with the file this instance
  // is initialized to.
  // @param types on success contains zero or more types.
  // @returns true on success, false on failure.
  bool GetTypes(TypeRepository* types);

  // Retrieves the relative virtual addresses of all virtual function tables.
  // @param vftable_rvas on success contains zero or more relative addresses.
  // @returns true on success, false on failure.
  bool GetVFTableRVAs(base::hash_set<RelativeAddress>* vftable_rvas);

 private:
  bool GetVFTableRVAForSymbol(base::hash_set<RelativeAddress>* vftable_rvas,
                              uint16_t symbol_length,
                              uint16_t symbol_type,
                              common::BinaryStreamReader* symbol_reader);

  // Pointers to the PDB type and symbol streams.
  scoped_refptr<pdb::PdbStream> tpi_stream_;
  scoped_refptr<pdb::PdbStream> sym_stream_;

  // The PE section headers extracted from the pdb.
  // Note: we use these as it seems the DbiStream's section map does not contain
  // information about section offsets (rva_offset is 0).
  std::vector<IMAGE_SECTION_HEADER> section_headers_;

  // OMAP data to map from original space to transformed space. Empty if there
  // is no OMAP data.
  std::vector<OMAP> omap_from_;
};

}  // namespace refinery

#endif  // SYZYGY_REFINERY_TYPES_PDB_CRAWLER_H_
