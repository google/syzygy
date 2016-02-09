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

#ifndef SYZYGY_REFINERY_TYPES_DIA_CRAWLER_H_
#define SYZYGY_REFINERY_TYPES_DIA_CRAWLER_H_

#include <dia2.h>
#include <vector>

#include "base/containers/hash_tables.h"
#include "base/files/file_path.h"
#include "base/strings/string_piece.h"
#include "base/win/scoped_comptr.h"
#include "syzygy/refinery/core/address.h"
#include "syzygy/refinery/types/type.h"

namespace refinery {

// fwd.
class TypeRepository;

// A worker class to scrape types from PDB symbols using DIA.
class DiaCrawler {
 public:
  DiaCrawler();
  ~DiaCrawler();

  // Initializes this crawler for the file at @p path.
  // @param path the image file whose symbols to crawl for types.
  // @returns true on success, false on failure.
  bool InitializeForFile(const base::FilePath& path);

  // Initializes this crawler using @p source and @p session.
  // @param source the dia source to initialize with.
  // @param session the dia session to initialize with.
  // @returns true on success, false on failure.
  bool InitializeForSession(base::win::ScopedComPtr<IDiaDataSource> source,
                            base::win::ScopedComPtr<IDiaSession> session);

  // Retrieves all types associated with the file this instance
  // is initialized to.
  // @param types on success contains zero or more types.
  // @returns true on success, false on failure.
  bool GetTypes(TypeRepository* types);

  // Retrieves the relative virtual addresses of all virtual function tables.
  // @param vftable_rvas on success contains zero or more relative addresses.
  // @returns true on success, false on failure.
  bool GetVFTableRVAs(base::hash_set<RelativeAddress>* vftable_rvas);

 private:
  base::win::ScopedComPtr<IDiaDataSource> source_;
  base::win::ScopedComPtr<IDiaSession> session_;
  base::win::ScopedComPtr<IDiaSymbol> global_;
};

}  // namespace refinery

#endif  // SYZYGY_REFINERY_TYPES_DIA_CRAWLER_H_
