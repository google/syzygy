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

#include "base/containers/hash_tables.h"
#include "base/files/file_path.h"
#include "syzygy/pdb/pdb_stream.h"

namespace refinery {
// Forward declaration.
class TypeRepository;

// A worker class to scrape types from PDB symbols using type info enumerator.
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

 private:
  // Pointer to the PDB type info stream.
  scoped_refptr<pdb::PdbStream> stream_;
};

}  // namespace refinery

#endif  // SYZYGY_REFINERY_TYPES_PDB_CRAWLER_H_
