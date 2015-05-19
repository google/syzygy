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

#include "base/files/file_path.h"
#include "base/strings/string_piece.h"
#include "base/win/scoped_comptr.h"
#include "syzygy/refinery/types/type.h"

namespace refinery {

// A worker class to scrape types from PDB symbols using DIA.
class DiaCrawler {
 public:
  DiaCrawler();
  ~DiaCrawler();

  // Initializes this crawler for the file at @p path.
  // @param path the image file whose symbols to crawl for types.
  bool InitializeForFile(const base::FilePath& path);

  // Retrieves types matching @p regexp.
  // @param regexp the name of the type or retrieve or a regular expression.
  // @param types on success contains one or more types.
  // @returns true on success, false on failure.
  // @note the @p regexp is whatever DIA defines as a regular expression, which
  //     appears to be more similar to a file glob.
  // TODO(siggi): This should eliminate duplicate type instances as it goes.
  bool GetTypes(const base::string16& regexp,
                std::vector<TypePtr>* types);

 private:
  base::win::ScopedComPtr<IDiaDataSource> source_;
  base::win::ScopedComPtr<IDiaSession> session_;
  base::win::ScopedComPtr<IDiaSymbol> global_;
};

}  // namespace refinery

#endif  // SYZYGY_REFINERY_TYPES_DIA_CRAWLER_H_
