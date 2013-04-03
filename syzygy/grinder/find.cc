// Copyright 2013 Google Inc. All Rights Reserved.
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
// Implementation of utility functions for finding the original PE file from
// a Syzygy transformed/instrumented version of it.

#include "syzygy/grinder/find.h"

#include "syzygy/pe/find.h"
#include "syzygy/pe/metadata.h"

namespace grinder {

bool PeFilesAreRelated(const base::FilePath& transformed_pe_path,
                       const base::FilePath& original_pe_path) {
  pe::PEFile transformed_pe_file;
  if (!transformed_pe_file.Init(transformed_pe_path)) {
    LOG(ERROR) << "Unable to parse PE file: " << transformed_pe_path.value();
    return false;
  }

  pe::Metadata metadata;
  if (!metadata.LoadFromPE(transformed_pe_file)) {
    LOG(ERROR) << "Unable to load metadata from PE file: "
               << transformed_pe_path.value();
    return false;
  }

  pe::PEFile original_pe_file;
  if (!original_pe_file.Init(original_pe_path)) {
    LOG(ERROR) << "Unable to parse PE file: " << original_pe_path.value();
    return false;
  }

  pe::PEFile::Signature original_signature;
  original_pe_file.GetSignature(&original_signature);
  if (!metadata.module_signature().IsConsistent(original_signature))
    return false;

  return true;
}

bool FindOriginalPeFile(const base::FilePath& transformed_pe_path,
                        base::FilePath* original_pe_path) {
  DCHECK(original_pe_path != NULL);
  return FindOriginalPeFile(transformed_pe_path,
                            L"",
                            original_pe_path);
}

bool FindOriginalPeFile(const base::FilePath& transformed_pe_path,
                        const base::StringPiece16& search_paths,
                        base::FilePath* original_pe_path) {
  DCHECK(original_pe_path != NULL);

  pe::PEFile transformed_pe_file;
  if (!transformed_pe_file.Init(transformed_pe_path)) {
    LOG(ERROR) << "Unable to parse PE file: " << transformed_pe_path.value();
    return false;
  }

  pe::Metadata metadata;
  if (!metadata.LoadFromPE(transformed_pe_file)) {
    LOG(ERROR) << "Unable to load metadata from PE file: "
               << transformed_pe_path.value();
    return false;
  }

  std::vector<base::FilePath> candidate_paths;
  if (!original_pe_path->empty())
    candidate_paths.push_back(*original_pe_path);
  candidate_paths.push_back(base::FilePath(metadata.module_signature().path));

  // Search using each of the candidate paths as a base.
  for (size_t i = 0; i < candidate_paths.size(); ++i) {
    const base::FilePath& path = candidate_paths[i];

    *original_pe_path = path;
    if (!FindModuleBySignature(metadata.module_signature(),
                               search_paths,
                               original_pe_path)) {
      return false;
    }

    // We can terminate the search early if the module is found.
    if (!original_pe_path->empty())
      return true;
  }
  DCHECK(original_pe_path->empty());

  return true;
}

}  // namespace grinder
