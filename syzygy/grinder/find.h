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
// Declares utility functions for finding the original PE file from a Syzygy
// transformed/instrumented version of it.

#ifndef SYZYGY_GRINDER_FIND_H_
#define SYZYGY_GRINDER_FIND_H_

#include "syzygy/pe/find.h"

namespace grinder {

// Determines if @p transformed_pe_path is a Syzygy-transformed version of
// @p original_pe_path.
// @param transformed_pe_path The path of the Syzygy-transformed PE file.
// @param original_pe_path The path of the original non-transformed PE file.
// @returns true if the files both exist and are related,
// false otherwise.
bool PeFilesAreRelated(const base::FilePath& transformed_pe_path,
                       const base::FilePath& original_pe_path);

// Given a Syzygy-transformed PE file looks for the corresponding original
// PE file. This extracts the metadata from the transformed image and uses that
// as input to pe::FindModuleBySignature (see for details on the search
// strategy).
// @param transformed_pe_path The path of the Syzygy-transformed PE file
//     whose untransformed source PE file we are looking for.
// @param search_paths A semi-colon separated list of additional search paths.
// @param original_pe_path Will contain the path to the original PE file if
//     found, otherwise will be empty.
// @returns false on error, true otherwise. @p original_pe_path will be
//      non-empty if the module was found, otherwise it'll be empty.
bool FindOriginalPeFile(const base::FilePath& transformed_pe_path,
                        base::FilePath* original_pe_path);
bool FindOriginalPeFile(const base::FilePath& transformed_pe_path,
                        const base::StringPiece16& search_paths,
                        base::FilePath* original_pe_path);

}  // namespace grinder

#endif  // SYZYGY_GRINDER_FIND_H_
