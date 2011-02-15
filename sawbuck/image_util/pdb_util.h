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
#ifndef SAWBUCK_IMAGE_UTIL_PDB_UTIL_H_
#define SAWBUCK_IMAGE_UTIL_PDB_UTIL_H_

#include "sawbuck/image_util/pdb_data.h"

namespace pdb_util {

// Get the DbiDbgHeader offset within the Dbi info stream. For some reason,
// the EC info data comes before the Dbi debug header despite that the Dbi
// debug header size comes before the EC info size in the Dbi header struct.
uint32 GetDbiDbgHeaderOffset(const DbiHeader& dbi_header);

}  // namespace pdb_util

#endif  // SAWBUCK_IMAGE_UTIL_PDB_UTIL_H_
