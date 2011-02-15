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
#include "sawbuck/image_util/pdb_util.h"

namespace pdb_util {

uint32 GetDbiDbgHeaderOffset(const DbiHeader& dbi_header) {
  uint32 offset = sizeof(DbiHeader);
  offset += dbi_header.gp_modi_size;
  offset += dbi_header.section_contribution_size;
  offset += dbi_header.section_map_size;
  offset += dbi_header.file_info_size;
  offset += dbi_header.ts_map_size;
  offset += dbi_header.ec_info_size;  // Unexpected, but necessary.
  return offset;
}

}  // namespace pdb_util
