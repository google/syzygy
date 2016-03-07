// Copyright 2011 Google Inc. All Rights Reserved.
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

#ifndef SYZYGY_PE_PE_DATA_H_
#define SYZYGY_PE_PE_DATA_H_

#include <windows.h>


namespace pe {

// This reads 'RSDS' in memory.
const uint32_t kPdb70Signature = 0x53445352;

// This is the structure referenced by the debug directory for
// CV info where the debug info is in a PDB 7 file.
struct CvInfoPdb70 {
  uint32_t cv_signature;
  GUID signature;
  uint32_t pdb_age;
  char pdb_file_name[1];
};

}  // namespace pe

#endif  // SYZYGY_PE_PE_DATA_H_
