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
#ifndef SYZYGY_PDB_PDB_UTIL_H_
#define SYZYGY_PDB_PDB_UTIL_H_

#include <windows.h>
#include <dbghelp.h>
#include <vector>
#include "base/file_path.h"
#include "syzygy/pdb/pdb_data.h"

namespace pdb {

// Get the DbiDbgHeader offset within the Dbi info stream. For some reason,
// the EC info data comes before the Dbi debug header despite that the Dbi
// debug header size comes before the EC info size in the Dbi header struct.
uint32 GetDbiDbgHeaderOffset(const DbiHeader& dbi_header);

// Add Omap stream data to an existing Pdb file and write it as a new Pdb file,
// while updating the Pdb header to a new GUID and timestamp.
// The Omap vector arguments must already be sorted in ascending order by rva.
// @param output_guid a new GUID to assign to the output_file.
bool AddOmapStreamToPdbFile(const FilePath& input_file,
                            const FilePath& output_file,
                            const GUID& output_guid,
                            const std::vector<OMAP>& omap_to_list,
                            const std::vector<OMAP>& omap_from_list);

// Reads the header from the given PDB file @p pdb_path.
// @returns true on success, false on error.
bool ReadPdbHeader(const FilePath& pdb_path, PdbInfoHeader70* pdb_header);

}  // namespace pdb

#endif  // SYZYGY_PDB_PDB_UTIL_H_
