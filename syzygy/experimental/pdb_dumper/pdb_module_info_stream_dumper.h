// Copyright 2012 Google Inc. All Rights Reserved.
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
// This file allows dumping the content of a module info stream of a PDB.

#ifndef SYZYGY_EXPERIMENTAL_PDB_DUMPER_PDB_MODULE_INFO_STREAM_DUMPER_H_
#define SYZYGY_EXPERIMENTAL_PDB_DUMPER_PDB_MODULE_INFO_STREAM_DUMPER_H_

#include <vector>

#include "syzygy/pdb/pdb_data.h"
#include "syzygy/pdb/pdb_data_types.h"
#include "syzygy/pdb/pdb_decl.h"
#include "syzygy/pdb/pdb_util.h"

namespace pdb {

// Forward declarations.
class DbiModuleInfo;

// Dump a module info stream.
// @param module_info Information about the module.
// @param name_table Name table of the files used by the different modules.
// @param out The output where the data should be dumped.
// @param stream The module info stream.
void DumpModuleInfoStream(const DbiModuleInfo& module_info,
                          const OffsetStringMap& name_table,
                          FILE* out,
                          PdbStream* stream);

}  // namespace pdb

#endif  // SYZYGY_EXPERIMENTAL_PDB_DUMPER_PDB_MODULE_INFO_STREAM_DUMPER_H_
