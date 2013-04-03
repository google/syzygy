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

#ifndef SYZYGY_EXPERIMENTAL_PDB_DUMPER_PDB_DUMP_H_
#define SYZYGY_EXPERIMENTAL_PDB_DUMPER_PDB_DUMP_H_

#include <utility>
#include <vector>

#include "base/files/file_path.h"
#include "syzygy/common/application.h"
#include "syzygy/pdb/pdb_util.h"

namespace pdb {

// Forward declarations.
class DbiStream;

// The PdbDump application dumps data for one or more PDB files to stdout,
// and can optionally explode the streams from each PDB file to a set of files
// in a directory named <pdbfile>-streams.
class PdbDumpApp : public common::AppImplBase {
 public:
  PdbDumpApp();

  // @name Application interface overrides.
  // @{
  bool ParseCommandLine(const CommandLine* command_line);
  int Run();
  // @}

 protected:
  // Prints @p message, followed by usage instructions.
  // @returns false.
  bool Usage(const char* message);

  // Dumps @p info and @p name_streams to out().
  void DumpInfoStream(const PdbInfoHeader70& info,
                      const NameStreamMap& name_streams);

  // Dumps headers from @p dbi_stream to out().
  void DumpDbiHeaders(const DbiStream& dbi_stream);

  // Dumps the name table from the PDB file to out().
  void DumpNameTable(const OffsetStringMap& name_table);

  // Dumps @p dbi_stream to out().
  void DumpDbiStream(const DbiStream& dbi_stream);

  // The PDB files to dump.
  std::vector<base::FilePath> pdb_files_;

  // Iff true, will explode the streams from pdb_files_ to individual files.
  // Default fo false.
  bool explode_streams_;

  // Iff true, the symbol record stream will be dumped. Default fo false.
  bool dump_symbol_record_;

  // Iff true, the type info stream will be dumped. Default fo false.
  bool dump_type_info_;

  // Iff true, the module streams will be dumped. Default fo false.
  bool dump_modules_;
};

}  // namespace pdb

#endif  // SYZYGY_EXPERIMENTAL_PDB_DUMPER_PDB_DUMP_H_
