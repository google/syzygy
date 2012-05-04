// Copyright 2012 Google Inc.
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

#ifndef SYZYGY_PDB_PDB_DUMP_H_
#define SYZYGY_PDB_PDB_DUMP_H_

#include <vector>

#include "base/file_path.h"
#include "syzygy/common/application.h"
#include "syzygy/pdb/pdb_data.h"
#include "syzygy/pdb/pdb_util.h"

namespace pdb {

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

  // Dumps @p dbi_header and @p dbg_header to out().
  void DumpDbiHeaders(const DbiHeader& dbi_header,
                      const DbiDbgHeader& dbg_header);

  // The PDB files to dump.
  std::vector<FilePath> pdb_files_;

  // Iff true, will explode the streams from pdb_files_ to individual files.
  bool explode_streams_;
};

}  // namespace pdb

#endif  // SYZYGY_PDB_PDB_DUMP_H_
