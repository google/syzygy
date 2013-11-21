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

#ifndef SYZYGY_PDB_PDB_READER_H_
#define SYZYGY_PDB_PDB_READER_H_

#include <vector>

#include "base/file_util.h"
#include "base/files/file_path.h"
#include "syzygy/pdb/pdb_constants.h"
#include "syzygy/pdb/pdb_data.h"
#include "syzygy/pdb/pdb_file.h"
#include "syzygy/pdb/pdb_file_stream.h"
#include "syzygy/pdb/pdb_stream.h"

namespace pdb {

// This class is used to read a PDB file from disk, populating a PdbFile
// object with its streams.
class PdbReader {
 public:
  PdbReader() { }

  // Reads a PDB, populating the given PdbFile object with the streams.
  //
  // @note Once use of the above Read function variants has been eliminated,
  //     PdbReader will become stateless and simply populate a PdbFile.
  //
  // @param pdb_path the PDB file to read.
  // @param pdb_file the empty PdbFile object to be filled in.
  // @returns true on success, false otherwise.
  bool Read(const base::FilePath& pdb_path, PdbFile* pdb_file);

 private:
  DISALLOW_COPY_AND_ASSIGN(PdbReader);
};

}  // namespace pdb

#endif  // SYZYGY_PDB_PDB_READER_H_
