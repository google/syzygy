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
#ifndef SAWBUCK_IMAGE_UTIL_PDB_READER_H_
#define SAWBUCK_IMAGE_UTIL_PDB_READER_H_

#include <vector>
#include "base/file_path.h"
#include "base/file_util.h"
#include "sawbuck/image_util/pdb_constants.h"
#include "sawbuck/image_util/pdb_data.h"
#include "sawbuck/image_util/pdb_stream.h"

// This class is used to read a pdb file and provide access to the file's
// symbol streams.
class PdbReader {
 public:
  // Construct a PdbReader for the given pdb path.
  PdbReader();
  ~PdbReader();

  // Read the pdb file. Load the file's header and directory into memory and
  // construct a list of PdbStreams that can be used to read the file's streams.
  // @p pdb_path is the path to the pdb file to be read, and @p pdb_streams is
  // a pointer to an already instantiated vector of PdbStream pointers which
  // will contain a list of PdbStreams on a successful file read.
  // @note The PdbStream pointers returned by this method are owned by the
  // PdbReader and are invalid once Read is called again or the PdbReader goes
  // out of scope.
  bool Read(const FilePath& pdb_path, std::vector<PdbStream*>* streams);

 protected:
  // Get the file size in bytes for an already opened file handle.
  // Will set stream cursor to end of file.
  bool GetFileSize(FILE* file, uint32* size) const;

  // Get the number of pages required to store specified number of bytes.
  uint32 GetNumPages(uint32 num_bytes) const;

  // Free any allocated PDB streams.
  void FreeStreams();

  // The current file handle open for reading.
  file_util::ScopedFILE file_;

  // The pdb file's header.
  PdbHeader header_;

  // The pdb file's directory.
  scoped_array<uint32> directory_;

  // The list of pdb streams in the pdb file.
  std::vector<PdbStream*> streams_;
};

#endif  // SAWBUCK_IMAGE_UTIL_PDB_READER_H_
