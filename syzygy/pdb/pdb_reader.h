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

#ifndef SYZYGY_PDB_PDB_READER_H_
#define SYZYGY_PDB_PDB_READER_H_

#include <vector>

#include "base/file_path.h"
#include "base/file_util.h"
#include "syzygy/pdb/pdb_constants.h"
#include "syzygy/pdb/pdb_data.h"
#include "syzygy/pdb/pdb_stream.h"

namespace pdb {

// This class is used to read a pdb file and provide access to the file's
// symbol streams.
class PdbReader {
 public:
  // Construct a PdbReader for the given pdb path.
  PdbReader();
  ~PdbReader();

  // Read the pdb file. Load the file's header and directory into memory and
  // construct a list of PdbStreams that can be used to read the file's streams.
  //
  // @param pdb_path the PDB file to read.
  // @returns true on success, false otherwise.
  bool Read(const FilePath& pdb_path);

  // Read the pdb file. Load the file's header and directory into memory and
  // construct a list of PdbStreams that can be used to read the file's streams.
  // @note The PdbStream pointers returned by this method are owned by the
  // PdbReader and are invalid once Read is called again or the PdbReader goes
  // out of scope.
  //
  // @note This version of the function is DEPRECATED in favour of using the
  //     single-parameter Read function combined with the stream accessors.
  //
  // @param pdb_path the PDB file to read.
  // @param streams a vector to receive the list of streams in the PDB.
  // @returns true on success, false otherwise.
  bool Read(const FilePath& pdb_path, std::vector<PdbStream*>* streams);

  // Get the path of the PDB file that we are reading.
  // @returns the path of the PDB file that is being read.
  const FilePath& path() const { return pdb_path_; }

  // An accessor for the streams in the PDB file.
  //
  // @returns the vector of streams.
  // @pre Read has been successfully called.
  const std::vector<PdbStream*>& streams() const { return streams_; }

  // An accessor for an individual stream. The returned pointer is owned by the
  // PdbRead and becomes invalid once Read is called again or the PdbReader goes
  // out of scope. Some streams may be NULL, even though there is a slot
  // allocated for them in streams().
  //
  // @param i the index of the stream to access. If i > streams().size, returns
  //     NULL.
  // @returns a pointer to the ith stream.
  PdbStream* stream(size_t i) const {
    if (i >= streams_.size())
      return NULL;
    return streams_[i];
  }

 protected:
  // Get the file size in bytes for an already opened file handle.
  // Will set stream cursor to end of file.
  bool GetFileSize(FILE* file, uint32* size) const;

  // Get the number of pages required to store specified number of bytes.
  uint32 GetNumPages(uint32 num_bytes) const;

  // Free any allocated PDB streams.
  void FreeStreams();

  // The path of the file we're reading.
  FilePath pdb_path_;

  // The current file handle open for reading.
  file_util::ScopedFILE file_;

  // The pdb file's header.
  PdbHeader header_;

  // The pdb file's directory.
  scoped_array<uint32> directory_;

  // The list of pdb streams in the pdb file.
  std::vector<PdbStream*> streams_;

 private:
  DISALLOW_COPY_AND_ASSIGN(PdbReader);
};

}  // namespace pdb

#endif  // SYZYGY_PDB_PDB_READER_H_
