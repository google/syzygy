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

#ifndef SYZYGY_PDB_PDB_WRITER_H_
#define SYZYGY_PDB_PDB_WRITER_H_

#include <vector>

#include "base/file_util.h"
#include "base/files/file_path.h"
#include "syzygy/pdb/pdb_file.h"
#include "syzygy/pdb/pdb_stream.h"

namespace pdb {

// This class is used to write a pdb file to disk given a list of PdbStreams.
// It will create a header and directory inside the pdb file that describe
// the page layout of the streams in the file.
class PdbWriter {
 public:
  PdbWriter();
  ~PdbWriter();

  // Writes the given PdbFile to disk with the given file name.
  // @param pdb_path the path of the PDB file to write.
  // @param pdb_file the PDB file to be written.
  // @returns true on success, false otherwise.
  bool Write(const base::FilePath& pdb_path, const PdbFile& pdb_file);

 protected:
  // Append the contents of the stream onto the file handle at the offset. The
  // contents of the file are padded to reach the next page boundary in the
  // output stream. The indices of the written pages are appended to
  // @p pages_written, while @p page_count is updated to reflect the total
  // number of pages written to disk.
  bool AppendStream(PdbStream* stream,
                    std::vector<uint32>* pages_written,
                    uint32* page_count);

  // Writes the MSF header after the directory has been written.
  bool WriteHeader(const std::vector<uint32>& root_directory_pages,
                   size_t directory_size,
                   uint32 page_count);

  // The current file handle open for writing.
  base::ScopedFILE file_;

 private:
  DISALLOW_COPY_AND_ASSIGN(PdbWriter);
};

}  // namespace pdb

#endif  // SYZYGY_PDB_PDB_WRITER_H_
