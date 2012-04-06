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
//
// Declares a PDB file, which is an in-memory representation of a PDB file.
// A PDB file consists of a collection of numbered PDB streams. The streams
// themselves obey certain formats and conventions but these are not enforced
// by this naive representation.

#ifndef SYZYGY_PDB_PDB_FILE_H_
#define SYZYGY_PDB_PDB_FILE_H_

#include <vector>

#include "syzygy/pdb/pdb_stream.h"

namespace pdb {

// A simple representation of a PDB file as a collection of numbered streams.
// This object owns all of the streams referred to by it and maintains
// responsibility for cleaning them up on destruction.
class PdbFile {
 public:
  PdbFile();
  ~PdbFile();

  // Clears all streams. After calling this the PdbFile is in the same state as
  // after construction.
  void Clear();

  // Accesses the nth stream.
  // @param index the index of the nth stream.
  // @returns a pointer to the stream, NULL if it does not exist.
  PdbStream* GetStream(uint32 index) const;

  // Adds a new stream to this PDB file, returning the index of the newly
  // generated stream. The stream must be heap allocated and ownership is
  // passed to this object.
  // @param pdb_stream a pointer to a heap allocated stream object. Ownership of
  //     the stream is passed to this object. This may be NULL, indicating that
  //     the nth stream exists but is empty.
  // @returns the index of the added stream.
  size_t AppendStream(PdbStream* pdb_stream);

  // Sets the nth stream. The stream object must be heap allocated and
  // ownership is implicitly transferred to the PdbFile object. Overwrites an
  // existing stream if there is one, and destroys it as well. It is up to the
  // caller to ensure there are no outstanding references to the existing
  // stream.
  // @param index the index of the stream. This must be >= 0, and must be
  //     a stream index that already exists.
  // @param pdb_stream a pointer to the heap allocated stream to be placed at
  //     the given position. Ownership is transferred to this object. This may
  //     be NULL, which is equivalent to erasing the given stream.
  void ReplaceStream(uint32 index, PdbStream* pdb_stream);

  // Returns the number of streams in the PDB file. There are streams with
  // IDs 0 through StreamCount() - 1.
  // @returns the number of streams in the PDB file.
  size_t StreamCount() const { return streams_.size(); }

  // @returns a constant reference to the streams representing this PDB file.
  const std::vector<PdbStream*>& streams() const { return streams_; }

 private:
  // The streams are implicitly numbered simply by their position in this
  // vector.
  std::vector<PdbStream*> streams_;
};

}  // namespace pdb

#endif  // SYZYGY_PDB_PDB_FILE_H_
