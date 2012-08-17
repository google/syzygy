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
// Declares a mutator for adding named streams to a PDB file. Takes care of
// reading and rewriting the named stream table in the header stream.

#ifndef SYZYGY_PDB_MUTATORS_ADD_NAMED_STREAM_MUTATOR_H_
#define SYZYGY_PDB_MUTATORS_ADD_NAMED_STREAM_MUTATOR_H_

#include <map>

#include "base/string_piece.h"
#include "syzygy/pdb/pdb_stream.h"
#include "syzygy/pdb/pdb_util.h"
#include "syzygy/pdb/mutators/named_mutator.h"

namespace pdb {
namespace mutators {

// A partial mutator implementation for easily adding named streams to a PDB.
// This is intended for adding streams whose contents are dynamic and not known
// until post-transform/post-ordering.
// @tparam DerivedType the type of the derived class.
template<typename DerivedType>
class AddNamedStreamMutatorImpl : public NamedPdbMutatorImpl<DerivedType> {
 public:
  // The main body of the mutator.
  virtual bool MutatePdb(PdbFile* pdb_file) OVERRIDE;

 protected:
  // This is called by MutatePdb and is the hook where the derived class can
  // actually add new streams to the PDB. The @p pdb_file is passed for
  // introspection purposes but it should not be modified directly. Rather,
  // streams should be added using the AddNamedStream utility function. This
  // function should be overridden by the derived class as no implementation is
  // provided here.
  // @param pdb_file The PDB file to which we will be adding streams.
  // @returns true on success, false otherwise.
  // bool AddNamedStreams(const PdbFile& pdb_file);

  // A utility function for adding an individual name stream to a PDB.
  // @param name the name of the stream to add.
  // @param stream the stream to add.
  void AddNamedStream(const base::StringPiece& name, PdbStream* stream) {
    name_stream_map_[name.as_string()] = stream;
  }

 private:
  typedef std::map<std::string, scoped_refptr<PdbStream>> NameStreamMap;

  // Houses a set of named streams to be added to the PDB.
  NameStreamMap name_stream_map_;
};

template<typename DerivedType>
bool AddNamedStreamMutatorImpl<DerivedType>::MutatePdb(PdbFile* pdb_file) {
  // Parse the header and named streams.
  pdb::PdbInfoHeader70 header = {};
  pdb::NameStreamMap name_stream_map;
  if (!ReadHeaderInfoStream(*pdb_file, &header, &name_stream_map))
    return false;

  // Call the hook.
  DerivedType* self = static_cast<DerivedType*>(this);
  if (!self->AddNamedStreams(*pdb_file))
    return false;

  // Add each stream to the PDB file and update the name to stream id map.
  NameStreamMap::const_iterator it = name_stream_map_.begin();
  for (; it != name_stream_map_.end(); ++it) {
    LOG(INFO) << "Adding named stream \"" << it->first << "\" to PDB.";
    size_t stream_id = pdb_file->AppendStream(it->second);
    name_stream_map[it->first] = stream_id;
  }

  // Write back the header with the updated map.
  if (!WriteHeaderInfoStream(header, name_stream_map, pdb_file))
    return false;

  return true;
}

}  // namespace mutators
}  // namespace pdb

#endif  // SYZYGY_PDB_MUTATORS_ADD_NAMED_STREAM_MUTATOR_H_
