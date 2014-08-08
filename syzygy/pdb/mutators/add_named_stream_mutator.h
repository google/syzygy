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
// Declares a mutator for adding named streams to a PDB file. Takes care of
// reading and rewriting the named stream table in the header stream.

#ifndef SYZYGY_PDB_MUTATORS_ADD_NAMED_STREAM_MUTATOR_H_
#define SYZYGY_PDB_MUTATORS_ADD_NAMED_STREAM_MUTATOR_H_

#include <map>

#include "base/strings/string_piece.h"
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

  // TODO(chrisha): The following utility functions need to be members of
  //     PdbFile. In fact, the current PdbFile should become MsfFile, and we
  //     need to have a 'smarter' PdbFile than the one we have now (aware of
  //     the header streams, named streams, stream types, etc). With all of that
  //     machinery available this entire class can disappear. In the meantime,
  //     we'll live with the ugliness.

  // A utility function for retrieving an individual named stream from a PDB.
  // @param name the name of the stream to lookup.
  // @returns a pointer to the stream if found, NULL if none exists.
  scoped_refptr<PdbStream> GetNamedStream(const base::StringPiece& name) const;

  // A utility function for adding an individual name stream to a PDB. If a
  // stream already exists with this name, it will be replaced.
  // @param name the name of the stream to add.
  // @param stream the stream to add.
  // @returns true if the stream was added, false if it replaced an existing
  //     stream.
  bool SetNamedStream(const base::StringPiece& name, PdbStream* stream);

 private:
  PdbFile* pdb_file_;
  NameStreamMap name_stream_map_;
};

template<typename DerivedType>
bool AddNamedStreamMutatorImpl<DerivedType>::MutatePdb(PdbFile* pdb_file) {
  DCHECK(pdb_file != NULL);

  // Parse the header and named streams.
  pdb_file_ = pdb_file;
  pdb::PdbInfoHeader70 header = {};
  if (!ReadHeaderInfoStream(*pdb_file, &header, &name_stream_map_))
    return false;

  // Call the hook.
  DerivedType* self = static_cast<DerivedType*>(this);
  if (!self->AddNamedStreams(*pdb_file))
    return false;

  // Write back the header with the updated map.
  if (!WriteHeaderInfoStream(header, name_stream_map_, pdb_file))
    return false;

  pdb_file_ = NULL;
  name_stream_map_.clear();

  return true;
}

template<typename DerivedType>
scoped_refptr<PdbStream>
AddNamedStreamMutatorImpl<DerivedType>::GetNamedStream(
    const base::StringPiece& name) const {
  DCHECK(pdb_file_ != NULL);

  NameStreamMap::const_iterator it = name_stream_map_.find(name.as_string());
  if (it == name_stream_map_.end())
    return NULL;

  size_t index = it->second;
  return pdb_file_->GetStream(index);
}

template<typename DerivedType>
bool AddNamedStreamMutatorImpl<DerivedType>::SetNamedStream(
    const base::StringPiece& name, PdbStream* stream) {
  DCHECK(pdb_file_ != NULL);

  size_t index = 0;
  NameStreamMap::const_iterator it = name_stream_map_.find(name.as_string());

  // We are adding a new stream.
  if (it == name_stream_map_.end()) {
    index = pdb_file_->AppendStream(stream);
    name_stream_map_.insert(std::make_pair(name.as_string(), index));
    return true;
  }

  // We are replacing an existing stream.
  index = it->second;
  pdb_file_->ReplaceStream(index, stream);
  return false;
}

}  // namespace mutators
}  // namespace pdb

#endif  // SYZYGY_PDB_MUTATORS_ADD_NAMED_STREAM_MUTATOR_H_
