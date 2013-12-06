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
// Declares a simple API for mutating PDB files.

#ifndef SYZYGY_PDB_PDB_MUTATOR_H_
#define SYZYGY_PDB_PDB_MUTATOR_H_

#include "syzygy/pdb/pdb_file.h"

namespace pdb {

// A PdbMutatorInterface is a pure virtual base class defining the mutator API.
class PdbMutatorInterface {
 public:
  virtual ~PdbMutatorInterface() { }

  // Gets the name of this mutator.
  // @returns the name of this mutator.
  virtual const char* name() const = 0;

  // Applies this mutator to the provided PDB. It is up to the mutator to
  // ensure that all headers are maintained properly, etc.
  // @param pdb_file The PDB file to be modified.
  virtual bool MutatePdb(PdbFile* pdb_file) = 0;
};

// Applies a vector of PDB mutators to the given file. Logs an error on failure.
// @param pdb_mutators The PDB mutators to be applied.
// @param pdb_file The PDB file to be modified.
// @returns true on success, false otherwise.
bool ApplyPdbMutators(const std::vector<PdbMutatorInterface*>& pdb_mutators,
                      PdbFile* pdb_file);

}  // namespace pdb

#endif  // SYZYGY_PDB_PDB_MUTATOR_H_
