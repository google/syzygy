// Copyright 2013 Google Inc. All Rights Reserved.
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

#include "syzygy/pdb/pdb_mutator.h"

namespace pdb {

bool ApplyPdbMutators(const std::vector<PdbMutatorInterface*>& pdb_mutators,
                      PdbFile* pdb_file) {
  DCHECK_NE(reinterpret_cast<PdbFile*>(NULL), pdb_file);

  // Apply the mutators.
  for (size_t i = 0; i < pdb_mutators.size(); ++i) {
    DCHECK_NE(reinterpret_cast<PdbMutatorInterface*>(NULL), pdb_mutators[i]);
    LOG(INFO) << "Apply PDB mutator \"" << pdb_mutators[i]->name();
    if (!pdb_mutators[i]->MutatePdb(pdb_file)) {
      LOG(ERROR) << "PDB mutator \"" << pdb_mutators[i]->name()
                 << "\" failed.";
      return false;
    }
  }

  return true;
}

}  // namespace pdb
