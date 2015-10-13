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
// Forward declaration of PDB specialization of MSF classes.

#ifndef SYZYGY_PDB_PDB_DECL_H_
#define SYZYGY_PDB_PDB_DECL_H_

#include "syzygy/msf/msf_decl.h"

namespace pdb {

// Forward declarations.
using PdbFile = msf::detail::MsfFileImpl<msf::kPdbMsfFileType>;
using PdbStream = msf::detail::MsfStreamImpl<msf::kPdbMsfFileType>;
using WritablePdbStream =
    msf::detail::WritableMsfStreamImpl<msf::kPdbMsfFileType>;

}  // namespace pdb

#endif  // SYZYGY_PDB_PDB_DECL_H_
