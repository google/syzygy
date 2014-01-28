// Copyright 2011 Google Inc. All Rights Reserved.
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
// Declares a simple class for extracting PDB information from a PE file.
#ifndef SYZYGY_PE_PDB_INFO_H_
#define SYZYGY_PE_PDB_INFO_H_

#include "base/basictypes.h"
#include "base/files/file_path.h"
#include "syzygy/pdb/pdb_data.h"
#include "syzygy/pe/pe_data.h"
#include "syzygy/pe/pe_file.h"

namespace pe {

// This class is analogous to CvInfoPdb70, but with a FilePath instead of a
// char*. It contains functionality for loading the debug information directly
// from a PE file using our PE parser rather than loading the whole image.
class PdbInfo {
 public:
  PdbInfo();

  // Initializes this object from @p cv_info_pdb.
  // @returns true on success, false otherwise.
  bool Init(const CvInfoPdb70& cv_info_pdb);

  // Initializes this object from an already loaded PE file @p pe_file.
  // @returns true on success, false otherwise.
  bool Init(const PEFile& pe_file);

  // Initializes this object from the provided PE file @pe_path.
  // @returns true on success, false otherwise.
  bool Init(const base::FilePath& pe_path);

  // Accessors.
  uint32 pdb_age() const { return pdb_age_; }
  const base::FilePath& pdb_file_name() const { return pdb_file_name_; }
  const GUID& signature() const { return signature_; }

  // Compares this object with the given PdbInfoHeader @p pdb_info_header.
  // @returns true if they are consistent, false otherwise.
  bool IsConsistent(const pdb::PdbInfoHeader70& pdb_info_header) const;

 private:
  uint32 pdb_age_;
  base::FilePath pdb_file_name_;
  GUID signature_;
};

}  // namespace pe

#endif  // SYZYGY_PE_PDB_INFO_H_
