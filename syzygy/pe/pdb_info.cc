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

#include "syzygy/pe/pdb_info.h"

#include <string.h>
#include "base/logging.h"
#include "base/strings/utf_string_conversions.h"
#include "syzygy/pe/pe_file.h"

namespace pe {

PdbInfo::PdbInfo() : pdb_age_(0) {
  ::memset(&signature_, 0, sizeof(signature_));
}

bool PdbInfo::Init(const CvInfoPdb70& cv_info_pdb) {
  pdb_age_ = cv_info_pdb.pdb_age;
  signature_ = cv_info_pdb.signature;

  // Convert the UTF-8 filename to a FilePath.
  std::wstring pdb_path;
  if (!base::UTF8ToWide(cv_info_pdb.pdb_file_name,
                        ::strlen(cv_info_pdb.pdb_file_name),
                        &pdb_path)) {
    LOG(ERROR) << "base::UTF8ToWide failed.";
    return false;
  }
  pdb_file_name_ = base::FilePath(pdb_path);

  return true;
}

bool PdbInfo::Init(const PEFile& pe_file) {
  const IMAGE_DATA_DIRECTORY& debug_data_dir =
      pe_file.nt_headers()->OptionalHeader.DataDirectory[
          IMAGE_DIRECTORY_ENTRY_DEBUG];

  // Iterate through the debug directory entries.
  const size_t kEntrySize = sizeof(IMAGE_DEBUG_DIRECTORY);
  for (size_t i = 0; i < debug_data_dir.Size; i += kEntrySize) {
    IMAGE_DEBUG_DIRECTORY debug_dir = {};
    PEFile::RelativeAddress entry_addr(debug_data_dir.VirtualAddress + i);
    if (!pe_file.ReadImage(entry_addr, &debug_dir, sizeof(debug_dir))) {
      LOG(ERROR) << "Unable to read debug directory entry from PE file: "
                 << pe_file.path().value();
      return false;
    }
    entry_addr += kEntrySize;

    // We're looking for a code-view (ie: PDB file) entry, so skip any others.
    if (debug_dir.Type != IMAGE_DEBUG_TYPE_CODEVIEW)
      continue;

    if (debug_dir.SizeOfData < sizeof(CvInfoPdb70)) {
      LOG(ERROR) << "CodeView debug entry too small.";
      return false;
    }

    // Read the actual debug directory data.
    PEFile::RelativeAddress pdb_info_addr(debug_dir.AddressOfRawData);
    std::vector<uint8> buffer(debug_dir.SizeOfData);
    if (!pe_file.ReadImage(pdb_info_addr, &buffer[0], buffer.size())) {
      LOG(ERROR) << "Unable to read debug directory data from PE file: "
                 << pe_file.path().value();
      return false;
    }

    CvInfoPdb70* cv_info = reinterpret_cast<CvInfoPdb70*>(&buffer[0]);
    return Init(*cv_info);
  }

  LOG(ERROR) << "PE file has no CodeView debug entry.";
  return false;
}

bool PdbInfo::Init(const base::FilePath& pe_path) {
  DCHECK(!pe_path.empty());

  PEFile pe_file;
  if (!pe_file.Init(pe_path)) {
    LOG(ERROR) << "Unable to process PE file: " << pe_path.value();
    return false;
  }

  return Init(pe_file);
}

bool PdbInfo::IsConsistent(const pdb::PdbInfoHeader70& pdb_header) const {
  // The PDB age in the PDB file is bumped when e.g. source information
  // is added to the file, so we want the PdbInfoHeader to have an equal or
  // greater age that the image's.
  return pdb_age_ <= pdb_header.pdb_age &&
      signature_ == pdb_header.signature;
}

}  // namespace pe
