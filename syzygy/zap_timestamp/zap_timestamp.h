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
// Declares a class that allows for the normalization of a PE file and its
// corresponding PDB file.
//
// TODO(chrisha): This currently works in-place only, but should be extended to
//     work to a new destination as well.

#ifndef SYZYGY_ZAP_TIMESTAMP_ZAP_TIMESTAMP_H_
#define SYZYGY_ZAP_TIMESTAMP_ZAP_TIMESTAMP_H_

#include <vector>

#include "base/files/file_path.h"
#include "base/strings/string_piece.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/common/application.h"
#include "syzygy/core/address_space.h"
#include "syzygy/pdb/pdb_file.h"
#include "syzygy/pe/image_layout.h"
#include "syzygy/pe/pe_file.h"

namespace zap_timestamp {

// Utility class for normalizing a PE file and the matching PDB file. They vary
// largely in terms of timestamps and hash values, hence the name of the class.
class ZapTimestamp {
 public:
  ZapTimestamp();

  // Prepares for modifying the given PE file. Tracks down all of the bytes
  // to be modified and prepares the new values to be stored. Searches for the
  // matching PDB file and does the same thing with it.
  // @param pe_path path to the PE file to be zapped.
  // @returns true on success, false otherwise.
  bool Init(const base::FilePath& pe_path);

  // Prepares for modifying the given PE file. Tracks down all of the bytes
  // to be modified and prepares the new values to be stored.
  // @param pe_path path to the PE file to be zapped.
  // @param pdb_path path the PDB file to be zapped.
  // @returns true on success, false otherwise.
  bool Init(const base::FilePath& pe_path, const base::FilePath& pdb_path);

  // Modifies the given PE file in place, as well as its associated PDB file.
  // @param modify_pe if true then the PE file will be updated in place.
  // @param modify_pdb if true then the PDB file will be updated in place.
  // @returns true on success, false on failure.
  // @pre Init has been successfully called.
  bool Zap(bool modify_pe, bool modify_pdb);

  // @name Accessors.
  // @{
  const base::FilePath& pe_path() const { return pe_path_; }
  const base::FilePath& pdb_path() const { return pdb_path_; }
  // @}

  // Forward declarations. These are public so they can be used by anonymous
  // helper functions in zap_timestamp.cc.
  struct PatchData;
  typedef core::AddressSpace<core::FileOffsetAddress, size_t, PatchData>
      PatchAddressSpace;

 private:
  // Ensures the PE file exists and is valid, and searches for the corresponding
  // PDB file. After this runs both pe_path_ and pdb_path_ are initialized and
  // point to valid corresponding files.
  bool ValidatePeAndPdbFiles();

  // Decomposes the PE file. After this is complete block_graph_, image_layout_
  // and pe_file_ and dos_header_block_ have been initialized.
  bool DecomposePeFile();

  // Paints the regions of the PE file that need to be modified.
  bool MarkPeFileRanges();

  // Calculates a PDB GUID using the non-changing parts of the PE file.
  bool CalculatePdbGuid();

  // Loads the PDB file and updates its in-memory representation.
  bool LoadAndUpdatePdbFile();

  // @{
  // These do the actual writing of the individual files.
  bool WritePeFile();
  bool WritePdbFile();
  // @}

  // Initialized by ValidatePeAndPdbFiles.
  base::FilePath pe_path_;
  base::FilePath pdb_path_;

  // Initialized by DecomposePeFile.
  block_graph::BlockGraph block_graph_;
  pe::ImageLayout image_layout_;
  pe::PEFile pe_file_;
  block_graph::BlockGraph::Block* dos_header_block_;

  // Populated by MarkPeFileRanges.
  PatchAddressSpace pe_file_addr_space_;

  // Populated by LoadPdbFile and modified by UpdatePdbFile.
  scoped_ptr<pdb::PdbFile> pdb_file_;

  // These house the new values to be written when the image is zapped.
  DWORD timestamp_data_;
  DWORD pdb_age_data_;
  GUID pdb_guid_data_;

  DISALLOW_COPY_AND_ASSIGN(ZapTimestamp);
};

// Used to keep track of data in the image that is to be changed, and the
// new values to be written.
struct ZapTimestamp::PatchData {
  PatchData(const uint8* data, const base::StringPiece& name)
      : data(data) {
    name.CopyToString(&this->name);
  }
  const uint8* data;
  std::string name;
};

// The application class that actually runs ZapTimestamp.
class ZapTimestampApp : public common::AppImplBase {
 public:
  ZapTimestampApp() : AppImplBase("Zap Timestamp") { }

  // @name Implementation of the AppImplbase interface.
  // @{
  bool ParseCommandLine(const CommandLine* command_line);
  int Run();
  // @}

 private:
  // The input modules to be zapped. Each one must be a PE file.
  std::vector<base::FilePath> input_modules_;

  DISALLOW_COPY_AND_ASSIGN(ZapTimestampApp);
};

}  // namespace zap_timestamp

#endif  // SYZYGY_ZAP_TIMESTAMP_ZAP_TIMESTAMP_H_
