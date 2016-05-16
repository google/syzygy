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

#ifndef SYZYGY_ZAP_TIMESTAMP_ZAP_TIMESTAMP_H_
#define SYZYGY_ZAP_TIMESTAMP_ZAP_TIMESTAMP_H_

#include "base/files/file_path.h"
#include "base/strings/string_piece.h"
#include "syzygy/block_graph/block_graph.h"
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

  // @name Mutators.
  // @{
  void set_input_image(const base::FilePath& input_image) {
    input_image_ = input_image;
  }
  void set_input_pdb(const base::FilePath& input_pdb) {
    input_pdb_ = input_pdb;
  }
  void set_output_image(const base::FilePath& output_image) {
    output_image_ = output_image;
  }
  void set_output_pdb(const base::FilePath& output_pdb) {
    output_pdb_ = output_pdb;
  }
  void set_write_image(bool write_image) {
    write_image_ = write_image;
  }
  void set_write_pdb(bool write_pdb) {
    write_pdb_ = write_pdb;
  }
  void set_overwrite(bool overwrite) {
    overwrite_ = overwrite;
  }
  void set_timestamp_value(size_t timestamp_value) {
    timestamp_data_ = static_cast<size_t>(timestamp_value);
  }
  // @}

  // @name Accessors.
  // @{
  const base::FilePath& input_image() const { return input_image_; }
  const base::FilePath& input_pdb() const { return input_pdb_; }
  const base::FilePath& output_image() const { return output_image_; }
  const base::FilePath& output_pdb() const { return output_pdb_; }
  bool write_image() const { return write_image_; }
  bool write_pdb() const { return write_pdb_; }
  bool overwrite() const { return overwrite_; }
  size_t timestamp_value() const {
    return static_cast<size_t>(timestamp_data_);
  }
  // @}

  // Prepares for modifying the given PE file. Tracks down all of the bytes
  // to be modified and prepares the new values to be stored. Searches for the
  // matching PDB file and does the same thing with it.
  // @returns true on success, false otherwise.
  bool Init();

  // Modifies the given PE file (and its associated PDB file, if applicable).
  // Output will be written to |output_image| and |output_pdb|. If these are
  // not specified the transform will be applied in place.
  // @returns true on success, false on failure.
  // @pre Init has been successfully called.
  bool Zap();

  // Forward declarations. These are public so they can be used by anonymous
  // helper functions in zap_timestamp.cc.
  struct PatchData;
  typedef core::AddressSpace<core::FileOffsetAddress, size_t, PatchData>
      PatchAddressSpace;

 private:
  // Ensures the PE file exists and is valid, and searches for the corresponding
  // PDB file. After this runs both input_image_ and input_pdb_ are initialized
  // and point to valid corresponding files.
  bool ValidatePeAndPdbFiles();

  // Infers and validates output paths. After this |output_image_| and
  // |output_pdb_| are configured.
  bool ValidateOutputPaths();

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

  // Initialized by DecomposePeFile.
  block_graph::BlockGraph block_graph_;
  pe::ImageLayout image_layout_;
  pe::PEFile pe_file_;
  block_graph::BlockGraph::Block* dos_header_block_;

  // Populated by MarkPeFileRanges.
  PatchAddressSpace pe_file_addr_space_;

  // Populated by LoadPdbFile and modified by UpdatePdbFile.
  std::unique_ptr<pdb::PdbFile> pdb_file_;

  // These house the new values to be written when the image is zapped.
  DWORD timestamp_data_;
  DWORD pdb_age_data_;
  GUID pdb_guid_data_;

  // Controls the transform. Configured externally.
  base::FilePath input_image_;
  base::FilePath input_pdb_;
  base::FilePath output_image_;
  base::FilePath output_pdb_;
  bool write_image_;
  bool write_pdb_;
  bool overwrite_;

  DISALLOW_COPY_AND_ASSIGN(ZapTimestamp);
};

// Used to keep track of data in the image that is to be changed, and the
// new values to be written.
struct ZapTimestamp::PatchData {
  PatchData(const uint8_t* data, const base::StringPiece& name) : data(data) {
    name.CopyToString(&this->name);
  }
  const uint8_t* data;
  std::string name;
};

}  // namespace zap_timestamp

#endif  // SYZYGY_ZAP_TIMESTAMP_ZAP_TIMESTAMP_H_
