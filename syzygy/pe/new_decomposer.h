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
// Declares the decomposer, which decomposes a PE file into an ImageLayout and
// its corresponding BlockGraph.
//
// TODO(chrisha): When the new decomposer is ready, swap out the old for the
//     new and rename this.

#ifndef SYZYGY_PE_NEW_DECOMPOSER_H_
#define SYZYGY_PE_NEW_DECOMPOSER_H_

#include <vector>

#include "syzygy/pdb/pdb_file.h"
#include "syzygy/pdb/pdb_stream.h"
#include "syzygy/pe/image_layout.h"
#include "syzygy/pe/pe_file.h"

namespace pe {

class NewDecomposer {
 public:
  // Initialize the decomposer for a given image file.
  // @param image_file the image file to decompose. This must outlive the
  //     instance of the decomposer.
  explicit NewDecomposer(const PEFile& image_file);

  // Decomposes the image file into a BlockGraph and an ImageLayout, which
  // have the breakdown of code and data blocks with typed references and
  // information on where the blocks resided in the original image,
  // respectively.
  // @returns true on success, false on failure.
  bool Decompose(ImageLayout* image_layout);

  // Sets the PDB path to be used. If this is not called it will be inferred
  // using the information in the module, and searched for using the OS
  // search functionality.
  // @param pdb_path the path to the PDB file to be used in decomposing the
  //     image.
  void set_pdb_path(const FilePath& pdb_path) { pdb_path_ = pdb_path; }

  // Accessor to the PDB path. If Decompose has been called successfully this
  // will reflect the path of the PDB file that was used to perform the
  // decomposition.
  // @returns the PDB path.
  const FilePath& pdb_path() const { return pdb_path_; }

 protected:
  typedef block_graph::BlockGraph BlockGraph;
  typedef core::RelativeAddress RelativeAddress;

  // Searches for (if necessary) the PDB file to be used in the decomposition,
  // and validates that the file exists and matches the module.
  bool FindAndValidatePdbPath();

  // @name Used for round-trip decomposition when a serialized block graph is
  //     in the PDB. Exposed here for unittesting.
  // @{
  static bool LoadBlockGraphFromPdbStream(const PEFile& image_file,
                                          pdb::PdbStream* block_graph_stream,
                                          ImageLayout* image_layout);
  static bool LoadBlockGraphFromPdb(const FilePath& pdb_path,
                                    const PEFile& image_file,
                                    ImageLayout* image_layout,
                                    bool* stream_exists);
  // @}

  // @name Decomposition steps.
  // @{
  // Performs the actual decomposition.
  bool DecomposeImpl();
  // Creates sections in the block-graph corresponding to those in the image.
  bool CreateBlockGraphSections();
  // @}

  // The PEFile that is being decomposed.
  const PEFile& image_file_;
  // The path to corresponding PDB file.
  FilePath pdb_path_;

  // @name Temporaries that are only valid while inside DecomposeImpl.
  //     Prevents us from having to pass these around everywhere.
  // The image layout we're building.
  // @{
  ImageLayout* image_layout_;
  // The image address space we're decomposing to.
  BlockGraph::AddressSpace* image_;
  // @}
};

}  // namespace pe

#endif  // SYZYGY_PE_NEW_DECOMPOSER_H_
