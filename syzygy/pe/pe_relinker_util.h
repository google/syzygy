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
//
// Declares utilities that are common in the decomposing, transforming,
// ordering, laying out and writing of a PE image file. These utilities
// constitute the core tasks performed by the PERelinker.

#ifndef SYZYGY_PE_PE_RELINKER_UTIL_H_
#define SYZYGY_PE_PE_RELINKER_UTIL_H_

#include "base/files/file_path.h"
#include "syzygy/block_graph/ordered_block_graph.h"
#include "syzygy/pdb/pdb_file.h"
#include "syzygy/pe/image_layout.h"
#include "syzygy/pe/image_source_map.h"
#include "syzygy/pe/pe_transform_policy.h"

namespace pe {

// Validates input and output module paths, and infers/validates input and
// output PDB paths. Logs an error on failure.
// @param input_module The path to the input module.
// @param output_module The path to the output module.
// @param allow_overwrite If true then this won't check to ensure that the
//     output paths already exist.
// @param input_pdb The path to the input PDB. This may be empty, in which
//     case it will be automatically determined.
// @param output_pdb The path to the output PDB. This may be empty, in
//     which case it will be automatically determined.
// @returns true on success, false otherwise.
bool ValidateAndInferPaths(const base::FilePath& input_module,
                           const base::FilePath& output_module,
                           bool allow_overwrite,
                           base::FilePath* input_pdb,
                           base::FilePath* output_pdb);

// Finalizes a block-graph, preparing it for ordering and laying out. This
// performs the following operations:
// - Adds metadata, if requested to.
// - Update the PDB information to point to the correct PDB file.
// - Finally, run the prepare headers transform. This ensures that the
//   header block is properly sized to receive layout information
//   post-ordering.
// @param input_module The path to the original input module the block-graph
//     was built from.
// @param output_pdb The path to the PDB that will refer to the transformed
//     PE file.
// @param pdb_guid The GUID to be used in the PDB file.
// @param add_metadata If true then the block-graph will be augmented with
//     metadata describing the transforms and Syzygy toolchain.
// @param policy The policy object to be used in applying any transforms.
// @param block_graph The block-graph to be finalized.
// @param dos_header_block The DOS header block in the block-graph.
// @returns true on success, false otherwise.
bool FinalizeBlockGraph(const base::FilePath& input_module,
                        const base::FilePath& output_pdb,
                        const GUID& pdb_guid,
                        bool add_metadata,
                        const PETransformPolicy* policy,
                        block_graph::BlockGraph* block_graph,
                        block_graph::BlockGraph::Block* dos_header_block);

// Finalizes an ordered block-graph, preparing it for laying out. This simply
// runs the PEOrderer which ensures that PE structures are in the appropriate
// places.
// @param ordered_block_graph The ordered block-graph to be finalized.
// @param dos_header_block The DOS header block in the block-graph.
// @returns true on success, false otherwise.
bool FinalizeOrderedBlockGraph(
    block_graph::OrderedBlockGraph* ordered_block_graph,
    block_graph::BlockGraph::Block* dos_header_block);

// Builds an image layout for an ordered block-graph.
// @param padding The minimum amount of padding to apply between blocks.
// @param code_alignment The minimum alignment to enforce for code blocks.
// @param ordered_block_graph The image to be laid out.
// @param dos_header_block The DOS header block in the image.
// @param image_layout The image-layout to be populated.
// @returns true on success, false otherwise.
bool BuildImageLayout(size_t padding,
                      size_t code_alignment,
                      const block_graph::OrderedBlockGraph& ordered_block_graph,
                      block_graph::BlockGraph::Block* dos_header_block,
                      ImageLayout* image_layout);

// Given the sections from an image layout calculates the source range that any
// derived OMAP information must cover. This should be calculated on the
// original untransformed image.
// @param sections The array of sections describing the original image.
// @param range The range to be populated.
void GetOmapRange(const std::vector<ImageLayout::SectionInfo>& sections,
                  RelativeAddressRange* range);

// Given a transformed PDB file, finalizes it in preparation for writing. This
// performs the following tasks:
// - Sets the new GUID and clears the age count of the PDB to 1.
// - Calculates OMAP information and injects it into the PDB.
// - Adds/updates the Syzygy history stream which contains a record of
//   operations performed by the toolchain.
// - If requested, serializes the block-graph to the PDB in an additional
//   stream.
// - Finalizes the PDB header.
// - Removes stream 0, the previous PDB directory stream.
// @param input_module The path to the original input module.
// @param output_module The path to the transformed output module.
// @param input_range The input range of the original image, as calculated by
//     GetOmapRange.
// @param image_layout The transformed image layout.
// @param guid The guid of the new PDB.
// @param augment_pdb If true then the serialized block-graph will be emitted to
//     the PDB.
// @param strip_strings If true then all strings will be stripped from the
//     serialized block-graph, to save on space. Has no effect unless
//     @p augment_pdb is true.
// @param compress_pdb If true then the serialized block-graph will be
//     compressed. Has no effect unless @p augment_pdb is true.
// @param pdb_file The decomposed original PDB file to be updated.
// @returns true on success, false otherwise.
// @pre The transformed PE file must already have been written and finalized
//     prior to calling this.
bool FinalizePdbFile(const base::FilePath input_module,
                     const base::FilePath output_module,
                     const RelativeAddressRange input_range,
                     const ImageLayout& image_layout,
                     const GUID& guid,
                     bool augment_pdb,
                     bool strip_strings,
                     bool compress_pdb,
                     pdb::PdbFile* pdb_file);

}  // namespace pe

#endif  // SYZYGY_PE_PE_RELINKER_UTIL_H_
