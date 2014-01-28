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

#ifndef SYZYGY_PE_SERIALIZATION_H_
#define SYZYGY_PE_SERIALIZATION_H_

#include "base/files/file_path.h"
#include "syzygy/block_graph/block_graph_serializer.h"
#include "syzygy/core/serialization.h"
#include "syzygy/pe/pe_file.h"

namespace pe {

// Forward declarations.
struct ImageLayout;

// Serializes the decomposition of a PE file, as represented by a BlockGraph
// and an ImageLayout. The @p pe_file must correspond exactly to the
// @p block_graph and @p image_layout pair.
// @param pe_file the PE file that the decomposition represents.
// @param attributes the attributes to be used in serializing @p block_graph.
// @param image_layout the layout of @p block_graph in @p pe_file.
// @param out_archive the archive object to receive the serialized
//     decomposition.
// @returns true on success, false otherwise.
bool SaveBlockGraphAndImageLayout(
    const PEFile& pe_file,
    block_graph::BlockGraphSerializer::Attributes attributes,
    const ImageLayout& image_layout,
    core::OutArchive* out_archive);

// Deserializes the decomposition of a PE file, as represented by a BlockGraph
// and an ImageLayout. If already initialized, @p pe_file must correspond
// exactly to the one referred to by the serialized contents of @p in_archive.
// @param attributes the attributes used in serializing the block-graph. This
//     may be NULL.
// @param pe_file the PE file that the decomposition represents.
//     As a const reference, this will be used strictly for
//     setting data pointers, and no search will be performed. If the provided
//     PEFile does not match the metadata in the serialized stream then the
//     call will fail.
//     As a pointer, the use is different. If the PEFile has already been
//     initialized and it matches the signature of the PE file referred to in
//     the archive, it will be used to populate block data. Otherwise, a search
//     for a matching PE file will be launched and this will be initialized to
//     that PE file, if found.
// @param image_layout the layout of @p block_graph in @p pe_file.
// @param in_archive the archive object storing the serialized block-graph and
//     image layout.
// @returns true on success, false otherwise.
bool LoadBlockGraphAndImageLayout(
    const PEFile& pe_file,
    block_graph::BlockGraphSerializer::Attributes* attributes,
    ImageLayout* image_layout,
    core::InArchive* in_archive);
bool LoadBlockGraphAndImageLayout(
    PEFile* pe_file,
    block_graph::BlockGraphSerializer::Attributes* attributes,
    ImageLayout* image_layout,
    core::InArchive* in_archive);

}  // namespace pe

#endif  // SYZYGY_PE_SERIALIZATION_H_
