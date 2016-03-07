// Copyright 2015 Google Inc. All Rights Reserved.
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
// Declares the data structures that will be injected into images transformed
// by hot patching transformations. These data structures contain the necessary
// metadata that is required to perform the hot patching of blocks at runtime.

#ifndef SYZYGY_BLOCK_GRAPH_HOT_PATCHING_METADATA_H_
#define SYZYGY_BLOCK_GRAPH_HOT_PATCHING_METADATA_H_

#include <vector>


namespace block_graph {

// Ensure there are no padding bytes because these structs are going to be
// written to the .syzyhp stream directly.
#pragma pack(push, 1)

// This data structure describes a single Block in the HotPatchingMetadata.
struct HotPatchingBlockMetadata {
  // The RVA of the start of the block.
  uint32_t relative_address;

  // The size of the code in the block data.
  uint16_t code_size;

  // The size of the block data.
  uint16_t block_size;
};

// This struct contains the data that will be injected into images transformed
// by hot patching transformations, it contains the necessary metadata that is
// required to perform the hot patching of blocks at runtime.
struct HotPatchingMetadataHeader {
  // Version information.
  uint32_t version;

  // Number of HotPatchingBlockMetadata structures to follow.
  uint32_t number_of_blocks;
};

#pragma pack(pop)

// The current version of the HotPatchingMetadata structure. This needs to
// be incremented if any time a non-backwards compatible change is made to the
// serialization format.
const uint32_t kHotPatchingMetadataVersion = 1U;

}  // namespace block_graph

#endif  // SYZYGY_BLOCK_GRAPH_HOT_PATCHING_METADATA_H_
