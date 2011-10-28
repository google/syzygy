// Copyright 2011 Google Inc.
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

#ifndef SYZYGY_PE_PE_UTILS_H_
#define SYZYGY_PE_PE_UTILS_H_

#include <windows.h>
#include <winnt.h>

#include "syzygy/core/block_graph.h"

namespace pe {

// Validates @p dos_header_block for the the size, magic constants and
// other properties of a valid DOS header.
// @returns true iff @p dos_header_block has all the correct properties
//     of a DOS header.
bool IsValidDosHeaderBlock(const core::BlockGraph::Block* dos_header_block);

// Validates @p nt_headers_block for the the size, magic constants and
// other properties of valid NT headers.
// @returns true iff block has correct size and signature for a DOS
//     header block.
bool IsValidNtHeadersBlock(const core::BlockGraph::Block* nt_headers_block);

// Retrieves and validates the NT headers block from a valid DOS headers block.
// @returns the NT headers block, iff it can be retrieved from the DOS headers
//     block, and if the NT headers block has valid signatures.
const core::BlockGraph::Block* GetNtHeadersBlockFromDosHeaderBlock(
    const core::BlockGraph::Block* dos_header_block);
core::BlockGraph::Block* GetNtHeadersBlockFromDosHeaderBlock(
    core::BlockGraph::Block* dos_header_block);

}  // namespace pe

#endif  // SYZYGY_PE_PE_UTILS_H_
