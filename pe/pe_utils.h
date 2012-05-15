// Copyright 2012 Google Inc.
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

#include "syzygy/block_graph/block_graph.h"

namespace pe {

// Typical section names.
extern const char kCodeSectionName[];
extern const char kReadOnlyDataSectionName[];
extern const char kReadWriteDataSectionName[];
extern const char kRelocSectionName[];
extern const char kResourceSectionName[];
extern const char kTlsSectionName[];

// Typical section characteristics.
extern const DWORD kCodeCharacteristics;
extern const DWORD kReadOnlyDataCharacteristics;
extern const DWORD kReadWriteDataCharacteristics;
extern const DWORD kRelocCharacteristics;

// Validates @p dos_header_block for the the size, magic constants and
// other properties of a valid DOS header.
// @returns true iff @p dos_header_block has all the correct properties
//     of a DOS header.
bool IsValidDosHeaderBlock(
    const block_graph::BlockGraph::Block* dos_header_block);

// Validates @p nt_headers_block for the the size, magic constants and
// other properties of valid NT headers.
// @returns true iff block has correct size and signature for a DOS
//     header block.
bool IsValidNtHeadersBlock(
    const block_graph::BlockGraph::Block* nt_headers_block);

// Retrieves and validates the NT headers block from a valid DOS headers block.
// @returns the NT headers block, iff it can be retrieved from the DOS headers
//     block, and if the NT headers block has valid signatures.
const block_graph::BlockGraph::Block* GetNtHeadersBlockFromDosHeaderBlock(
    const block_graph::BlockGraph::Block* dos_header_block);
block_graph::BlockGraph::Block* GetNtHeadersBlockFromDosHeaderBlock(
    block_graph::BlockGraph::Block* dos_header_block);

// Updates the provided DOS header block in preparation for writing a module
// from a BlockGraph. Trims any superfluous data and inserts a new DOS stub.
// After this has been applied IsValidDosHeaderBlock will succeed.
// @param dos_header_block the DOS header block to update.
// @returns true on success, false otherwise.
bool UpdateDosHeader(block_graph::BlockGraph::Block* dos_header_block);

}  // namespace pe

#endif  // SYZYGY_PE_PE_UTILS_H_
