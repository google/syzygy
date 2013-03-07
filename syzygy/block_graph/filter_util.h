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
// Declares helper functions for dealing with filters and determining whether or
// not a given block, basic block or instruction should be instrumented or
// transformed.

#ifndef SYZYGY_BLOCK_GRAPH_FILTER_UTIL_H_
#define SYZYGY_BLOCK_GRAPH_FILTER_UTIL_H_

#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/core/address_filter.h"

namespace block_graph {

typedef core::AddressFilter<core::RelativeAddress, size_t>
    RelativeAddressFilter;

// Determines if the given @p block is filtered. A block is filtered if any of
// it's source data is marked in the filter.
// @param filter The filter to be checked.
// @param block The block to be checked.
// @returns true if the block is filtered, false otherwise.
bool IsFiltered(const RelativeAddressFilter& filter,
                const block_graph::BlockGraph::Block* block);

// Determines if the given @p basic_block is filtered. A basic block is filtered
// if any of its source data is marked in the filter.
// @param filter The filter to be checked.
// @param basic_block The basic block to be checked.
// @returns true if the basic block is filtered, false otherwise.
bool IsFiltered(const RelativeAddressFilter& filter,
                const block_graph::BasicBlock* basic_block);
bool IsFiltered(const RelativeAddressFilter& filter,
                const block_graph::BasicCodeBlock* basic_block);
bool IsFiltered(const RelativeAddressFilter& filter,
                const block_graph::BasicDataBlock* basic_block);

// Determines if the given instruction is filtered. An instruction is filtered
// if any of its source data is marked in the given filter.
// @param filter The filter to be checked.
// @param instruction The instruction to be checked.
// @returns true if the instruction is filtered, false otherwise.
bool IsFiltered(const RelativeAddressFilter& filter,
                const block_graph::Instruction& instruction);

}  // namespace block_graph

#endif  // SYZYGY_BLOCK_GRAPH_FILTER_UTIL_H_
