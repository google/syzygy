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
// Declares a Filterable object, which can be given a RelativeAddressFilter to
// be respected while doing its work.

#ifndef SYZYGY_BLOCK_GRAPH_FILTERABLE_H_
#define SYZYGY_BLOCK_GRAPH_FILTERABLE_H_

#include "syzygy/block_graph/filter_util.h"

namespace block_graph {

class Filterable {
 public:
  Filterable() : filter_(NULL) { }
  explicit Filterable(const RelativeAddressFilter* filter) : filter_(filter) { }

  // Sets the filter to be used by this object.
  // @param filter The filter to use. May be NULL.
  void set_filter(const RelativeAddressFilter* filter) {
    filter_ = filter;
  }

  // Returns the filter currently used by this object.
  const RelativeAddressFilter* filter() const { return filter_; }

  // Determines if the given object is filtered.
  // @param basic_block The basic block to be checked.
  // @returns true if the object filtered, false otherwise.
  // @note If no filter is specified this always returns false.
  bool IsFiltered(const block_graph::BlockGraph::Block* block) const;
  bool IsFiltered(const block_graph::BasicBlock* basic_block) const;
  bool IsFiltered(const block_graph::BasicCodeBlock* basic_block) const;
  bool IsFiltered(const block_graph::BasicDataBlock* basic_block) const;
  bool IsFiltered(const block_graph::Instruction& instruction) const;

 private:
  const RelativeAddressFilter* filter_;

  DISALLOW_COPY_AND_ASSIGN(Filterable);
};

}  // namespace block_graph

#endif  // SYZYGY_BLOCK_GRAPH_FILTERABLE_H_
