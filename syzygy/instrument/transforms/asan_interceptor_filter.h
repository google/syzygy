// Copyright 2014 Google Inc. All Rights Reserved.
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
// Declaration of the AsanInterceptorFilter class.
#ifndef SYZYGY_INSTRUMENT_TRANSFORMS_ASAN_INTERCEPTOR_FILTER_H_
#define SYZYGY_INSTRUMENT_TRANSFORMS_ASAN_INTERCEPTOR_FILTER_H_

#include <map>
#include <set>
#include <string>

#include "syzygy/block_graph/block_graph.h"
#include "syzygy/instrument/transforms/asan_intercepts.h"

namespace instrument {
namespace transforms {

// This class defines a filter for the functions that should be intercepted by
// the Asan transform. The list of the functions to intercept is stored in a map
// associating the function name to one or several hashes of the expected block
// contents.
//
// It's not sufficient to only filter the function by its name because some
// linker optimizations can result in a function being stubbed by a block with
// the same name but with a different calling convention.
class AsanInterceptorFilter {
 public:
  virtual ~AsanInterceptorFilter() { }

  // Loads the hashes of the intercepted functions into the map.
  // @param intercepts a NULL terminated array of intercept descriptors to be
  //     parsed.
  // @param parse_optional_intercepts If true then functions marked as optional
  //     intercepts will be parsed. Otherwise, only mandatory intercepts will
  //     be parsed.
  void InitializeContentHashes(const AsanIntercept* intercepts,
                               bool parse_optional_intercepts);

  // Indicates if a block should be intercepted.
  // @param block The block for which we want to know if it should be
  //     intercepted.
  // @returns true if the block should be intercepted, false otherwise.
  bool ShouldIntercept(const block_graph::BlockGraph::Block* block);

  bool empty() const { return function_hash_map_.empty(); }

 protected:
  typedef std::set<std::string> HashSet;
  typedef std::map<std::string, HashSet> FunctionHashMap;

  // Add a block to the function hash map.
  // @param block The block that we want to add to the function hash map.
  // @note This is exposed for unit testing.
  void AddBlockToHashMap(block_graph::BlockGraph::Block* block);

  // The map containing the name and the hashes of the functions that should be
  // intercepted. Some functions have several hashes in order to support
  // different versions of the CRT (e.g VS2010 and VS2013).
  FunctionHashMap function_hash_map_;
};

}  // namespace transforms
}  // namespace instrument

#endif  // SYZYGY_INSTRUMENT_TRANSFORMS_ASAN_INTERCEPTOR_FILTER_H_
