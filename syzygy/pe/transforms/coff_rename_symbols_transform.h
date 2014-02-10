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
// Declares a transform for renaming symbols in COFF files. A symbol is a
// named object to be defined by another translation unit. Renaming them is
// equivalent to redirecting an import for a PE file. This is used by some
// instrumentation methods to redirect functions to instrumented equivalents.

#ifndef SYZYGY_PE_TRANSFORMS_COFF_RENAME_SYMBOLS_TRANSFORM_H_
#define SYZYGY_PE_TRANSFORMS_COFF_RENAME_SYMBOLS_TRANSFORM_H_

#include <map>

#include "base/strings/string_piece.h"
#include "syzygy/block_graph/transforms/named_transform.h"

namespace pe {
namespace transforms {

// A transform for renaming COFF symbols in a given block graph.
class CoffRenameSymbolsTransform
    : public block_graph::transforms::NamedBlockGraphTransformImpl<
          CoffRenameSymbolsTransform> {
 public:
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::TransformPolicyInterface TransformPolicyInterface;

  // Construct an empty CoffRenameSymbolsTransform; initially, no symbol is
  // set to be renamed. By default, the input symbol of any specified mapping
  // must exist, otherwise the transform will fail.
  CoffRenameSymbolsTransform() : symbols_must_exist_(true) {}

  // Add the specified mapping to be applied.
  // @param from the symbol to rename.
  // @param to the replacement symbol name.
  void AddSymbolMapping(const base::StringPiece& from,
                        const base::StringPiece& to);

  // Perform the transform. Rename symbols according to the mappings
  // previously added.
  // @param policy the policy object restricting how the transform is applied.
  // @param block_graph the BlockGraph to transform.
  // @param headers_block the block containing the headers.
  // @returns true on success, false otherwise.
  virtual bool TransformBlockGraph(
      const TransformPolicyInterface* policy,
      BlockGraph* block_graph,
      BlockGraph::Block* headers_block) OVERRIDE;

  // The name of this transform.
  static const char kTransformName[];

  // @name Accessors and mutators.
  // @{
  bool symbols_must_exist() const { return symbols_must_exist_; }
  void set_symbols_must_exist(bool symbols_must_exist) {
    symbols_must_exist_ = symbols_must_exist;
  }
  // @}

 protected:
  typedef std::vector<std::pair<std::string, std::string>> SymbolMap;
  SymbolMap mappings_;
  bool symbols_must_exist_;

  DISALLOW_COPY_AND_ASSIGN(CoffRenameSymbolsTransform);
};

}  // namespace transforms
}  // namespace pe

#endif  // SYZYGY_PE_TRANSFORMS_COFF_RENAME_SYMBOLS_TRANSFORM_H_
