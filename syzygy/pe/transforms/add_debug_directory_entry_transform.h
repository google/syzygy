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
// Declares the AddDebugDirectoryEntryTransform. This find or creates a debug
// directory entry of the specified type. It is intended to be used by other
// transforms.
//
// After the transform has completed the 'offset' and 'block' members functions
// point to the found or created debug directory entry with the type as
// specified in the transform constructor.

#ifndef SYZYGY_PE_TRANSFORMS_ADD_DEBUG_DIRECTORY_ENTRY_TRANSFORM_H_
#define SYZYGY_PE_TRANSFORMS_ADD_DEBUG_DIRECTORY_ENTRY_TRANSFORM_H_

#include <windows.h>

#include "base/files/file_path.h"
#include "syzygy/block_graph/transforms/named_transform.h"

namespace pe {
namespace transforms {

using block_graph::BlockGraph;
using block_graph::TransformPolicyInterface;
using block_graph::transforms::NamedBlockGraphTransformImpl;

// A PE BlockGraph transform for adding/updating the a debug directory entry
// of a given type.
class AddDebugDirectoryEntryTransform
    : public NamedBlockGraphTransformImpl<AddDebugDirectoryEntryTransform> {
 public:
  // Configures this transform.
  //
  // @param type the type of the debug directory entry to search for.
  // @param always_add if this is true a new debug directory entry will always
  //     be created, otherwise a new one will be created only if none already
  //     exists.
  AddDebugDirectoryEntryTransform(DWORD type, bool always_add)
      : type_(type), always_add_(always_add), added_(false), block_(NULL),
        offset_(-1) {
  }

  // Adds or finds the debug data directory of the given type.
  //
  // @param policy The policy object restricting how the transform is applied.
  // @param block_graph The block graph to transform.
  // @param dos_header_block The DOS header block of the block graph.
  // @returns true on success, false otherwise.
  virtual bool TransformBlockGraph(
      const TransformPolicyInterface* policy,
      BlockGraph* block_graph,
      BlockGraph::Block* dos_header_block) override;

  // Returns true if a new debug directory entry was created.
  bool added() const { return added_; }

  // Access the block containing the found or created debug directory entry.
  //
  // @returns the block housing the debug directory entry.
  BlockGraph::Block* block() const { return block_; }

  // Access the offset of the found or created debug directory entry.
  //
  // @returns the offset into the block of the debug directory entry.
  BlockGraph::Offset offset() const { return offset_; }

  // The transform name.
  static const char kTransformName[];

 private:
  // The type of the debug directory entry to find or add.
  DWORD type_;
  // If this is true a new debug directory entry will always be added, even if
  // there exists another one.
  bool always_add_;

  // These member variables hold state after the transform has been applied.

  // Indicates if a new directory entry was added.
  bool added_;
  // Stores the block housing the debug data directory entries.
  BlockGraph::Block* block_;
  // Stores the offset into the block of the found or created debug data
  // directory entry.
  BlockGraph::Offset offset_;

  DISALLOW_COPY_AND_ASSIGN(AddDebugDirectoryEntryTransform);
};

}  // namespace transforms
}  // namespace pe

#endif  // SYZYGY_PE_TRANSFORMS_ADD_DEBUG_DIRECTORY_ENTRY_TRANSFORM_H_
