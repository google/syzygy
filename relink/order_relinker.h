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

#ifndef SYZYGY_RELINK_ORDER_RELINKER_H_
#define SYZYGY_RELINK_ORDER_RELINKER_H_

#include "syzygy/relink/relinker.h"

namespace relink {

class OrderRelinker : public Relinker {
 public:
  enum BlockInitType {
    INITIALIZED_BLOCKS,
    UNINITIALIZED_BLOCKS,
    ALL_BLOCKS
  };

  explicit OrderRelinker(const FilePath& order_file_path);

 private:
  DISALLOW_COPY_AND_ASSIGN(OrderRelinker);

  typedef std::set<const BlockGraph::Block*> BlockSet;
  typedef Reorderer::Order::BlockList BlockList;

  // Overrides for base class methods.
  bool SetupOrdering(const PEFile& pe_file,
                     const DecomposedImage& image,
                     Reorderer::Order* order) OVERRIDE;
  bool ReorderSection(size_t section_index,
                      const ImageLayout::SegmentInfo& section,
                      const Reorderer::Order& order) OVERRIDE;

  // Outputs a padding block. Automatically determines whether or not to output
  // initialized or blank padding.
  bool OutputPadding(BlockInitType block_init_type,
                     BlockGraph::BlockType block_type,
                     size_t size,
                     RelativeAddress* insert_at);

  // Outputs blocks of a given type to the section.
  bool OutputBlocks(BlockInitType block_init_type,
                    const ImageLayout::SegmentInfo& section,
                    const BlockList& block_order,
                    BlockSet* inserted_blocks,
                    RelativeAddress* insert_at);

  // The JSON encoded file with the new ordering.
  FilePath order_file_path_;
};

}  // namespace relink

#endif  // SYZYGY_RELINK_ORDER_RELINKER_H_
