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
//
// Declares a helper class for serializing a block-graph.

#ifndef SYZYGY_BLOCK_GRAPH_BLOCK_GRAPH_SERIALIZER_H_
#define SYZYGY_BLOCK_GRAPH_BLOCK_GRAPH_SERIALIZER_H_

#include "base/basictypes.h"
#include "base/callback.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/core/address.h"

namespace block_graph {

// A class for serializing a block-graph.
class BlockGraphSerializer {
 public:
  typedef uint32 Attributes;
  typedef core::RelativeAddress RelativeAddress;

  // An enumeration that governs the mode of data serialization.
  enum DataMode {
    // In this mode no block data is serialized. The data will be recovered from
    // an external data source.
    OUTPUT_NO_DATA,
    DEFAULT_DATA_MODE = OUTPUT_NO_DATA,

    // In this mode of serialization, only blocks that own their own data will
    // will have the data serialized explicitly. The other block data will be
    // recovered from an external data source.
    OUTPUT_OWNED_DATA,

    // In this mode all block data is serialized. The generated serialization
    // is completely independent of any external data sources.
    OUTPUT_ALL_DATA,
  };

  // Attributes that govern the serializer behaviour.
  enum AttributesEnum {
    // The serializer uses default behaviour.
    DEFAULT_ATTRIBUTES = 0,

    // If specified then no strings will be written as part of the
    // serialization (block names, label names). They are useful as debugging
    // information, but not required by any transforms.
    OMIT_STRINGS = (1 << 0),

    // If specified then all labels will be omitted from the serialization.
    // They are not needed for block level motion, but this will make basic
    // block disassembly impossible.
    OMIT_LABELS = (1 << 1),
  };

  // Defines the callback used to get data for a block. The callback is given
  // the following parameter:
  //   1. size_t data_size
  //      The size of the data that was in the block at serialization time.
  //   2. BlockGraph::Block* block
  //      The block whose data is to be retrieved. The block will have all of
  //      its attributes set except the data-size will be zero and the data
  //      pointer will be null.
  // The callback should set the data associated with the block and return
  // true on success. If the call has failed it should return false. Upon
  // return it is expected that block->data_size() == data_size and that
  // block->data() != NULL. It is up to the callback to ensure that the contents
  // match those that were there at serialization time.
  typedef base::Callback<bool(BlockGraph::Block*)> BlockDataCallback;

  // Default constructor.
  BlockGraphSerializer()
      : data_mode_(DEFAULT_DATA_MODE), attributes_(DEFAULT_ATTRIBUTES) { }

  // @name For setting and accessing the data mode.
  // @{
  DataMode data_mode() const { return data_mode_; }
  void set_data_mode(DataMode data_mode) { data_mode_ = data_mode; }
  // @}

  // @name For setting and accessing attributes.
  // @{
  // Adds new attributes, combining them with the existing attributes.
  // @param attr the attributes to add.
  void add_attributes(Attributes attr) { attributes_ |= attr; }
  // Clears the given attributes, removing them from the existing attributes.
  // @param attr the attributes to clear.
  void clear_attributes(Attributes attr) { attributes_ &= ~attr; }
  // Sets the attributes wholesale.
  // @param attr the new attributes to use.
  void set_attributes(Attributes attr) { attributes_ = attr; }
  // @returns the current attributes.
  Attributes attributes() const { return attributes_; }
  // Determines if all the given attributes are set.
  // @param attr the attributes to check for.
  // @returns true if all attributes in @p attr are set.
  bool has_attributes(Attributes attr) const {
    return (attributes_ & attr) == attr;
  }
  // Determines if any of the given attributes are set.
  // @param attr the attributes to check for.
  // @returns true if any of the attributes in @p attr are set.
  bool has_any_attributes(Attributes attr) const {
    return (attributes_ & attr) != 0;
  }
  // @}

  // Saves the given block-graph to the provided output archive.
  // @param block_graph the block-graph to be serialized.
  // @param out_archive the archive to be written to.
  // @returns true on success, false otherwise.
  bool Save(const BlockGraph& block_graph, core::OutArchive* out_archive) const;

  // Sets a callback to be used by the load function for retrieving block
  // data. This is optional, but is required to be set prior to calling Load
  // for any block-graph that was serialized using OUTPUT_NO_DATA or
  // OUTPUT_OWNED_DATA.
  void set_block_data_callback(const BlockDataCallback& block_data_callback) {
    block_data_callback_ = scoped_ptr<BlockDataCallback>(
        new BlockDataCallback(block_data_callback));
  }

  // Loads a block-graph from the provided input archive. The data-mode and
  // attributes used in the serialization will also be updated. If an external
  // data source is required SetBlockDataCallback must be called prior to Load.
  // @param block_graph the block-graph to be written to.
  // @param in_archive the archive to be read from.
  // @returns true on success, false otherwise.
  bool Load(BlockGraph* block_graph, core::InArchive* in_archive);

 private:
  // The mode in which the serializer is operating for block data.
  DataMode data_mode_;
  // Controls the specifics of how the serialization is performed.
  Attributes attributes_;

  // The optional callback to be used for getting block data from an external
  // source.
  scoped_ptr<BlockDataCallback> block_data_callback_;
};

}  // namespace block_graph

#endif  // SYZYGY_BLOCK_GRAPH_BLOCK_GRAPH_SERIALIZER_H_
