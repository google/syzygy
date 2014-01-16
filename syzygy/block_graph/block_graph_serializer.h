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
  typedef core::InArchive InArchive;
  typedef core::OutArchive OutArchive;
  typedef core::RelativeAddress RelativeAddress;

  // An enumeration that governs the mode of data serialization.
  enum DataMode {
    // In this mode no block data is serialized. The data will be recovered from
    // an external data source via the LoadBlockDataCallback. While serializing
    // an optional SaveBlockDataCallback may save any metadata necessary to
    // recover the original block data.
    OUTPUT_NO_DATA,
    DEFAULT_DATA_MODE = OUTPUT_NO_DATA,

    // In this mode of serialization, only blocks that own their own data will
    // have the data serialized explicitly. The other block data will be
    // recovered via LoadBlockDataCallback, and saved via the optional
    // SaveBlockDataCallback.
    OUTPUT_OWNED_DATA,

    // In this mode all block data is serialized directly. The generated
    // serialization is completely independent of any external data sources.
    // Even if either of the callbacks are set, they will never be invoked.
    OUTPUT_ALL_DATA,

    // This needs to be last.
    DATA_MODE_MAX,
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

    // This needs to be last, and the next unused attributes enum bit.
    ATTRIBUTES_MAX = (1 << 2),
  };

  // Defines the callback used to save data for a block. The callback is given
  // the following parameters:
  //
  //   1. bool data_already_saved
  //      If this is true the block's contents have been saved explicitly in the
  //      stream.
  //   2. const BlockGraph::Block& block
  //      The block whose data is to be saved.
  //   3. OutArchive* out_archive
  //      The output archive. Can be used to write data that will then be used
  //      by LoadBlockDataCallback.
  //
  // If this callback writes any data the matching LoadBlockDataCallback must
  // read the same data. Otherwise, serialization will lose its synchronization
  // and derail. This callback is optional, but if present is called for every
  // single block. It can be used to serialize additional data alongside a
  // block.
  typedef base::Callback<bool(bool,
                              const BlockGraph::Block&,
                              core::OutArchive*)> SaveBlockDataCallback;

  // Defines the callback used to load data for a block. The callback is given
  // the following parameters:
  //
  //   1. bool need_to_set_data
  //      If this is true then the callback is responsible for filling in the
  //      block's data. Otherwise, it will already have been set by the time of
  //      this call.
  //   2. size_t data_size
  //      The size of the data that was in the block at serialization time.
  //      Can be ignored if need_to_set_data is false.
  //   3. BlockGraph::Block* block
  //      The block whose data is to be retrieved. The block will have all of
  //      its attributes set. If need_to_set_data is true then data-size will be
  //      zero and the data pointer will be null.
  //   4. InArchive* in_archive
  //      The input archive. Can be used to read data that was written by the
  //      corresponding SaveBlockDataCallback.
  //
  // The callback should read any data set by SaveBlockData. Additionally, if
  // data_size is non-zero, block->data_size is 0 and the block's data is
  // currently NULL it should also set the block's data. If the call has failed
  // it should return false. Upon return it is expected that
  // block->data_size() == data_size and that block->data() != NULL. It is up to
  // the callback to ensure that the contents match those that were there at
  // serialization time.
  //
  // If this function is provided it will be called for every single block in
  // the block-graph. It must be provided if there are any blocks whose data
  // needs to be set.
  typedef base::Callback<bool(bool,
                              size_t,
                              BlockGraph::Block*,
                              core::InArchive*)> LoadBlockDataCallback;

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

  // Sets a callback to be used by the save function for writing block
  // data. This is optional, and will only be used by the OUTPUT_NO_DATA or
  // OUTPUT_OWNED_DATA data modes.
  // @param save_block_data_callback the callback to be used.
  void set_save_block_data_callback(
      const SaveBlockDataCallback& save_block_data_callback) {
    save_block_data_callback_ = scoped_ptr<SaveBlockDataCallback>(
        new SaveBlockDataCallback(save_block_data_callback));
  }

  // Saves the given block-graph to the provided output archive.
  // @param block_graph the block-graph to be serialized.
  // @param out_archive the archive to be written to.
  // @returns true on success, false otherwise.
  bool Save(const BlockGraph& block_graph, core::OutArchive* out_archive) const;

  // Sets a callback to be used by the load function for retrieving block
  // data. This is optional, but is required to be set prior to calling Load
  // for any block-graph that was serialized using OUTPUT_NO_DATA or
  // OUTPUT_OWNED_DATA.
  // @param load_block_data_callback the callback to be used.
  void set_load_block_data_callback(
      const LoadBlockDataCallback& load_block_data_callback) {
    load_block_data_callback_ = scoped_ptr<LoadBlockDataCallback>(
        new LoadBlockDataCallback(load_block_data_callback));
  }

  // Loads a block-graph from the provided input archive. The data-mode and
  // attributes used in the serialization will also be updated. If an external
  // data source is required SetBlockDataCallback must be called prior to Load.
  // @param block_graph the block-graph to be written to.
  // @param in_archive the archive to be read from.
  // @returns true on success, false otherwise.
  bool Load(BlockGraph* block_graph, core::InArchive* in_archive);

 protected:
  // @{
  // The block-graph is serialized by breaking it down into its constituent
  // pieces, and saving each of these using the following functions.
  bool SaveBlockGraphProperties(const BlockGraph& block_graph,
                                OutArchive* out_archive) const;
  bool LoadBlockGraphProperties(uint32 version,
                                BlockGraph* block_graph,
                                InArchive* in_archive) const;

  bool SaveBlocks(const BlockGraph& block_graph, OutArchive* out_archive) const;
  bool LoadBlocks(BlockGraph* block_graph, InArchive* in_archive) const;

  bool SaveBlockGraphReferences(const BlockGraph& block_graph,
                                OutArchive* out_archive) const;
  bool LoadBlockGraphReferences(BlockGraph* block_graph,
                                InArchive* in_archive) const;

  bool SaveBlockProperties(const BlockGraph::Block& block,
                           OutArchive* out_archive) const;
  bool LoadBlockProperties(BlockGraph::Block* block,
                           InArchive* in_archive) const;

  bool SaveBlockLabels(const BlockGraph::Block& block,
                       OutArchive* out_archive) const;
  bool LoadBlockLabels(BlockGraph::Block* block, InArchive* in_archive) const;

  bool SaveBlockData(const BlockGraph::Block& block,
                     OutArchive* out_archive) const;
  bool LoadBlockData(BlockGraph::Block* block, InArchive* in_archive) const;

  bool SaveBlockReferences(const BlockGraph::Block& block,
                           OutArchive* out_archive) const;
  bool LoadBlockReferences(BlockGraph* block_graph,
                           BlockGraph::Block* block,
                           InArchive* in_archive) const;

  bool SaveReference(const BlockGraph::Reference& ref,
                     OutArchive* out_archive) const;
  bool LoadReference(BlockGraph* block_graph,
                     BlockGraph::Reference* ref,
                     InArchive* in_archive) const;
  // @}

  // @{
  // Utility functions for loading and saving integer values with a simple
  // variable-length encoding.
  bool SaveUint32(uint32 value, OutArchive* out_archive) const;
  bool LoadUint32(uint32* value, InArchive* in_archive) const;
  bool SaveInt32(int32 value, OutArchive* out_archive) const;
  bool LoadInt32(int32* value, InArchive* in_archive) const;
  // @}

  // The mode in which the serializer is operating for block data.
  DataMode data_mode_;
  // Controls the specifics of how the serialization is performed.
  Attributes attributes_;

  // Optional callbacks.
  scoped_ptr<SaveBlockDataCallback> save_block_data_callback_;
  scoped_ptr<LoadBlockDataCallback> load_block_data_callback_;
};

}  // namespace block_graph

#endif  // SYZYGY_BLOCK_GRAPH_BLOCK_GRAPH_SERIALIZER_H_
