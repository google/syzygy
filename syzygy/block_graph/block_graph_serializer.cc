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

#include "syzygy/block_graph/block_graph_serializer.h"

#include "base/strings/stringprintf.h"

namespace block_graph {

namespace {

using core::InArchive;
using core::OutArchive;

// This needs to be incremented any time a non-backwards compatible change
// is made to the serialization format.
// TODO(chrisha): Enforce this via a unittest. Check in a version of a
//     simple block-graph, and ensure it deserializes to the same in-memory
//     representation.
// Version 3: Added image_format_ block-graph property.
// Version 4: Deprecated old decomposer attributes.
static const uint32 kSerializedBlockGraphVersion = 4;

// Some constants for use in dealing with backwards compatibility.
static const uint32 kMinSupportedSerializedBlockGraphVersion = 2;
static const uint32 kImageFormatPropertyBlockGraphVersion = 3;

// Potentially saves a string, depending on whether or not OMIT_STRINGS is
// enabled.
bool MaybeSaveString(const BlockGraphSerializer& bgs,
                     const std::string& value,
                     OutArchive* out_archive) {
  DCHECK(out_archive != NULL);

  if (bgs.has_attributes(BlockGraphSerializer::OMIT_STRINGS))
    return true;

  if (!out_archive->Save(value)) {
    LOG(ERROR) << "Unable to save string \"" << value << "\".";
    return false;
  }

  return true;
}

// Potentially loads a string, depending on whether or not OMIT_STRINGS is
// enabled.
bool MaybeLoadString(const BlockGraphSerializer& bgs,
                     std::string* value,
                     InArchive* in_archive) {
  DCHECK(value != NULL);
  DCHECK(in_archive != NULL);

  if (bgs.has_attributes(BlockGraphSerializer::OMIT_STRINGS))
    return true;

  if (!in_archive->Load(value)) {
    LOG(ERROR) << "Unable to load string.";
    return false;
  }

  return true;
}

bool ValidAttributes(uint32 attributes, uint32 attributes_max) {
  return (attributes & ~(attributes_max - 1)) == 0;
}

}  // namespace

bool BlockGraphSerializer::Save(const BlockGraph& block_graph,
                                core::OutArchive* out_archive) const {
  CHECK(out_archive != NULL);

  // Save the serialization attributes so we can read this block-graph without
  // having to be told how it was saved.
  if (!out_archive->Save(kSerializedBlockGraphVersion) ||
      !out_archive->Save(static_cast<uint32>(data_mode_)) ||
      !out_archive->Save(attributes_)) {
    LOG(ERROR) << "Unable to save serialized block-graph properties.";
    return false;
  }

  // TODO(etienneb): We should serialize the string table in the block graph,
  //    and encode string ids instead of the raw strings.

  // This function takes care of outputting a meaningful log message on
  // failure.
  if (!SaveBlockGraphProperties(block_graph, out_archive))
    return false;

  // Save the blocks, except for their references. We do that in a second pass
  // so that when loading the referenced blocks will exist.
  if (!SaveBlocks(block_graph, out_archive)) {
    LOG(ERROR) << "Unable to save blocks.";
    return false;
  }

  // Save all of the references. The referrers are implicitly saved by this.
  if (!SaveBlockGraphReferences(block_graph, out_archive)) {
    LOG(ERROR) << "Unable to save block graph references.";
    return false;
  }

  return true;
}

bool BlockGraphSerializer::Load(BlockGraph* block_graph,
                                core::InArchive* in_archive) {
  CHECK(block_graph != NULL);
  CHECK(in_archive != NULL);

  uint32 version = 0;
  if (!in_archive->Load(&version)) {
    LOG(ERROR) << "Unable to load serialized block graph version.";
    return false;
  }

  // We are backwards compatible back to version 2, for now.
  if (version < kMinSupportedSerializedBlockGraphVersion ||
      version > kSerializedBlockGraphVersion) {
    LOG(ERROR) << "Unable to load block graph with version " << version << ".";
    return false;
  }

  // Read the serialization attributes and mode information so that we know how
  // to load the block-graph.
  uint32 data_mode = 0;
  if (!in_archive->Load(&data_mode) || !in_archive->Load(&attributes_)) {
    LOG(ERROR) << "Unable to load serialized block-graph properties.";
    return false;
  }
  data_mode_ = static_cast<DataMode>(data_mode);

  // Ensure that the data mode and the attributes are valid.
  if (data_mode_ >= DATA_MODE_MAX ||
      !ValidAttributes(attributes_, ATTRIBUTES_MAX)) {
    LOG(ERROR) << "Invalid data mode and/or attributes.";
    return false;
  }

  // This function takes care of outputting a meaningful log message on
  // failure.
  if (!LoadBlockGraphProperties(version, block_graph, in_archive))
    return false;

  // Load the blocks, except for their references.
  if (!LoadBlocks(block_graph, in_archive)) {
    LOG(ERROR) << "Unable to load blocks.";
    return false;
  }

  // Now load the references and wire them up.
  if (!LoadBlockGraphReferences(block_graph, in_archive)) {
    LOG(ERROR) << "Unable to load block graph references.";
    return false;
  }

  return true;
}

bool BlockGraphSerializer::SaveBlockGraphProperties(
    const BlockGraph& block_graph,
    OutArchive* out_archive) const {
  DCHECK(out_archive != NULL);

  if (!out_archive->Save(block_graph.next_section_id_) ||
      !out_archive->Save(block_graph.sections_) ||
      !out_archive->Save(block_graph.next_block_id_) ||
      !out_archive->Save(static_cast<uint8>(block_graph.image_format_))) {
    LOG(ERROR) << "Unable to save block graph properties.";
    return false;
  }

  return true;
}

bool BlockGraphSerializer::LoadBlockGraphProperties(
    uint32 version, BlockGraph* block_graph, InArchive* in_archive) const {
  DCHECK(block_graph != NULL);
  DCHECK(in_archive != NULL);

  // The block graph properties should be empty.
  DCHECK_EQ(0u, block_graph->next_section_id_);
  DCHECK_EQ(0u, block_graph->sections_.size());
  DCHECK_EQ(0u, block_graph->next_block_id_);

  if (!in_archive->Load(&block_graph->next_section_id_) ||
      !in_archive->Load(&block_graph->sections_) ||
      !in_archive->Load(&block_graph->next_block_id_)) {
    LOG(ERROR) << "Unable to load block graph properties.";
    return false;
  }

  // Read the image format property. This is not present in all versions of the
  // block-graph.
  uint8 image_format = 0;
  if (version >= kImageFormatPropertyBlockGraphVersion) {
    if (!in_archive->Load(&image_format)) {
      LOG(ERROR) << "Unable to load block graph image format.";
      return false;
    }
  } else {
    // We default to the PE format, as COFF images were not previously
    // supported.
    image_format = BlockGraph::PE_IMAGE;
  }
  block_graph->image_format_ = static_cast<BlockGraph::ImageFormat>(
      image_format);

  return true;
}

bool BlockGraphSerializer::SaveBlocks(const BlockGraph& block_graph,
                                      OutArchive* out_archive) const {
  DCHECK(out_archive != NULL);

  if (!out_archive->Save(block_graph.blocks().size())) {
    LOG(ERROR) << "Unable to save block count.";
    return false;
  }

  // Output the basic block properties first.
  BlockGraph::BlockMap::const_iterator it = block_graph.blocks_.begin();
  for (; it != block_graph.blocks_.end(); ++it) {
    BlockGraph::BlockId block_id = it->first;
    const BlockGraph::Block& block = it->second;
    if (!out_archive->Save(block_id) ||
        !SaveBlockProperties(block, out_archive) ||
        !SaveBlockLabels(block, out_archive) ||
        !SaveBlockData(block, out_archive)) {
      LOG(ERROR) << "Unable to save block with id " << block_id << ".";
      return false;
    }
  }

  return true;
}

bool BlockGraphSerializer::LoadBlocks(BlockGraph* block_graph,
                                      InArchive* in_archive) const {
  DCHECK(block_graph != NULL);
  DCHECK(in_archive != NULL);

  DCHECK_EQ(0u, block_graph->blocks_.size());

  size_t count = 0;
  if (!in_archive->Load(&count)) {
    LOG(ERROR) << "Unable to load block count.";
    return false;
  }

  for (size_t i = 0; i < count; ++i) {
    BlockGraph::BlockId id = 0;
    if (!in_archive->Load(&id)) {
      LOG(ERROR) << "Unable to load id for block " << i << " of " << count
                 << ".";
      return false;
    }

    std::pair<BlockGraph::BlockMap::iterator, bool> result =
        block_graph->blocks_.insert(
            std::make_pair(id, BlockGraph::Block(block_graph)));
    if (!result.second) {
      LOG(ERROR) << "Unable to insert block with id " << id << ".";
      return false;
    }
    BlockGraph::Block* block = &result.first->second;
    block->id_ = id;

    if (!LoadBlockProperties(block, in_archive) ||
        !LoadBlockLabels(block, in_archive) ||
        !LoadBlockData(block, in_archive)) {
      LOG(ERROR) << "Unable to load block " << i << " of " << count
                 << " with id " << id << ".";
      return false;
    }
  }
  DCHECK_EQ(count, block_graph->blocks_.size());

  return true;
}

bool BlockGraphSerializer::SaveBlockGraphReferences(
    const BlockGraph& block_graph, OutArchive* out_archive) const {
  DCHECK(out_archive != NULL);

  BlockGraph::BlockMap::const_iterator it = block_graph.blocks().begin();
  for (; it != block_graph.blocks().end(); ++it) {
    if (!SaveBlockReferences(it->second, out_archive)) {
      LOG(ERROR) << "Unable to save references for block with id "
                 << it->second.id() << ".";
      return false;
    }
  }

  return true;
}

bool BlockGraphSerializer::LoadBlockGraphReferences(
    BlockGraph* block_graph, InArchive* in_archive) const {
  DCHECK(block_graph != NULL);
  DCHECK(in_archive != NULL);

  BlockGraph::BlockMap::iterator it = block_graph->blocks_mutable().begin();
  for (; it != block_graph->blocks_mutable().end(); ++it) {
    if (!LoadBlockReferences(block_graph, &it->second, in_archive)) {
      LOG(ERROR) << "Unable to load references for block with id "
                 << it->second.id() << ".";
      return false;
    }
  }

  return true;
}

bool BlockGraphSerializer::SaveBlockProperties(const BlockGraph::Block& block,
                                               OutArchive* out_archive) const {
  DCHECK(out_archive != NULL);

  uint8 type = static_cast<uint8>(block.type());

  // We use a signed integer for saving the section ID, as -1 is used to
  // indicate 'no section'.
  if (!out_archive->Save(type) ||
      !SaveUint32(block.size(), out_archive) ||
      !SaveUint32(block.alignment(), out_archive) ||
      !out_archive->Save(block.source_ranges()) ||
      !out_archive->Save(block.addr()) ||
      !SaveInt32(static_cast<uint32>(block.section()), out_archive) ||
      !out_archive->Save(block.attributes()) ||
      !MaybeSaveString(*this, block.name(), out_archive) ||
      !MaybeSaveString(*this, block.compiland_name(), out_archive)) {
    LOG(ERROR) << "Unable to save properties for block with id "
               << block.id() << ".";
    return false;
  }

  return true;
}

bool BlockGraphSerializer::LoadBlockProperties(BlockGraph::Block* block,
                                               InArchive* in_archive) const {
  DCHECK(block != NULL);
  DCHECK(in_archive != NULL);

  // Make sure the block is freshly initialized.
  DCHECK_EQ(BlockGraph::CODE_BLOCK, block->type_);
  DCHECK_EQ(0u, block->size_);
  DCHECK_EQ(1u, block->alignment_);
  DCHECK_EQ(0u, block->source_ranges_.size());
  DCHECK_EQ(RelativeAddress::kInvalidAddress, block->addr_);
  DCHECK_EQ(BlockGraph::kInvalidSectionId, block->section_);
  DCHECK_EQ(0u, block->attributes_);

  uint8 type = 0;
  uint32 size = 0;
  uint32 alignment = 0;
  uint32 section = 0;
  uint32 attributes = 0;
  std::string name;
  std::string compiland_name;
  if (!in_archive->Load(&type) ||
      !LoadUint32(&size, in_archive) ||
      !LoadUint32(&alignment, in_archive) ||
      !in_archive->Load(&block->source_ranges_) ||
      !in_archive->Load(&block->addr_) ||
      !LoadInt32(reinterpret_cast<int32*>(&section), in_archive) ||
      !in_archive->Load(&attributes) ||
      !MaybeLoadString(*this, &name, in_archive) ||
      !MaybeLoadString(*this, &compiland_name, in_archive)) {
    LOG(ERROR) << "Unable to load properties for block with id "
               << block->id() << ".";
    return false;
  }

  if (type > BlockGraph::BLOCK_TYPE_MAX ||
      !ValidAttributes(attributes, BlockGraph::BLOCK_ATTRIBUTES_MAX)) {
    LOG(ERROR) << "Invalid block type (" << static_cast<uint32>(type)
               << ") and/or attributes ("
               << base::StringPrintf("%04X", attributes)
               << ") for block with id " << block->id() << ".";
    return false;
  }

  block->type_ = static_cast<BlockGraph::BlockType>(type);
  block->size_ = size;
  block->alignment_ = alignment;
  block->section_ = section;
  block->attributes_ = attributes;
  block->set_name(name);
  block->set_compiland_name(compiland_name);
  return true;
}

bool BlockGraphSerializer::SaveBlockLabels(const BlockGraph::Block& block,
                                           OutArchive* out_archive) const {
  DCHECK(out_archive != NULL);

  if (has_attributes(BlockGraphSerializer::OMIT_LABELS))
    return true;

  uint32 count = block.labels().size();
  if (!SaveUint32(count, out_archive)) {
    LOG(ERROR) << "Unable to save label count.";
    return false;
  }

  BlockGraph::Block::LabelMap::const_iterator label_iter =
      block.labels().begin();
  for (; label_iter != block.labels().end(); ++label_iter) {
    COMPILE_ASSERT(BlockGraph::LABEL_ATTRIBUTES_MAX <= (1 << 16),
                   label_attributes_require_more_than_16_bits);

    int32 offset = label_iter->first;
    const BlockGraph::Label& label = label_iter->second;
    uint16 attributes = static_cast<uint16>(label.attributes());

    if (!SaveInt32(offset, out_archive) || !out_archive->Save(attributes) ||
        !MaybeSaveString(*this, label.name(), out_archive)) {
      LOG(ERROR) << "Unable to save label at offset "
                 << label_iter->first << " of block with id "
                 << block.id() << ".";
      return false;
    }
  }

  return true;
}

bool BlockGraphSerializer::LoadBlockLabels(BlockGraph::Block* block,
                                           InArchive* in_archive) const {
  DCHECK(block != NULL);
  DCHECK(in_archive != NULL);

  // The block shouldn't have any labels yet.
  DCHECK_EQ(0u, block->labels().size());

  if (has_attributes(BlockGraphSerializer::OMIT_LABELS))
    return true;

  uint32 label_count = 0;
  if (!LoadUint32(&label_count, in_archive)) {
    LOG(ERROR) << "Unable to load label count.";
    return false;
  }

  for (size_t i = 0; i < label_count; ++i) {
    int32 offset = 0;
    uint16 attributes = 0;
    std::string name;

    if (!LoadInt32(&offset, in_archive) || !(in_archive->Load(&attributes)) ||
        !MaybeLoadString(*this, &name, in_archive)) {
      LOG(ERROR) << "Unable to load label " << i << " of " << label_count
                 << " for block with id " << block->id() << ".";
      return false;
    }

    // Ensure the attributes are valid.
    if (!ValidAttributes(attributes, BlockGraph::LABEL_ATTRIBUTES_MAX)) {
      LOG(ERROR) << "Invalid attributes ("
                 << base::StringPrintf("%04X", attributes) << ") for block "
                 << "with id " << block->id() << ".";
      return false;
    }

    BlockGraph::Label label(name, attributes);
    CHECK(block->SetLabel(offset, label));
  }
  DCHECK_EQ(label_count, block->labels().size());

  return true;
}

bool BlockGraphSerializer::SaveBlockData(const BlockGraph::Block& block,
                                         OutArchive* out_archive) const {
  DCHECK(out_archive != NULL);

  // We always output the data size.
  uint32 data_size = block.data_size();
  if (!SaveUint32(data_size, out_archive)) {
    LOG(ERROR) << "Unable to save block data size for block with id "
               << block.id() << ".";
    return false;
  }

  bool output_data = false;

  if (block.data_size() > 0) {
    switch (data_mode_) {
      default:
        NOTREACHED();

      case OUTPUT_NO_DATA: {
        output_data = false;
        break;
      }

      case OUTPUT_OWNED_DATA: {
        uint8 owns_data = block.owns_data();
        if (!out_archive->Save(owns_data)) {
          LOG(ERROR) << "Unable to save 'owns_data' field of block with id "
                     << block.id() << ".";
          return false;
        }

        output_data = block.owns_data();
        break;
      }

      case OUTPUT_ALL_DATA: {
        output_data = true;
        break;
      }
    }
  }

  // Save the data if we need to.
  if (output_data) {
    DCHECK_LT(0u, block.data_size());
    if (!out_archive->out_stream()->Write(block.data_size(), block.data())) {
      LOG(ERROR) << "Unable to save data for block with id "
                 << block.id() << ".";
      return false;
    }
  }

  // No callback? Then do nothing!
  if (save_block_data_callback_.get() == NULL)
    return true;

  // Invoke the callback.
  bool data_already_saved = output_data || block.data_size() == 0;
  if (!save_block_data_callback_->Run(data_already_saved,
                                      block, out_archive)) {
    return false;
  }

  return true;
}

bool BlockGraphSerializer::LoadBlockData(BlockGraph::Block* block,
                                         InArchive* in_archive) const {
  DCHECK(block != NULL);
  DCHECK(in_archive != NULL);
  DCHECK_EQ(0u, block->data_size());
  DCHECK(block->data() == NULL);
  DCHECK(!block->owns_data());

  uint32 data_size = 0;
  if (!LoadUint32(&data_size, in_archive)) {
    LOG(ERROR) << "Unable to load data size for block with id "
               << block->id() << ".";
    return false;
  }

  // This indicates whether or not we need to explicitly load the data directly
  // from the serialized stream.
  bool data_in_stream = false;

  if (data_size > 0) {
    switch (data_mode_) {
      default:
        NOTREACHED();

      case OUTPUT_NO_DATA: {
        data_in_stream = false;
        break;
      }

      case OUTPUT_OWNED_DATA: {
        uint8 owns_data = 0;
        if (!in_archive->Load(&owns_data)) {
          LOG(ERROR) << "Unable to load 'owns_data' field of block with id "
                     << block->id() << ".";
          return false;
        }

        // If we own the data then it must have been serialized to the stream.
        data_in_stream = owns_data != 0;
        break;
      }

      case OUTPUT_ALL_DATA: {
        data_in_stream = true;
        break;
      }
    }
  }

  bool callback_needs_to_set_data = !data_in_stream && data_size > 0;

  if (data_in_stream) {
    DCHECK_LT(0u, data_size);

    // Read the data from the stream.
    block->AllocateData(data_size);
    DCHECK_EQ(data_size, block->data_size());
    DCHECK(block->data() != NULL);
    if (!in_archive->in_stream()->Read(data_size, block->GetMutableData())) {
      LOG(ERROR) << "Unable to read data for block with id "
                 << block->id() << ".";
      return false;
    }
  }

  if (callback_needs_to_set_data) {
    // If we didn't explicitly load the data, then we expect the callback to
    // do it. We make sure there is one.
    if (load_block_data_callback_.get() == NULL) {
      LOG(ERROR) << "No load block data callback specified.";
      return false;
    }
  }

  // If there's a callback, invoke it.
  if (load_block_data_callback_.get()) {
    if (!load_block_data_callback_->Run(callback_needs_to_set_data,
                                        data_size,
                                        block,
                                        in_archive)) {
      LOG(ERROR) << "Block data callback failed.";
      return false;
    }
  }

  if (data_size > 0 && block->data() == NULL) {
    LOG(ERROR) << "Load block data callback failed to set block data.";
    return false;
  }

  if (block->data_size() != data_size) {
    LOG(ERROR) << "Load block data callback set incorrect data size.";
    return false;
  }

  return true;
}

bool BlockGraphSerializer::SaveBlockReferences(const BlockGraph::Block& block,
                                               OutArchive* out_archive) const {
  // Output the number of references for this block.
  if (!out_archive->Save(block.references().size())) {
    LOG(ERROR) << "Unable to save reference count for block with id "
               << block.id() << ".";
    return false;
  }

  // Output the references as (offset, reference) pairs.
  BlockGraph::Block::ReferenceMap::const_iterator it =
      block.references().begin();
  for (; it != block.references().end(); ++it) {
    int32 offset = it->first;
    if (!SaveInt32(offset, out_archive) ||
        !SaveReference(it->second, out_archive)) {
      LOG(ERROR) << "Unable to save (offset, reference) pair at offset "
                 << offset << " of block with id " << block.id() << ".";
      return false;
    }
  }

  return true;
}

bool BlockGraphSerializer::LoadBlockReferences(BlockGraph* block_graph,
                                               BlockGraph::Block* block,
                                               InArchive* in_archive) const {
  DCHECK(block_graph != NULL);
  DCHECK(block != NULL);
  DCHECK(in_archive != NULL);

  // This block should not have any references yet.
  DCHECK_EQ(0u, block->references().size());

  size_t count = 0;
  if (!in_archive->Load(&count)) {
    LOG(ERROR) << "Unable to load reference count for block with id "
               << block->id() << ".";
    return false;
  }

  for (size_t i = 0; i < count; ++i) {
    int32 offset = 0;
    BlockGraph::Reference ref;
    if (!LoadInt32(&offset, in_archive) ||
        !LoadReference(block_graph, &ref, in_archive)) {
      LOG(ERROR) << "Unable to load (offset, reference) pair " << i << " of "
                 << count << " for block with id " << block->id() << ".";
      return false;
    }
    DCHECK(ref.referenced() != NULL);

    if (!block->SetReference(offset, ref)) {
      LOG(ERROR) << "Unable to create block reference at offset " << offset
                 << " of block with id " << block->id() << ".";
      return false;
    }
  }

  return true;
}

bool BlockGraphSerializer::SaveReference(const BlockGraph::Reference& ref,
                                         OutArchive* out_archive) const {
  DCHECK(ref.referenced() != NULL);
  DCHECK(out_archive != NULL);

  COMPILE_ASSERT(BlockGraph::REFERENCE_TYPE_MAX < 16,
                 reference_type_requires_more_than_one_nibble);
  COMPILE_ASSERT(BlockGraph::Reference::kMaximumSize < 16,
                 reference_size_requires_more_than_one_nibble);

  // The type and size are each stored as a nibble of one byte.
  uint8 type_size = (static_cast<uint8>(ref.type()) << 4) |
      static_cast<uint8>(ref.size());
  int32 offset = ref.offset();
  // Most often the offset and the base are identical, so we actually save
  // the base as a difference from the offset to encourage smaller values.
  int32 base_delta = ref.base() - ref.offset();

  if (!out_archive->Save(type_size) ||
      !out_archive->Save(ref.referenced()->id()) ||
      !SaveInt32(offset, out_archive) || !SaveInt32(base_delta, out_archive)) {
    LOG(ERROR) << "Unable to write reference properties.";
    return false;
  }

  return true;
}

bool BlockGraphSerializer::LoadReference(BlockGraph* block_graph,
                                         BlockGraph::Reference* ref,
                                         InArchive* in_archive) const {
  DCHECK(block_graph != NULL);
  DCHECK(ref != NULL);
  DCHECK(in_archive != NULL);

  uint8 type_size = 0;
  BlockGraph::BlockId id = 0;
  int32 offset = 0;
  int32 base_delta = 0;

  if (!in_archive->Load(&type_size) || !in_archive->Load(&id) ||
      !LoadInt32(&offset, in_archive) || !LoadInt32(&base_delta, in_archive)) {
    LOG(ERROR) << "Unable to load reference properties.";
    return false;
  }

  // The type and size are each stored as a nibble of one byte.
  uint8 type = (type_size >> 4) & 0xF;
  uint8 size = type_size & 0xF;

  if (type >= BlockGraph::REFERENCE_TYPE_MAX ||
      size > BlockGraph::Reference::kMaximumSize) {
    LOG(ERROR) << "Invalid reference type (" << static_cast<uint32>(type)
               << ") and/or size (" << static_cast<uint32>(size) << ").";
    return false;
  }

  BlockGraph::Block* referenced = block_graph->GetBlockById(id);
  if (referenced == NULL) {
    LOG(ERROR) << "Unable to find referenced block with id " << id << ".";
    return false;
  }

  *ref = BlockGraph::Reference(static_cast<BlockGraph::ReferenceType>(type),
                               size, referenced, offset, offset + base_delta);

  return true;
}

// Saves an unsigned 32 bit value. This uses a variable length encoding where
// the first three bits are reserved to indicate the number of bytes required to
// store the value.
bool BlockGraphSerializer::SaveUint32(uint32 value,
                                      OutArchive* out_archive) const {
  DCHECK(out_archive != NULL);

  // Determine the number of bytes needed in the representation.
  uint32 bytes = 1;
  if (value >= (1 << 29)) {
    bytes = 5;
  } else if (value >= (1 << 21)) {
    bytes = 4;
  } else if (value >= (1 << 13)) {
    bytes = 3;
  } else if (value >= (1 << 5)) {
    bytes = 2;
  }

  // Output the value, LSB first. We actually only output 5 bits of the LSB.
  uint8 byte = (value & ((1 << 5) - 1));
  byte |= ((bytes - 1) << 5);
  value >>= 5;
  while (true) {
    if (!out_archive->Save(byte)) {
      LOG(ERROR) << "Unable to write variable-length 32-bit unsigned integer.";
      return false;
    }

    if (--bytes == 0)
      break;

    byte = value & 0xFF;
    value >>= 8;
  }

  return true;
}

// Loads an unsigned 32-bit value using the encoding discussed in SaveUint32.
bool BlockGraphSerializer::LoadUint32(uint32* value,
                                      InArchive* in_archive) const {
  DCHECK(value != NULL);
  DCHECK(in_archive != NULL);

  uint32 temp_value = 0;
  uint32 bytes = 0;
  uint32 position = 0;
  uint8 byte = 0;

  while (true) {
    if (!in_archive->Load(&byte)) {
      LOG(ERROR) << "Unable to read variable-length 32-bit unsigned integer.";
      return false;
    }

    // If we're reading the first byte, we need to read the number of bytes
    // remaining from its 3 leading bits.
    if (position == 0) {
      bytes = (byte >> 5) & 0x7;
      temp_value = byte & ((1 << 5) - 1);
      position += 5;
    } else {
      temp_value |= byte << position;
      position += 8;
    }

    if (bytes == 0)
      break;

    --bytes;
  }

  *value = temp_value;
  return true;
}

// Saves a signed 32-bit value using a variable length encoding. This can
// represent signed values where the magnitude is at most 31-bits. We use a
// simple sign-bit encoding, so there are 2 encodings for 0.
bool BlockGraphSerializer::SaveInt32(int32 value,
                                     OutArchive* out_archive) const {
  DCHECK(out_archive != NULL);

  uint32 uvalue = static_cast<uint32>(value < 0 ? -value : value);
  CHECK_GT((1u << 31), uvalue);

  // Add the sign bit as the least significant bit. This allows values near 0
  // (positive or negative) to be encoded in as little space as possible.
  uvalue <<= 1;
  if (value < 0)
    uvalue |= 1;

  if (!SaveUint32(uvalue, out_archive))
    return false;

  return true;
}

bool BlockGraphSerializer::LoadInt32(int32* value,
                                     InArchive* in_archive) const {
  DCHECK(value != NULL);
  DCHECK(in_archive != NULL);

  uint32 uvalue = 0;
  if (!LoadUint32(&uvalue, in_archive))
    return false;

  *value = static_cast<int32>(uvalue >> 1);
  if ((uvalue & 1) != 0)
    *value = -(*value);

  return true;
}

}  // namespace block_graph
