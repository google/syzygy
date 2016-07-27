// Copyright 2015 Google Inc. All Rights Reserved.
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

#include "syzygy/pe/hot_patching_decomposer.h"

#include "base/bind.h"
#include "syzygy/common/defs.h"
#include "syzygy/pe/pe_utils.h"

namespace pe {

namespace {

using block_graph::BlockGraph;
using block_graph::BlockInfo;
using core::AbsoluteAddress;
using core::FileOffsetAddress;
using core::RelativeAddress;

typedef BlockGraph::Block Block;

// NOTE: This is based on GetSectionName in from pe_coff_file_impl.h.
std::string GetSectionName(const IMAGE_SECTION_HEADER& section) {
  const char* name = reinterpret_cast<const char*>(section.Name);
  return std::string(name, strnlen(name, arraysize(section.Name)));
}

// NOTE: This is based on CopySectionInfoToBlockGraph in pe_utils_impl.h.
//    Added the section_index parameter to create an index used later in
//    CreateBlock.
bool CopySectionInfoToBlockGraph(
    const base::win::PEImage& image_file,
    BlockGraph* block_graph,
    HotPatchingDecomposer::SectionIdMap* section_index) {
  DCHECK_NE(static_cast<BlockGraph*>(nullptr), block_graph);
  DCHECK_NE(static_cast<HotPatchingDecomposer::SectionIdMap*>(nullptr),
            section_index);

  // Iterate through the image sections, and create sections in the BlockGraph.
  uint32_t num_sections =
      image_file.GetNTHeaders()->FileHeader.NumberOfSections;
  for (uint32_t i = 0; i < num_sections; ++i) {
    const IMAGE_SECTION_HEADER* header = image_file.GetSectionHeader(i);
    std::string name = GetSectionName(*header);
    BlockGraph::Section* section = block_graph->AddSection(
        name, header->Characteristics);
    DCHECK_NE(static_cast<BlockGraph::Section*>(nullptr), section);

    // For now, we expect them to have been created with the same IDs as those
    // in the original image.
    if (section->id() != i) {
      LOG(ERROR) << "Unexpected section ID.";
      return false;
    }

    section_index->insert(std::make_pair(header, section->id()));
  }

  return true;
}

// Interprets the 32-bit unsigned integer parameter as a pointer, and checks
// if it points to the block's data, after a specific offset.
// @param displacement The 32-bit unsigned integer.
// @param block The block to check.
// @param offset The pointer must point after this offset.
// @returns true if the conditions are met, false otherwise.
bool DisplacementPointsIntoBlockAfterOffset(uint32_t displacement,
                                            const BlockGraph::Block* block,
                                            size_t offset) {
  DCHECK_NE(static_cast<BlockGraph::Block*>(nullptr), block);

  return reinterpret_cast<uint8_t*>(displacement) >= block->data() + offset &&
         reinterpret_cast<uint8_t*>(displacement) <
             block->data() + block->data_size();
}

// This function is called when we didn't manage to parse an instruction.
// We do some sanity DCHECKs to verify that the instruction does not contain
// a reference that we failed to recover.
// @param block The block containing the instructions.
// @param inst The instruction to examine.
void ExecuteSanityChecks(BlockGraph::Block* block,
                         BlockGraph::Offset offset,
                         const _DInst& inst) {
  DCHECK_NE(static_cast<BlockGraph::Block*>(nullptr), block);

  for (int i = 0; i < arraysize(inst.ops); ++i) {
    // Fail if we see PC-relative operand.
    if (inst.ops[i].type == O_PC)
      NOTREACHED();

    // Fail if we see an absolute pointer in the displacement that can be
    // interpreted as a pointer to anywhere inside the block. This is
    // probably some unknown construct that needs to be handled.
    if (inst.ops[i].type == O_SMEM || inst.ops[i].type == O_MEM) {
      if (inst.dispSize == 32U &&
          DisplacementPointsIntoBlockAfterOffset(inst.disp, block, 0U)) {
        LOG(ERROR) << "Pointer-like displacement: " << inst.disp;
        NOTREACHED();
      }
    }
  }
}

// Adds a data label to a block. If a data label already exists at the offset
// that is neither a case table nor a jump table label, it will be replaced.
// Otherwise a DCHECK will be used to check if the old and the desired labels
// have the same attributes.
// @param block The block to add the label to.
// @param offset The offset of the desired label.
// @param label_name The name of the desired label.
// @param additional_attribute Specifies whether the desired label is a
//     JUMP_TABLE_LABEL or CASE_TABLE_LABEL.
void AddDataLabel(BlockGraph::Block* block,
                  BlockGraph::Offset offset,
                  const std::string& label_name,
                  BlockGraph::LabelAttributesEnum additional_attribute) {
  DCHECK_NE(static_cast<BlockGraph::Block*>(nullptr), block);
  DCHECK(additional_attribute == BlockGraph::JUMP_TABLE_LABEL ||
         additional_attribute == BlockGraph::CASE_TABLE_LABEL);

  BlockGraph::LabelAttributes label_attributes =
      BlockGraph::DATA_LABEL | additional_attribute;

  if (block->HasLabel(offset)) {
    // The label already exists, just update the attribute if needed.
    BlockGraph::Label old_label;
    block->GetLabel(offset, &old_label);
    DCHECK(old_label.has_attributes(BlockGraph::DATA_LABEL));

    if (old_label.attributes() == BlockGraph::DATA_LABEL) {
      // A simple DATA_LABEL is created by the decomposer at the end of the code
      // block. We replace this label with a more specific one.

      // The data part may not start with a case table.
      DCHECK_EQ(additional_attribute, BlockGraph::JUMP_TABLE_LABEL);

      // We can't change the label, so remove it and add a new one.
      block->RemoveLabel(offset);
    } else {
      // Sanity check: no case table and jump table at the same location.
      DCHECK_EQ(old_label.name(), label_name);
      DCHECK_EQ(old_label.attributes(), label_attributes);

      // The label is already there, no need to add it again.
      return;
    }
  }

  if (!block->SetLabel(offset, label_name, label_attributes)) {
    // SetLabel returns false if the label already existed, which can't happen
    // because we've just removed it.
    NOTREACHED();
  }
}

}  // namespace

HotPatchingDecomposer::HotPatchingDecomposer(HMODULE module)
    : image_layout_(nullptr),
      image_(nullptr),
      last_code_block_id_(0U),
      module_(module) {
}

HotPatchingDecomposer::~HotPatchingDecomposer() { }

bool HotPatchingDecomposer::Decompose(ImageLayout* image_layout) {
  DCHECK_NE(static_cast<ImageLayout*>(nullptr), image_layout);

  // The temporaries should be nullptr.
  DCHECK_EQ(static_cast<ImageLayout*>(nullptr), image_layout_);
  DCHECK_EQ(static_cast<BlockGraph::AddressSpace*>(nullptr), image_);

  image_layout_ = image_layout;
  image_ = &(image_layout->blocks);

  // Initialize in-memory PE wrapper.
  pe_image_ = std::make_unique<base::win::PEImage>(module_);

  // Set the image format.
  image_->graph()->set_image_format(BlockGraph::PE_IN_MEMORY_IMAGE);

  // Process sections in image.
  if (!LoadSectionInformation())
    return false;

  // Process blocks using the hot patching metadata.
  if (!LoadHotPatchableBlocks())
    return false;

  return true;
}

// NOTE: This is based on Decomposer::CreateBlock.
Block* HotPatchingDecomposer::CreateBlock(BlockType type,
                                          RelativeAddress address,
                                          BlockGraph::Size size,
                                          const base::StringPiece& name) {
  Block* block = image_->AddBlock(type, address, size, name);
  if (block == nullptr) {
    LOG(ERROR) << "Unable to add block \"" << name.as_string() << "\" at "
               << address << " with size " << size << ".";
    return nullptr;
  }

  // Mark the source range from whence this block originates.
  bool pushed = block->source_ranges().Push(
      Block::DataRange(0, size),
      Block::SourceRange(address, size));
  DCHECK(pushed);

  // Search section id in the index.
  const IMAGE_SECTION_HEADER* block_section_header =
      pe_image_->GetImageSectionFromAddr(pe_image_->RVAToAddr(address.value()));
  if (block_section_header == nullptr) {
    LOG(ERROR) << "Block \"" << name.as_string() << "\" at " << address
               << " with size " << size << " lies outside of all sections.";
    return nullptr;
  }
  const auto it = section_index_.find(block_section_header);
  DCHECK(it != section_index_.end());
  block->set_section(it->second);

  const uint8_t* data =
      static_cast<const uint8_t*>(pe_image_->RVAToAddr(address.value()));
  if (data != nullptr)
    block->SetData(data, size);

  return block;
}

bool HotPatchingDecomposer::InferCodeReferences(Block* block,
                                                size_t code_size) {
  DCHECK_NE(static_cast<BlockGraph::Block*>(nullptr), block);

  // Disassemble the block
  size_t offset = 0;
  while (offset < code_size) {
    _DInst inst;

    // Try to decode the next instruction.
    const uint8_t* inst_data = block->data() + offset;
    if (!core::DecodeOneInstruction(inst_data,
                                    static_cast<int>(code_size - offset),
                                    &inst)) {
      LOG(ERROR) << "Failed to decode instruction at offset " << offset
                 << " in block " << BlockInfo(block);
      return false;
    }

    // Try to recover reference from the instruction.
    bool parsed = false;
    if (!ParsePCRelativeBranchAndCallInstuction(block, offset, inst, &parsed))
      return false;
    if (!parsed && !ParseJumpTableCall(block, offset, inst, code_size, &parsed))
      return false;
    if (!parsed && !ParseCaseTableRead(block, offset, inst, code_size, &parsed))
      return false;

    // Do some sanity checks in DCHECK builds if we see no reference.
    if (!parsed)
      ExecuteSanityChecks(block, offset, inst);

    offset += inst.size;
  }

  return true;
}

bool HotPatchingDecomposer::InferJumpTableReferences(Block* block,
                                                     size_t code_size) {
  DCHECK_NE(static_cast<BlockGraph::Block*>(nullptr), block);

  const uint8_t* block_start = block->data();
  const uint8_t* block_end = block->data() + block->data_size();

  for (auto it = block->labels().begin(); it != block->labels().end();) {
    BlockGraph::Offset offset = it->first;
    const BlockGraph::Label& label = it->second;

    // We increment the iterator here because we want to access the next label
    // below. The current label is already saved in |label|.
    ++it;

    if (label.has_attributes(BlockGraph::JUMP_TABLE_LABEL)) {
      // The jump table ends at the next label or at the end of the block.
      BlockGraph::Offset end_offset = 0;
      if (it != block->labels().end()) {
        end_offset = it->first;
      } else {
        end_offset = block->data_size();
      }

      // Calculate start and end relative addresses.
      RelativeAddress addr = block->addr() + offset;
      const RelativeAddress end_addr = block->addr() + end_offset;

      // While we have more than 4 bytes remaining.
      for (; addr <= end_addr - 4; addr += 4) {

        // Interpret the 4 bytes starting at |addr| as a pointer.
        const uint8_t* const* target_location =
            reinterpret_cast<const uint8_t* const*>(block->data() +
                                                    (addr - block->addr()));
        const uint8_t* target_as_pointer = *target_location;

        // Add an absolute reference if this address points into the block.
        if (block_start <= target_as_pointer && target_as_pointer < block_end) {
          BlockGraph::Offset target_offset = target_as_pointer - block_start;
          DCHECK_GE(target_offset, 0);
          // The reference should not point into the data part of the block.
          DCHECK_LT(target_offset, static_cast<int>(code_size));

          if (!block->SetReference(addr - block->addr(),
                                   BlockGraph::Reference(
                                       BlockGraph::ABSOLUTE_REF,
                                       4,
                                       block,
                                       target_offset,
                                       target_offset))) {
            return false;
          }
        }
      }
    }
  }

  return true;
}

bool HotPatchingDecomposer::LoadHotPatchableBlocks() {
  PIMAGE_SECTION_HEADER hp_sect_hdr = pe_image_->GetImageSectionHeaderByName(
      common::kHotPatchingMetadataSectionName);
  DCHECK_NE(static_cast<PIMAGE_SECTION_HEADER>(nullptr), hp_sect_hdr);

  // Load metadata section header.
  block_graph::HotPatchingMetadataHeader* hp_metadata_header =
      static_cast<block_graph::HotPatchingMetadataHeader*>(
          pe_image_->RVAToAddr(hp_sect_hdr->VirtualAddress));
  DCHECK_NE(static_cast<block_graph::HotPatchingMetadataHeader*>(nullptr),
      hp_metadata_header);
  if (block_graph::kHotPatchingMetadataVersion !=
      hp_metadata_header->version) {
    return false;
  }

  // Locate the block metadata array. The (hp_metadata_header + 1) expression is
  // a pointer pointing to the location after the header.
  block_graph::HotPatchingBlockMetadata* hp_block_metadata_arr =
      reinterpret_cast<block_graph::HotPatchingBlockMetadata*>(
          hp_metadata_header + 1);

  // Create hot patchable code blocks and their labels based on the hot
  // patching metadata.
  for (size_t i = 0; i < hp_metadata_header->number_of_blocks; ++i) {
    Block* block = ProcessHotPatchableCodeBlock(hp_block_metadata_arr[i]);
    DCHECK_NE(static_cast<Block*>(nullptr), block);
  }

  // Create references for hot patchable code blocks.
  //
  // This must run after all hot patchable blocks have been created because it
  // searches for the referred block and creates a dummy block if the referred
  // block is not found.
  for (size_t i = 0; i < hp_metadata_header->number_of_blocks; ++i) {
    Block* block = image_layout_->blocks.GetBlockByAddress(
        RelativeAddress(hp_block_metadata_arr[i].relative_address));

    DCHECK_NE(static_cast<Block*>(nullptr), block);

    InferCodeReferences(block, hp_block_metadata_arr[i].code_size);

    if (hp_block_metadata_arr[i].code_size <
        hp_block_metadata_arr[i].block_size) {
      InferJumpTableReferences(block, hp_block_metadata_arr[i].code_size);
    }
  }

  return true;
}

bool HotPatchingDecomposer::LoadSectionInformation() {
  // Create sections in the image layout.
  CopySectionHeadersToImageLayout(
      pe_image_->GetNTHeaders()->FileHeader.NumberOfSections,
      pe_image_->GetSectionHeader(0),
      &(image_layout_->sections));

  // Create the sections in the underlying block-graph.
  if (!CopySectionInfoToBlockGraph(*pe_image_,
                                   image_->graph(),
                                   &section_index_)) {
    return false;
  }

  return true;
}

bool HotPatchingDecomposer::ParseCaseTableRead(BlockGraph::Block* block,
                                               BlockGraph::Offset offset,
                                               const _DInst &inst,
                                               size_t code_size,
                                               bool* parsed) {
  DCHECK_NE(static_cast<BlockGraph::Block*>(nullptr), block);
  DCHECK_NE(static_cast<bool*>(nullptr), parsed);

  // Check if the instruction is a case table read.
  *parsed = inst.opcode == I_MOVZX &&
            inst.ops[0].type == O_REG &&
            inst.ops[1].type == O_SMEM &&
            inst.dispSize == 32U &&
            inst.ops[2].type == O_NONE &&
            DisplacementPointsIntoBlockAfterOffset(inst.disp, block, code_size);

  // Return early if not.
  if (!*parsed)
    return true;

  int reference_size = inst.dispSize / 8;

  BlockGraph::Offset ref_source_offset =
      offset + inst.size - reference_size;
  BlockGraph::Offset ref_target_offset =
      reinterpret_cast<uint8_t*>(inst.disp) - block->data();

  // The displacement is at the end of this instruction.
  if (!block->SetReference(ref_source_offset,
                           BlockGraph::Reference(
                               BlockGraph::ABSOLUTE_REF,
                               reference_size,
                               block,
                               ref_target_offset,
                               ref_target_offset))) {
    LOG(ERROR) << "Failed to create self reference in block "
               << BlockInfo(block) << " from offset "
               << ref_source_offset << " to offset " << ref_target_offset;
    return false;
  }

  // Insert a case table label.
  AddDataLabel(block,
               ref_target_offset,
               "case-table",
               BlockGraph::CASE_TABLE_LABEL);

  return true;
}

bool HotPatchingDecomposer::ParseJumpTableCall(BlockGraph::Block* block,
                                               BlockGraph::Offset offset,
                                               const _DInst &inst,
                                               size_t code_size,
                                               bool* parsed) {
  DCHECK_NE(static_cast<BlockGraph::Block*>(nullptr), block);
  DCHECK_NE(static_cast<bool*>(nullptr), parsed);

  // Check if the instruction is a jump using a jump table.
  *parsed = inst.opcode == I_JMP &&
            inst.ops[0].type == O_MEM &&
            inst.ops[1].type == O_NONE &&
            inst.scale == 4U &&
            inst.dispSize == 32U &&
            DisplacementPointsIntoBlockAfterOffset(inst.disp, block,
                                                   code_size);

  // Return early if not.
  if (!*parsed)
    return true;

  int reference_size = inst.dispSize / 8;

  BlockGraph::Offset ref_source_offset =
      offset + inst.size - reference_size;
  BlockGraph::Offset ref_target_offset =
      reinterpret_cast<uint8_t*>(inst.disp) - block->data();

  // The displacement is always at the end of a one-operand instruction.
  if (!block->SetReference(ref_source_offset,
                           BlockGraph::Reference(
                               BlockGraph::ABSOLUTE_REF,
                               reference_size,
                               block,
                               ref_target_offset,
                               ref_target_offset))) {
    LOG(ERROR) << "Failed to create self reference in block "
               << BlockInfo(block) << " from offset "
               << ref_source_offset << " to offset " << ref_target_offset;
    return false;
  }

  // Insert a jump table label.
  AddDataLabel(block,
               ref_target_offset,
               "jump-table",
               BlockGraph::JUMP_TABLE_LABEL);

  return true;
}

bool HotPatchingDecomposer::ParsePCRelativeBranchAndCallInstuction(
    BlockGraph::Block* block,
    BlockGraph::Offset offset,
    const _DInst &inst,
    bool* parsed) {
  DCHECK_NE(static_cast<BlockGraph::Block*>(nullptr), block);
  DCHECK_NE(static_cast<bool*>(nullptr), parsed);

  *parsed = (core::IsBranch(inst) || core::IsCall(inst)) &&
            inst.ops[0].type == O_PC;
  if (!*parsed)
    return true;

  CHECK(inst.ops[1].type == O_NONE);

  int reference_size = inst.ops[0].size / 8;

  if (reference_size == 4) {
    // Insert a reference for 32-bit PC-relative jump and call instructions.

    // Create the reference.
    BlockGraph::Offset pc_relative_address = inst.imm.addr;
    RelativeAddress target_relative_address = RelativeAddress(
        block->addr().value() + offset + pc_relative_address + inst.size);
    Block* referenced_block = image_layout_->blocks.GetBlockByAddress(
        target_relative_address);

    BlockGraph::Offset ref_target_offset = 0;

    if (referenced_block != nullptr) {
      ref_target_offset =
          target_relative_address - referenced_block->addr();

      if (referenced_block != block) {
        // If the following check fails that means that we have an
        // inter-block reference pointing inside a hot patchable block.
        CHECK_EQ(target_relative_address, referenced_block->addr());
      }
    } else {
      // There is no block at the referred location. This means that the
      // referred block is not hot patchable. Create a dummy code block that
      // can be referenced.
      referenced_block = CreateBlock(BlockGraph::CODE_BLOCK,
                                     target_relative_address,
                                     1,
                                     "TargetBlock");
      DCHECK_NE(static_cast<Block*>(nullptr), referenced_block);
      // We set the BUILT_BY_UNSUPPORTED_COMPILER attribute on dummy blocks.
      // This attribute expresses that the block can't be moved and the data
      // of the block should not be interpreted.
      referenced_block->set_attribute(
          BlockGraph::BUILT_BY_UNSUPPORTED_COMPILER);

      ref_target_offset = 0;
    }

    DCHECK_GE(inst.size, 1 + reference_size);
    DCHECK_GE(2 + reference_size, inst.size);

    // The reference is always at the end of the instruction.
    if (!block->SetReference(offset + inst.size - reference_size,
                              BlockGraph::Reference(
                                  BlockGraph::PC_RELATIVE_REF,
                                  reference_size,
                                  referenced_block,
                                  ref_target_offset,
                                  ref_target_offset))) {
      return false;
    }
    ++parsed;
  } else {
    // We don't deal with smaller references. These are in-block references
    // that are resolved by the basic block decomposer.
  }

  return true;
}

Block *HotPatchingDecomposer::ProcessHotPatchableCodeBlock(
    const block_graph::HotPatchingBlockMetadata& block_metadata) {

  // The relative address will point to the correct field as it should be
  // relocated.
  RelativeAddress data_address(block_metadata.relative_address);
  size_t block_size = block_metadata.block_size;

  // Generate a unique name for the block.
  ++last_code_block_id_;
  std::string block_name = "CodeBlock" + std::to_string(last_code_block_id_);

  // Add the block to the block graph.
  Block* block = CreateBlock(BlockGraph::CODE_BLOCK,
                             data_address,
                             block_size,
                             block_name);
  if (block == nullptr) {
    LOG(ERROR) << "Unable to add code block at "
               << data_address << " with size " << block_size << ".";
    return nullptr;
  }

  // Add a code label to the beginning of the block.
  block->SetLabel(0, "CODE", BlockGraph::CODE_LABEL);

  // If the code does not fill the whole data, put a data label at the end of
  // the code.
  if (block_metadata.code_size != block_metadata.block_size) {
    block->SetLabel(static_cast<int>(block_metadata.code_size),
                    "DATA", BlockGraph::DATA_LABEL);
  }

  return block;
}

}  // namespace pe
