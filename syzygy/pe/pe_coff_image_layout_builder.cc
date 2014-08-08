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

#include "syzygy/pe/pe_coff_image_layout_builder.h"

#include "base/strings/string_util.h"
#include "syzygy/common/align.h"
#include "syzygy/pe/pe_utils.h"

namespace pe {

PECoffImageLayoutBuilder::PECoffImageLayoutBuilder(ImageLayout* image_layout)
    : image_layout_(image_layout),
      padding_(0),
      code_alignment_(1),
      section_alignment_(1),
      file_alignment_(1) {
  DCHECK(image_layout != NULL);
  DCHECK_EQ(0u, image_layout->blocks.address_space_impl().size());
  DCHECK_EQ(0u, image_layout->sections.size());
}

void PECoffImageLayoutBuilder::Init(size_t section_alignment,
                                    size_t file_alignment) {
  DCHECK_LT(0u, section_alignment);
  DCHECK_LT(0u, file_alignment);
  DCHECK_LE(file_alignment, section_alignment);
  DCHECK_EQ(0u, section_alignment % file_alignment);

  section_alignment_ = section_alignment;
  file_alignment_ = file_alignment;
}

bool PECoffImageLayoutBuilder::OpenSection(const char* name,
                                           uint32 characteristics) {
  DCHECK(name != NULL);

  // If we're already in a section, close it.
  if (section_start_.value() != 0)
    CloseSection();

  // Align to the start of the next section.
  DCHECK_LT(0u, cursor_.value());
  cursor_ = cursor_.AlignUp(section_alignment_);

  // Remember the start of the section and reset the initialized data cursors.
  DCHECK_EQ(0u, section_start_.value());
  DCHECK_EQ(0u, section_auto_init_end_.value());
  DCHECK_EQ(0u, section_init_end_.value());
  section_start_ = cursor_;
  section_auto_init_end_ = cursor_;
  section_init_end_ = cursor_;

  // Create a section.
  ImageLayout::SectionInfo section_info;
  section_info.name = name;
  section_info.addr = section_start_;
  section_info.size = 0;
  section_info.data_size = 0;
  section_info.characteristics = characteristics;
  image_layout_->sections.push_back(section_info);

  return true;
}

bool PECoffImageLayoutBuilder::OpenSection(const BlockGraph::Section& section) {
  return OpenSection(section.name().c_str(), section.characteristics());
}

bool PECoffImageLayoutBuilder::LayoutBlock(BlockGraph::Block* block) {
  DCHECK(block != NULL);
  return LayoutBlock(block->alignment(), block);
}

bool PECoffImageLayoutBuilder::LayoutBlock(size_t alignment,
                                           BlockGraph::Block* block) {
  DCHECK_LT(0u, alignment);
  DCHECK(block != NULL);
  DCHECK_NE(0u, section_start_.value());

  // If this is not the first block of the section and we have padding, then
  // output the padding.
  if (padding_ > 0 && cursor_ > section_start_)
    cursor_ += padding_;

  // Keep the larger alignment.
  if (block->type() == BlockGraph::CODE_BLOCK && alignment < code_alignment_)
    alignment = code_alignment_;
  cursor_ = cursor_.AlignUp(alignment);

  // If we have explicit data, advance the explicit data cursor.
  if (block->data_size() > 0)
    section_auto_init_end_ = cursor_ + block->data_size();

  // This advances the cursor for us.
  if (!LayoutBlockImpl(block))
    return false;

  return true;
}

void PECoffImageLayoutBuilder::CloseExplicitSectionData() {
  DCHECK_NE(0u, section_start_.value());
  section_init_end_ = cursor_;
}

bool PECoffImageLayoutBuilder::CloseSection() {
  DCHECK_NE(0u, section_start_.value());
  DCHECK_LT(0u, image_layout_->sections.size());

  size_t section_size = cursor_ - section_start_;

  // If provided use the explicit initialized data size, otherwise use the
  // automatic one.
  size_t init_size = 0;
  if (section_init_end_ > cursor_) {
    if (section_auto_init_end_ > section_init_end_) {
      LOG(ERROR) << "Blocks with initialized data lay beyond explicitly "
                    "specified end of initialized data.";
      return false;
    }
    init_size = section_init_end_ - section_start_;
  } else {
    init_size = section_auto_init_end_ - section_start_;
  }

  // A section must have *some* presence in the file.
  if (init_size == 0)
    init_size = 1;

  init_size = common::AlignUp(init_size, file_alignment_);

  ImageLayout::SectionInfo& section_info = image_layout_->sections.back();
  section_info.size = section_size;
  section_info.data_size = init_size;

  if (cursor_ < section_start_ + init_size)
    cursor_ = section_start_ + init_size;

  section_start_.set_value(0);
  section_auto_init_end_.set_value(0);
  section_init_end_.set_value(0);

  return true;
}

// Lays out a block at the current cursor location.
bool PECoffImageLayoutBuilder::LayoutBlockImpl(BlockGraph::Block* block) {
  DCHECK(block != NULL);
  if (!image_layout_->blocks.InsertBlock(cursor_, block)) {
    LOG(ERROR) << "InsertBlock failed for block (id=" << block->id()
               << ", name=\"" << block->name() << "\").";
    return false;
  }
  cursor_ += block->size();
  return true;
}

}  // namespace pe
