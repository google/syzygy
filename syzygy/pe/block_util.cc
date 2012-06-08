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

#include "syzygy/pe/block_util.h"

#include "syzygy/core/address.h"

namespace pe {

namespace {

using block_graph::BlockGraph;

const size_t kPointerSize = sizeof(core::AbsoluteAddress);

// Returns true if there is a data label at the given offset,
// false otherwise.
bool HasDataLabel(const BlockGraph::Block* block,
                  BlockGraph::Offset offset) {
  BlockGraph::Block::LabelMap::const_iterator label_it =
      block->labels().find(offset);
  if (label_it == block->labels().end())
    return false;
  if (!label_it->second.has_attributes(BlockGraph::DATA_LABEL))
    return false;
  return true;
}

bool IsValidSelfReferenceCodeToCode(
    const BlockGraph::Block* block,
    const BlockGraph::Reference& ref) {
  // These references must be direct. They may be 1- or 4-byte PC-relative refs,
  // or 4-byte absolute refs.
  if (!ref.IsDirect())
    return false;

  switch (ref.type()) {
    case BlockGraph::PC_RELATIVE_REF: {
      if (ref.size() != 1 && ref.size() != kPointerSize)
        return false;
      break;
    }

    case BlockGraph::ABSOLUTE_REF: {
      if (ref.size() != kPointerSize)
        return false;
      break;
    }

    default: {
      return false;
    }
  }

  return true;
}

bool IsValidSelfReferenceCodeToData(
    const BlockGraph::Block* block,
    const BlockGraph::Reference& ref) {
  // Must be direct 4-byte absolute references to a data label.
  if (ref.type() != BlockGraph::ABSOLUTE_REF ||
      ref.size() != kPointerSize ||
      !ref.IsDirect() ||
      !HasDataLabel(block, ref.offset())) {
    return false;
  }
  return true;
}

bool IsValidSelfReferenceDataToCode(
    const BlockGraph::Block* block,
    const BlockGraph::Reference& ref) {
  // Must be 4-byte direct absolute references.
  if (ref.type() != BlockGraph::ABSOLUTE_REF ||
      ref.size() != kPointerSize ||
      !ref.IsDirect()) {
    return false;
  }
  return true;
}

bool IsValidExternalReferenceCodeBlockToCode(
    const BlockGraph::Block* block,
    const BlockGraph::Reference& ref) {
  // Must be direct 4-byte absolute or pc-rel reference to offset 0.
  if (ref.type() != BlockGraph::ABSOLUTE_REF &&
      ref.type() != BlockGraph::PC_RELATIVE_REF) {
    return false;
  }
  if (ref.size() != kPointerSize ||
      ref.offset() != 0 ||
      !ref.IsDirect())
    return false;
  return true;
}

bool IsValidExternalReferenceDataBlockToCode(
    const BlockGraph::Block* block,
    const BlockGraph::Reference& ref) {
  // Must be direct 4-byte absolute or relative (PE structures) pointer to
  // offset 0.
  if (ref.type() != BlockGraph::ABSOLUTE_REF &&
      ref.type() != BlockGraph::RELATIVE_REF) {
    return false;
  }
  if (ref.size() != kPointerSize ||
      ref.offset() != 0 ||
      !ref.IsDirect())
    return false;
  return true;
}

}  // namespace

bool CodeBlockAttributesAreClConsistent(
    const block_graph::BlockGraph::Block* block) {
  DCHECK(block != NULL);
  DCHECK_EQ(BlockGraph::CODE_BLOCK, block->type());

  // TODO(chrisha): Implement and set a PARTIAL_DISASSEMBLY_COVERAGE bit in
  //     decomposer.

  const BlockGraph::BlockAttributes kInvalidAttributes =
      BlockGraph::HAS_INLINE_ASSEMBLY |
      BlockGraph::BUILT_BY_UNSUPPORTED_COMPILER;
  if (block->attributes() & kInvalidAttributes)
    return false;

  return true;
}

bool CodeBlockReferencesAreClConsistent(const BlockGraph::Block* block) {
  DCHECK(block != NULL);
  DCHECK_EQ(BlockGraph::CODE_BLOCK, block->type());

  // Iterate over the outgoing references from this block.
  BlockGraph::Block::ReferenceMap::const_iterator ref_it =
      block->references().begin();
  for (; ref_it != block->references().end(); ++ref_it) {
    switch (ref_it->second.referenced()->type()) {
      // References to data are always safe.
      case BlockGraph::DATA_BLOCK: {
        break;
      }

      // References to code blocks must be direct.
      case BlockGraph::CODE_BLOCK: {
        if (!ref_it->second.IsDirect())
          return false;
        break;
      }

      default: {
        // References to any other type of block are considered unsafe by
        // default. Really, this should never happen.
        NOTREACHED() << "Unexpected block type.";
      }
    }
  }

  return true;
}

bool CodeBlockReferrersAreClConsistent(const BlockGraph::Block* block) {
  DCHECK(block != NULL);
  DCHECK_EQ(BlockGraph::CODE_BLOCK, block->type());

  // Code blocks generated by CL.EXE tend to be cleanly split in two, with
  // code first and local data (jump and case tables) second. We expect all of
  // the data labels to be referenced.
  std::set<BlockGraph::Offset> data_label_offsets;
  BlockGraph::Block::LabelMap::const_iterator label_it =
      block->labels().begin();
  for (; label_it != block->labels().end(); ++label_it) {
    // Have we already seen at least one data label?
    if (!data_label_offsets.empty()) {
      // We only expect to see other data labels thereafter.
      if (!label_it->second.has_attributes(BlockGraph::DATA_LABEL))
        return false;
    }

    // Not data? Skip it.
    if (!label_it->second.has_attributes(BlockGraph::DATA_LABEL))
      continue;

    // If we get here it's another data label.
    data_label_offsets.insert(label_it->first);
  }

  // Determine the transition point that divides code from data.
  BlockGraph::Offset start_of_data = block->size();
  if (!data_label_offsets.empty())
    start_of_data = *data_label_offsets.begin();

  // Iterate through the referrers. Since we have to look up back-references
  // this is O(n log n).
  BlockGraph::Block::ReferrerSet::const_iterator ref_it =
      block->referrers().begin();
  for (; ref_it != block->referrers().end(); ++ref_it) {
    // Get the reference associated with this referrer.
    BlockGraph::Reference ref;
    CHECK(ref_it->first->GetReference(ref_it->second, &ref));

    if (ref_it->first == block) {                           // Self-reference.
      if (ref_it->second < start_of_data) {                   //   From code
        if (ref.offset() < start_of_data) {                   //     To code.
          if (!IsValidSelfReferenceCodeToCode(block, ref))
            return false;
        } else {                                              //     To data.
          if (!IsValidSelfReferenceCodeToData(block, ref))
            return false;
          // Mark the data label as having been seen.
          data_label_offsets.erase(ref.offset());
        }
      } else {                                                //   From data.
        if (ref.offset() < start_of_data) {                   //     To code.
          if (!IsValidSelfReferenceDataToCode(block, ref))
            return false;
        } else {                                              //     To data.
          // The data in a code block should not be self-referential. It should
          // consist only of jump and case tables.
          return false;
        }
      }
    } else {                                                  // External.
      if (ref_it->first->type() == BlockGraph::CODE_BLOCK) {  //   From code.
        if (ref.offset() < start_of_data) {                   //     To code.
          if (!IsValidExternalReferenceCodeBlockToCode(block, ref))
            return false;
        } else {                                              //     To data.
          // No code block should ever have a pointer to data internal to
          // a code block.
          return false;
        }
      } else {                                                //   From data.
        if (ref.offset() < start_of_data) {                   //     To code.
          if (!IsValidExternalReferenceDataBlockToCode(block, ref))
            return false;
        } else {                                              //     To data.
          // No data block should ever have a pointer to data internal to
          // a code block.
          return false;
        }
      }
    }
  }

  // If there are leftover data labels that have not been referenced then we
  // are not consistent with CL.EXE compiled code.
  if (!data_label_offsets.empty())
    return false;

  return true;
}

bool CodeBlockIsClConsistent(
    const block_graph::BlockGraph::Block* block) {
  DCHECK(block != NULL);
  DCHECK_EQ(BlockGraph::CODE_BLOCK, block->type());

  if (!CodeBlockAttributesAreClConsistent(block))
    return false;
  if (!CodeBlockReferencesAreClConsistent(block))
    return false;
  if (!CodeBlockReferrersAreClConsistent(block))
    return false;

  return true;
}

bool CodeBlockIsBasicBlockDecomposable(
    const block_graph::BlockGraph::Block* block) {
  DCHECK(block != NULL);
  DCHECK_EQ(BlockGraph::CODE_BLOCK, block->type());

  // If the block was built by our toolchain it's inherently safe.
  if (block->attributes() & BlockGraph::BUILT_BY_SYZYGY)
    return true;

  if (!CodeBlockIsClConsistent(block))
    return false;

  return true;
}

}  // namespace pe
