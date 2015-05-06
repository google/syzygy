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
//
// The HotPatchingDecomposer decomposes a loaded module into an ImageLayout and
// its corresponding BlockGraph. The module must have been instrumented with
// PEHotPatchingTransform first. The module must not be unloaded from memory
// while decomposing and while using the resulting block graph as the contents
// of the blocks are backed by their actual memory.
//
// The decomposer first reads the hot patching metadata to obtain the location
// of the blocks in memory.
//
// Each decomposed block will have a code label to its beginning. If the block
// contains data, an additional data label will be inserted at the first
// data byte.
//
// Inter-block PC-relative references and in-block absolute references must be
// recovered before passing the resulting block graph to a basic block
// decomposer. In-block PC-relative references are automatically inserted by
// the basic block decomposer. We expect that inter-block PC-relative references
// are used only as arguments of direct jump instructions. In-block absolute
// references are used for referring to the jump and case tables and referencing
// in-block code in the jump tables.
//
// To recover these references we apply the following algorithm:
// - The code part of each block will be disassembled and examined:
//   - We add all 4-byte PC-relative references from immediate arguments of
//     branch and call instructions. We create 1-byte long dummy code blocks
//     marked with the BUILT_BY_UNSUPPORTED_COMPILER attribute for the
//     references that point to blocks that are not in the metadata.
//   - We recognize jump table references in the displacement of specific
//     indirect jump instructions. If the displacement can be interpreted as
//     a reference to the data part of the block, we add the absolute reference
//     and also insert a label for the jump table.
//   - We recognize case table references in the displacement of specific
//     MOVZX instructions. If the displacement can be interpreted as a reference
//     to the data part of the block, we add the absolute reference and also
//     insert a label for the case table.
// - The data part of the block is supposed to contain only jump tables and case
//   tables. Only jump tables contain references, and during the disassembly of
//   the code part we already recovered the locations of these. Jump tables
//   contain absolute references. We only recover the in-block absolute
//   references by inspecting each 4-byte long position in the jump table and
//   adding a reference if it can be interpreted as a pointer pointing inside
//   the block.
//
// NOTE: Currently, inter-block absolute references are not recovered.
//     Recovering (at least some of) them would allow avoiding the double
//     indirection when hot patched blocks call each other.

#ifndef SYZYGY_PE_HOT_PATCHING_DECOMPOSER_H_
#define SYZYGY_PE_HOT_PATCHING_DECOMPOSER_H_

#include <memory>
#include <unordered_map>

#include "base/win/pe_image.h"
#include "syzygy/block_graph/hot_patching_metadata.h"
#include "syzygy/core/disassembler_util.h"
#include "syzygy/pe/image_layout.h"

namespace pe {

class HotPatchingDecomposer {
 public:
  typedef block_graph::BlockGraph BlockGraph;
  typedef std::unordered_map<const IMAGE_SECTION_HEADER*, BlockGraph::SectionId>
      SectionIdMap;

  // Constructs a hot patching decomposer for a given module.
  // @param module The handle of the module to decompose.
  explicit HotPatchingDecomposer(HMODULE module);

  ~HotPatchingDecomposer();

  // Decomposes the module into the image layout.
  // @param image_layout The image layout to decompose into.
  bool Decompose(ImageLayout* image_layout);

 protected:
  typedef block_graph::BlockGraph::BlockType BlockType;
  typedef core::RelativeAddress RelativeAddress;

  // Creates a new block with the given properties, and attaches the
  // data to it. This assumes that no conflicting block exists.
  BlockGraph::Block* CreateBlock(BlockType type,
                                 RelativeAddress address,
                                 BlockGraph::Size size,
                                 const base::StringPiece& name);

  // This function disassembles a hot patchable block and recovers inter-block
  // PC-relative references and in-block absolute references originating in the
  // code by examining the instructions. Jump table and case table labels are
  // also recovered.
  // @param block The block to disassemble.
  // @param code_size The number of bytes that should be interpreted as code.
  bool InferCodeReferences(BlockGraph::Block* block, size_t code_size);

  // Recover in-block absolute references originating in jump tables.
  // @param block The block to examine.
  // @param code_size The number of bytes that should be interpreted as code.
  bool InferJumpTableReferences(BlockGraph::Block* block, size_t code_size);

  // Create the blocks with the help of the hot patching metadata.
  bool LoadHotPatchableBlocks();

  // Create sections in the image layout and the underlying block-graph.
  bool LoadSectionInformation();

  // Parse the case table reference if the instruction is a case table read.
  //
  // We expect that case tables are used by instructions in the following
  // form: MOVZX EAX, BYTE [ECX+<case-table-address>] where
  // <case-table-address> is an address inside the block, after the code.
  // Any register can stand in place of EAX and ECX. If we encounter an
  // instruction in this form we insert an absolute reference to the block
  // itself with the proper offset. We also insert a case table label, this
  // allows us to separate jump table entries from case table entries when
  // creating jump table references.
  //
  // @param block The block containing the instruction.
  // @param offset The offset of the instruction.
  // @param inst The instruction to parse.
  // @param code_size The size of the code in the block.
  // @param parse Output parameter, true if the instruction was recognized as
  //     a case table read.
  // @returns true if no error occurred (not a case table instruction or
  //     successfully added the reference), false on failure.
  bool ParseCaseTableRead(BlockGraph::Block* block,
                          BlockGraph::Offset offset,
                          const _DInst &inst,
                          size_t code_size,
                          bool* parsed);

  // Parse the in-block absolute reference to the jump table if the instruction
  // is a jump using a jump table.
  //
  // We expect that jump tables are used by instructions in the following
  // form: JMP DWORD [EAX*4+<jump-table-address>] where
  // <jump-table-address> is an address inside the block, after the code.
  // Any register can stand in place of EAX. If we encounter an
  // instruction in this form we insert an absolute reference to the
  // block itself with the proper offset. We also insert a jump table
  // label because basic block decomposer expects these labels at branch
  // reference targets.
  //
  // @param block The block containing the instruction.
  // @param offset The offset of the instruction.
  // @param inst The instruction to parse.
  // @param code_size The size of the code in the block.
  // @param parse Output parameter, true if the instruction was recognized as
  //     a jump table read.
  // @returns true if no error occurred (not a jump table instruction or
  //     successfully added the reference), false on failure.
  bool ParseJumpTableCall(BlockGraph::Block* block,
                          BlockGraph::Offset offset,
                          const _DInst &inst,
                          size_t code_size,
                          bool* parsed);

  // Parse the jump and call instructions and recover PC-relative reference
  // from their immediate arguments. This also creates dummy blocks for
  // referred blocks not in the image layout. The dummy blocks will be
  // 1-byte-long code blocks backed by the actual memory at the location of
  // the target of the reference. They will also have the
  // BUILT_BY_UNSUPPORTED_COMPILER attribute set to differentiate them from
  // other blocks and to mark them that their contents should not be
  // interpreted.
  // @param block The block containing the instruction.
  // @param offset The offset of the instruction.
  // @param inst The instruction to parse.
  // @param parse Output parameter, true if the instruction was recognized as
  //     a PC-relative branch or call instruction.
  // @returns true if no error occurred (even if no reference added), false
  //     on failure.
  bool ParsePCRelativeBranchAndCallInstuction(BlockGraph::Block* block,
                                              BlockGraph::Offset offset,
                                              const _DInst &inst,
                                              bool* parsed);

  // This function uses the hot patching block metadata to create the
  // corresponding code block in the block graph.
  // @param block_metadata Metadata for a single code block.
  BlockGraph::Block* ProcessHotPatchableCodeBlock(
      const block_graph::HotPatchingBlockMetadata& block_metadata);

 private:
  // The image layout that we decompose into.
  ImageLayout* image_layout_;

  // The address space of the image layout.
  BlockGraph::AddressSpace* image_;

  // This variable is used to generate increasing IDs for the code blocks.
  size_t last_code_block_id_;

  // The handle to the module being decomposed.
  HMODULE module_;

  // The PEImage object representing the module to be decomposed.
  std::unique_ptr<base::win::PEImage> pe_image_;

  // Maps the section header addresses to section ids.
  SectionIdMap section_index_;

  DISALLOW_COPY_AND_ASSIGN(HotPatchingDecomposer);
};

}  // namespace pe

#endif  // SYZYGY_PE_HOT_PATCHING_DECOMPOSER_H_
