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

#include "syzygy/pe/decompose_image_to_text_app.h"

#include "syzygy/block_graph/basic_block_decomposer.h"
#include "syzygy/pe/block_util.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/new_decomposer.h"
#include "syzygy/pe/pe_file.h"

#include "distorm.h"  // NOLINT

namespace pe {

using block_graph::BasicBlockDecomposer;
using core::RelativeAddress;
using pe::Decomposer;
using pe::ImageLayout;
using pe::PEFile;

namespace {

const char kUsageFormatStr[] =
  "Usage: %ls [options]\n"
  "\n"
  "  A tool that decomposes a given image file, and decomposes it to a\n"
  "  human-readable textual description.\n"
  "\n"
  "Available options\n"
  "  --basic-blocks\n"
  "    Breaks each function down to basic blocks and dumps it at that level.\n"
  "  --image=<image file>\n"
  "  --new-decomposer\n"
  "    Use the new decomposer.\n";

using block_graph::BlockGraph;
using block_graph::BasicBlock;
using block_graph::BasicCodeBlock;
using block_graph::BasicDataBlock;
using block_graph::BasicBlockReference;

void DumpReference(const BasicBlockReference& ref, FILE* out) {
  DCHECK(out != NULL);

  switch (ref.referred_type()) {
    case BasicBlockReference::REFERRED_TYPE_BLOCK: {
        const BlockGraph::Block* block = ref.block();
        if (ref.offset() == 0) {
          ::fprintf(out, " ; (%s)", block->name().c_str());
        } else if (ref.offset() < 0) {
          ::fprintf(out, " ; (%s%d)", block->name().c_str(), ref.offset());
        } else {
          BlockGraph::Label label;
          if (block->GetLabel(ref.offset(), &label)) {
            ::fprintf(out, " ; (%s:%s)",
                      block->name().c_str(),
                      label.ToString().c_str());
          } else {
            ::fprintf(out, " ; (%s+%d)", block->name().c_str(), ref.offset());
          }
        }
      }
      break;

    case BasicBlockReference::REFERRED_TYPE_BASIC_BLOCK: {
        const BasicBlock* bb = ref.basic_block();
        DCHECK_EQ(0, ref.offset());

        ::fprintf(out, " ; (%s)", bb->name().c_str());
      }
      break;

    case BasicBlockReference::REFERRED_TYPE_UNKNOWN:
    default:
      NOTREACHED() << "All references should be typed.";
      break;
  }
}

void HexDump(const uint8* data, size_t size, FILE* out) {
  for (size_t i = 0; i < size; ++i)
    ::fprintf(out, "%02x", data[i]);
}

}  // namespace


DecomposeImageToTextApp::DecomposeImageToTextApp()
    : common::AppImplBase("Image To Text Decomposer"),
      dump_basic_blocks_(false),
      use_new_decomposer_(false),
      num_refs_(0) {
}

void DecomposeImageToTextApp::PrintUsage(const base::FilePath& program,
                                         const base::StringPiece& message) {
  if (!message.empty()) {
    ::fwrite(message.data(), 1, message.length(), out());
    ::fprintf(out(), "\n\n");
  }

  ::fprintf(out(), kUsageFormatStr, program.BaseName().value().c_str());
}

bool DecomposeImageToTextApp::ParseCommandLine(
    const CommandLine* cmd_line) {
  image_path_ = cmd_line->GetSwitchValuePath("image");
  if (image_path_.empty()) {
    PrintUsage(cmd_line->GetProgram(),
               "You must provide the path to an image file.");
    return false;
  }

  dump_basic_blocks_ = cmd_line->HasSwitch("basic-blocks");

  use_new_decomposer_ = cmd_line->HasSwitch("new-decomposer");

  return true;
}

int DecomposeImageToTextApp::Run() {
  DCHECK(!image_path_.empty());

  if (!DumpImageToText(image_path_))
    return 1;

  return 0;
}

void DecomposeImageToTextApp::DumpAddressSpaceToText(
    const BlockGraph::AddressSpace& address_space) {
  BlockGraph::AddressSpace::RangeMap::const_iterator block_it(
    address_space.address_space_impl().ranges().begin());
  BlockGraph::AddressSpace::RangeMap::const_iterator block_end(
    address_space.address_space_impl().ranges().end());

  for (; block_it != block_end; ++block_it) {
    const BlockGraph::Block* block = block_it->second;
    RelativeAddress addr = block_it->first.start();

    DumpBlockToText(addr, block);
  }
}

void DecomposeImageToTextApp::DumpSubGraphToText(
    BasicBlockSubGraph& subgraph) {
  typedef BasicBlockSubGraph::BlockDescription BlockDescription;
  typedef BasicBlockSubGraph::BasicBlockOrdering BasicBlockOrdering;
  typedef block_graph::BasicBlock BasicBlock;
  typedef block_graph::BasicBlockReference BasicBlockReference;

  // Post-decomposition we have a single description only.
  DCHECK_EQ(1U, subgraph.block_descriptions().size());
  DCHECK(subgraph.original_block() != NULL);

  const BlockGraph::Block* block = subgraph.original_block();
  const BlockDescription& descr = subgraph.block_descriptions().front();
  BasicBlockOrdering::const_iterator bb_it(descr.basic_block_order.begin());
  for (; bb_it != descr.basic_block_order.end(); ++bb_it) {
    const BasicBlock* bb = *bb_it;
    DCHECK(bb != NULL);

    // Print the BB's name for an identifying label.
    ::fprintf(out(), "%s:\n", bb->name().c_str());

    switch (bb->type()) {
      case BasicBlock::BASIC_CODE_BLOCK:
        DumpCodeBBToText(block, BasicCodeBlock::Cast(bb));
        break;

      case BasicBlock::BASIC_DATA_BLOCK:
        DumpDataBBToText(block, BasicDataBlock::Cast(bb));
        break;

      default:
        NOTREACHED();
        break;
    }
  }
}

void DecomposeImageToTextApp::DumpCodeBBToText(
    const BlockGraph::Block* block, const BasicCodeBlock* bb) {
  BasicBlock::Instructions::const_iterator instr_it(
      bb->instructions().begin());
  for (; instr_it != bb->instructions().end(); ++instr_it) {
    const block_graph::Instruction& instr = *instr_it;

    _CodeInfo code = {};
    code.codeOffset = 0;
    code.code = instr.data();
    code.codeLen = instr.size();
    code.dt = Decode32Bits;
    _DecodedInst decoded = {};
    _DInst dinst = instr.representation();

    dinst.addr = 0;
    distorm_format(&code, &dinst, &decoded);
    ::fprintf(out(), "  %-14s %s %s",
              decoded.instructionHex.p,
              decoded.mnemonic.p,
              decoded.operands.p);

    BasicBlock::BasicBlockReferenceMap::const_iterator ref_it(
        instr_it->references().begin());
    for (; ref_it != instr_it->references().end(); ++ref_it) {
      DumpReference(ref_it->second, out());
    }
    ::fprintf(out(), "\n");
  }

  BasicBlock::Successors::const_iterator succ_it(bb->successors().begin());
  for (; succ_it != bb->successors().end(); ++succ_it) {
    const block_graph::Successor& succ = *succ_it;

    // Shortcut alert! As we know the blocks are in-order right after
    // decomposition, we can get away with just disassembling the (sole)
    // successor that has a size.
    // The other successor, if any, will be fall-through.
    if (succ.instruction_size()) {
      _CodeInfo code = {};
      code.codeOffset = 0;
      code.code = block->data() + bb->offset() + bb->GetInstructionSize();
      code.codeLen = succ.instruction_size();
      code.dt = Decode32Bits;
      _DecodedInst decoded = {};
      _DInst instr = {};

      unsigned int count = 0;
      distorm_decompose64(&code, &instr, 1, &count);
      instr.addr = 0;
      distorm_format(&code, &instr, &decoded);
      ::fprintf(out(), "  %-14s %s %s",
                decoded.instructionHex.p,
                decoded.mnemonic.p,
                decoded.operands.p);

      DumpReference(succ.reference(), out());
      ::fprintf(out(), "\n");
    }
  }
}

void DecomposeImageToTextApp::DumpDataBBToText(
    const BlockGraph::Block* block, const BasicDataBlock* bb) {
  // Here we proceed by dumping a hex chunk up to the next reference, then
  // the reference and so on.
  size_t curr_start = 0;

  while (curr_start < bb->size()) {
    BasicBlock::BasicBlockReferenceMap::const_iterator it(
        bb->references().lower_bound(curr_start));

    size_t next_chunk_end = bb->size();
    if (it != bb->references().end())
      next_chunk_end = it->first;
    if (next_chunk_end == curr_start) {
      // We're on a reference, dump it and it's reference.
      switch (it->second.size()) {
        case 1:
          ::fprintf(out(), "  DB ");
          break;
        case 2:
          ::fprintf(out(), "  DW ");
          break;
        case 4:
          ::fprintf(out(), "  DD ");
          break;
        default:
          NOTREACHED();
          break;
      }
      HexDump(bb->data() + curr_start, it->second.size(), out());
      DumpReference(it->second, out());
      ::fprintf(out(), "\n");

      curr_start += it->second.size();
    } else {
      if (next_chunk_end - curr_start > 16)
        next_chunk_end = curr_start + 16;

      ::fprintf(out(), "  DB ");
      HexDump(bb->data() + curr_start, next_chunk_end - curr_start, out());
      ::fprintf(out(), "\n");

      curr_start = next_chunk_end;
    }
  }
}

void DecomposeImageToTextApp::DumpBlockToText(
    core::RelativeAddress addr, const BlockGraph::Block* block) {
  ::fprintf(out(), "0x%08X(%d): %s\n",
            addr.value(),
            block->size(),
            block->name().c_str());

  // Attempt basic block decomposition if BB-dumping is requested.
  // Note that on success we return early from here.
  // TODO(siggi): Remove the cl consistent check and section contrib checks
  //     once the BB decomposer is no longer asserting on non-consistent inputs.
  if (dump_basic_blocks_ &&
      block->type() == BlockGraph::CODE_BLOCK &&
      block->attributes() == BlockGraph::SECTION_CONTRIB &&
      pe::CodeBlockIsClConsistent(block)) {
    BasicBlockSubGraph subgraph;
    BasicBlockDecomposer decomposer(block, &subgraph);

    if (decomposer.Decompose()) {
      DumpSubGraphToText(subgraph);
      return;
    }
    // Fall through on failure to decompose.
  }

  BlockGraph::Block::LabelMap::const_iterator
      label_it(block->labels().begin());
  for (; label_it != block->labels().end(); ++label_it) {
    ::fprintf(out(), "\t+0x%04X: %s\n",
              label_it->first,
              label_it->second.ToString().c_str());
  }

  BlockGraph::Block::ReferenceMap::const_iterator ref_it(
      block->references().begin());
  for (; ref_it != block->references().end(); ++ref_it) {
    ++num_refs_;
    const BlockGraph::Reference& ref = ref_it->second;
    if (ref.offset() == 0) {
      ::fprintf(out(), "\t+0x%04X->%s(%d)\n",
                ref_it->first,
                ref.referenced()->name().c_str(),
                ref.size());
    } else {
      // See if there's a label at the destination's offset, and if so
      // use that in preference to a raw numeric offset.
      BlockGraph::Block::LabelMap::const_iterator label =
          ref.referenced()->labels().find(ref.offset());
      if (label != ref.referenced()->labels().end()) {
        ::fprintf(out(), "\t+0x%04X->%s:%s[%d]\n",
                  ref_it->first,
                  ref.referenced()->name().c_str(),
                  label->second.ToString().c_str(),
                  ref.size());
      } else {
        ::fprintf(out(), "\t+0x%04X->%s+0x%04X(%d)\n",
                  ref_it->first,
                  ref.referenced()->name().c_str(),
                  ref.offset(),
                  ref.size());
      }
    }
  }
}

bool DecomposeImageToTextApp::DumpImageToText(
    const base::FilePath& image_path) {
  // Load the image file.
  PEFile image_file;
  if (!image_file.Init(image_path)) {
    LOG(ERROR) << "Unable to initialize image " << image_path.value();
    return false;
  }

  BlockGraph block_graph;
  ImageLayout image_layout(&block_graph);

 if (use_new_decomposer_) {
    LOG(INFO) << "Using new decomposer for decomposition.";
    NewDecomposer decomposer(image_file);
    if (!decomposer.Decompose(&image_layout)) {
      LOG(ERROR) << "Unable to decompose image \""
          << image_path.value() << "\".";
      return false;
    }
  } else {
    // And decompose it to an ImageLayout.
    Decomposer decomposer(image_file);
    if (!decomposer.Decompose(&image_layout)) {
      LOG(ERROR) << "Unable to decompose image \""
          << image_path.value() << "\".";
      return false;
    }
  }

  num_refs_ = 0;
  DumpAddressSpaceToText(image_layout.blocks);

  ::fprintf(out(), "Discovered: %d blocks\nand %d references.\n",
            block_graph.blocks().size(),
            num_refs_);

  return true;
}

}  // namespace pe
