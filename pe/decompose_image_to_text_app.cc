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

#include "syzygy/pe/decompose_image_to_text_app.h"

#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/pe_file.h"

namespace pe {

using block_graph::BlockGraph;
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
  "  --image=<image file>\n";

}  // namespace

void DecomposeImageToTextApp::PrintUsage(const FilePath& program,
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

  return true;
}

int DecomposeImageToTextApp::Run() {
  DCHECK(!image_path_.empty());

  return DumpImageToText(image_path_, out());
}

void DecomposeImageToTextApp::DumpAddressSpaceToText(
    const BlockGraph::AddressSpace& address_space,
    FILE* out, size_t* num_refs) {
  BlockGraph::AddressSpace::RangeMap::const_iterator block_it(
    address_space.address_space_impl().ranges().begin());
  BlockGraph::AddressSpace::RangeMap::const_iterator block_end(
    address_space.address_space_impl().ranges().end());

  size_t refs = 0;
  for (; block_it != block_end; ++block_it) {
    const BlockGraph::Block* block = block_it->second;
    RelativeAddress addr = block_it->first.start();

    ::fprintf(out, "0x%08X(%d): %s\n",
              addr.value(), block->size(), block->name().c_str());

    BlockGraph::Block::LabelMap::const_iterator
        label_it(block->labels().begin());
    for (; label_it != block->labels().end(); ++label_it) {
      ::fprintf(out, "\t+0x%04X: %s\n",
                label_it->first,
                label_it->second.ToString().c_str());
    }

    BlockGraph::Block::ReferenceMap::const_iterator ref_it(
        block->references().begin());
    for (; ref_it != block->references().end(); ++ref_it) {
      ++refs;
      const BlockGraph::Reference& ref = ref_it->second;
      if (ref.offset() == 0) {
        ::fprintf(out, "\t+0x%04X->%s(%d)\n",
                  ref_it->first,
                  ref.referenced()->name().c_str(),
                  ref.size());
      } else {
        // See if there's a label at the desination's offset, and if so
        // use that in preference to a raw numeric offset.
        BlockGraph::Block::LabelMap::const_iterator label =
            ref.referenced()->labels().find(ref.offset());
        if (label != ref.referenced()->labels().end()) {
          ::fprintf(out, "\t+0x%04X->%s:%s[%d]\n",
                    ref_it->first,
                    ref.referenced()->name().c_str(),
                    label->second.ToString().c_str(),
                    ref.size());
        } else {
          ::fprintf(out, "\t+0x%04X->%s+0x%04X(%d)\n",
                    ref_it->first,
                    ref.referenced()->name().c_str(),
                    ref.offset(),
                    ref.size());
        }
      }
    }
  }
  if (num_refs != NULL)
    *num_refs = refs;
}

bool DecomposeImageToTextApp::DumpImageToText(const FilePath& image_path,
                                              FILE* out) {
  // Load the image file.
  PEFile image_file;
  if (!image_file.Init(image_path)) {
    LOG(ERROR) << "Unable to initialize image " << image_path.value();
    return false;
  }

  // And decompose it to an ImageLayout.
  Decomposer decomposer(image_file);
  BlockGraph block_graph;
  ImageLayout image_layout(&block_graph);
  if (!decomposer.Decompose(&image_layout)) {
    LOG(ERROR) << "Unable to decompose image \"" << image_path.value() << "\".";
    return false;
  }

  size_t num_refs = 0;
  DumpAddressSpaceToText(image_layout.blocks, out, &num_refs);

  ::fprintf(out, "Discovered: %d blocks\nand %d references.\n",
            block_graph.blocks().size(),
            num_refs);

  return true;
}

}  // namespace pe
