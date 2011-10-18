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
//
// Decomposes an image, then dumps the blocks and references to stdout.
#include <iostream>
#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/file_path.h"
#include "base/string_util.h"
#include "syzygy/core/block_graph.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/pe_file.h"

using core::BlockGraph;
using core::RelativeAddress;
using pe::Decomposer;
using pe::PEFile;

// Given @p address_space, dump it in text format to @p str. Also, increment
// @p num_refs with the count of the number of block references in the address
// space if @p num_refs is not NULL.
void DumpAddressSpaceToText(const BlockGraph::AddressSpace& address_space,
                            std::ostream& str,
                            size_t* num_refs) {
  BlockGraph::AddressSpace::RangeMap::const_iterator block_it(
      address_space.address_space_impl().ranges().begin());
  BlockGraph::AddressSpace::RangeMap::const_iterator block_end(
      address_space.address_space_impl().ranges().end());

  size_t refs = 0;
  for (; block_it != block_end; ++block_it) {
    const BlockGraph::Block* block = block_it->second;
    RelativeAddress addr = block_it->first.start();

    str << StringPrintf("0x%08X(%d): %s\n",
                        addr.value(),
                        block->size(),
                        block->name());

    BlockGraph::Block::LabelMap::const_iterator
        label_it(block->labels().begin());
    for (; label_it != block->labels().end(); ++label_it) {
      str << "\t" << StringPrintf("+0x%04X: %s\n",
                                  label_it->first,
                                  label_it->second.c_str());
    }

    BlockGraph::Block::ReferenceMap::const_iterator ref_it(
        block->references().begin());
    for (; ref_it != block->references().end(); ++ref_it) {
      ++refs;
      const BlockGraph::Reference& ref = ref_it->second;
      if (ref.offset() == 0) {
        str << StringPrintf("\t+0x%04X->%s(%d)\n",
                            ref_it->first,
                            ref.referenced()->name(),
                            ref.size());
      } else {
        // See if there's a label at the desination's offset, and if so
        // use that in preference to a raw numeric offset.
        BlockGraph::Block::LabelMap::const_iterator label =
            ref.referenced()->labels().find(ref.offset());
        if (label != ref.referenced()->labels().end()) {
          str << StringPrintf("\t+0x%04X->%s:%s(%d)\n",
                              ref_it->first,
                              ref.referenced()->name(),
                              label->second.c_str(),
                              ref.size());
        } else {
          str << StringPrintf("\t+0x%04X->%s+0x%04X(%d)\n",
                              ref_it->first,
                              ref.referenced()->name(),
                              ref.offset(),
                              ref.size());
        }
      }
    }
  }
  if (num_refs != NULL)
    *num_refs = refs;
}

bool DumpImageToText(const FilePath& image_path,
                     std::ostream& str,
                     bool basic_block_decomposition) {
  // Load the image file.
  PEFile image_file;
  if (!image_file.Init(image_path)) {
    LOG(ERROR) << "Unable to initialize image " << image_path.value();
    return false;
  }

  // And decompose it to a DecomposedImage instance.
  Decomposer decomposer(image_file, image_path);
  Decomposer::DecomposedImage decomposed;
  if (!decomposer.Decompose(&decomposed, NULL)) {
    LOG(ERROR) << "Unable to decompose image \"" << image_path.value() << "\".";
    return false;
  }

  size_t num_refs = 0;
  DumpAddressSpaceToText(decomposed.address_space, str, &num_refs);

  str << "Discovered: " << decomposed.image.blocks().size() << " blocks\n"
      << "and " << num_refs << " references.";

  if (basic_block_decomposition) {
    Decomposer::BasicBlockBreakdown breakdown;

    if (!decomposer.BasicBlockDecompose(decomposed, &breakdown)) {
      LOG(ERROR) << "Unable to decompose basic blocks for image \""
                 << image_path.value() << "\".";
      return false;
    }

    str << "\n\nBASIC BLOCKS:\n\n";
    DumpAddressSpaceToText(breakdown.basic_block_address_space, str, NULL);

    str << "Discovered: " << breakdown.basic_block_graph.blocks().size()
        << " basic blocks.";
  }

  return true;
}

int Usage(char** argv, const char* message) {
  if (message != NULL) {
    std::cout << message << std::endl << std::endl;
  }

  std::cout <<
      "Usage: " << argv[0] << " [options]" << std::endl;
  std::cout <<
      "  A tool that uses symbol information and disassembly to decompose a\n"
      "  PE image file into discrete blocks of code (and data), and to infer\n"
      "  the references between them.\n"
      "\n"
      "Available options\n"
      "  --image=<image file>\n"
      "  --bb\t(Enables basic block decomposition)\n";

  return 1;
}

int main(int argc, char** argv) {
  HRESULT hr = ::CoInitialize(NULL);
  if (FAILED(hr)) {
    LOG(ERROR) << "CoInitialize failed with " << hr;
    return 1;
  }

  base::AtExitManager at_exit_manager;
  CommandLine::Init(argc, argv);

  CommandLine* cmd_line = CommandLine::ForCurrentProcess();
  DCHECK(cmd_line != NULL);

  std::wstring image_file = cmd_line->GetSwitchValueNative("image");
  if (image_file.empty())
    return Usage(argv, "You must provide the path to an image file.");

  bool basic_block_decomposition = cmd_line->HasSwitch("bb");

  return DumpImageToText(FilePath(image_file),
                         std::cout,
                         basic_block_decomposition) ? 0 : 1;
}
