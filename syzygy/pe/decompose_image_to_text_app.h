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
// A command line application to decompose an image to a human-readable,
// textual description.

#ifndef SYZYGY_PE_DECOMPOSE_IMAGE_TO_TEXT_APP_H_
#define SYZYGY_PE_DECOMPOSE_IMAGE_TO_TEXT_APP_H_

#include "base/files/file_path.h"
#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/common/application.h"

namespace pe {

// This class implements the decompose image to text command-line utility.
//
// See the description given in PrintUsage() for information about running
// this utility.
class DecomposeImageToTextApp : public common::AppImplBase {
 public:
  DecomposeImageToTextApp();

  // @name Implementation of the AppImplBase interface.
  // @{
  bool ParseCommandLine(const CommandLine* command_line);

  int Run();
  // @}

 protected:
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::BasicBlock BasicBlock;
  typedef block_graph::BasicCodeBlock BasicCodeBlock;
  typedef block_graph::BasicDataBlock BasicDataBlock;
  typedef block_graph::BasicBlockSubGraph BasicBlockSubGraph;

  void PrintUsage(const base::FilePath& program,
                  const base::StringPiece& message);

  // Given @p address_space, dump it in text format to out().
  void DumpAddressSpaceToText(const BlockGraph::AddressSpace& address_space);

  // Given @p subgraph, dump it in text format to out().
  void DumpSubGraphToText(BasicBlockSubGraph& subgraph);

  // Given the code basic block @p bb, dump it in text format to out().
  void DumpCodeBBToText(const BlockGraph::Block* block,
                        const BasicCodeBlock* bb);
  // Given the data basic block @p bb, dump it in text format to out().
  void DumpDataBBToText(const BlockGraph::Block* block,
                        const BasicDataBlock* bb);

  // Dump @p block at @p addr in text format to out().
  void DumpBlockToText(core::RelativeAddress addr,
                       const BlockGraph::Block* block);

  // Dump the image at @p image_path to out().
  bool DumpImageToText(const base::FilePath& image_path);

  // The image to decompose.
  base::FilePath image_path_;

  // True if we're to dump basic block information.
  bool dump_basic_blocks_;

  // Number of references we've encountered.
  size_t num_refs_;
};

}  // namespace pe

#endif  // SYZYGY_PE_DECOMPOSE_IMAGE_TO_TEXT_APP_H_
