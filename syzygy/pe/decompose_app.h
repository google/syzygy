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
// A command line application to decompose and image and serialize the
// decomposition to a file.

#ifndef SYZYGY_PE_DECOMPOSE_APP_H_
#define SYZYGY_PE_DECOMPOSE_APP_H_

#include "base/command_line.h"
#include "base/file_util.h"
#include "base/files/file_path.h"
#include "base/strings/string_piece.h"
#include "base/strings/string_util.h"
#include "base/time/time.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/common/application.h"
#include "syzygy/pe/image_layout.h"
#include "syzygy/pe/pe_file.h"


namespace pe {

// This class implements the decompose command-line utility.
//
// See the description given in DecomposeApp:::PrintUsage() for information
// about running this utility.
class DecomposeApp : public common::AppImplBase {
 public:
  typedef block_graph::BlockGraph::AddressSpace AddressSpace;
  typedef block_graph::BlockGraph::Block Block;
  typedef block_graph::BlockGraph BlockGraph;
  typedef std::set<const BlockGraph::Block*> BlockSet;
  typedef pe::ImageLayout ImageLayout;

  // @name Implementation of the AppImplBase interface.
  // @{
  DecomposeApp()
    : common::AppImplBase("Decomposer"),
      benchmark_load_(false),
      graph_only_(false),
      strip_strings_(false) {
  }

  bool ParseCommandLine(const CommandLine* command_line);

  int Run();
  // @}

 protected:
  // @name Utility functions
  // @{
  void PrintUsage(const base::FilePath& program,
                  const base::StringPiece& message);

  bool SaveDecomposedImage(const pe::PEFile& pe_file,
                           const ImageLayout& image_layout,
                           const base::FilePath& output_path) const;

  bool LoadDecomposedImage(const base::FilePath& file_path) const;
  // @}

  // @name Command-line options.
  // @{
  base::FilePath image_path_;
  base::FilePath output_path_;
  bool benchmark_load_;
  bool graph_only_;
  bool strip_strings_;
  // @}

 private:
  DISALLOW_COPY_AND_ASSIGN(DecomposeApp);
};

}  // namespace pe

#endif  // SYZYGY_PE_DECOMPOSE_APP_H_
