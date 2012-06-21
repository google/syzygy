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
//
// A command line application to decompose an image to a human-readable,
// textual description.

#ifndef SYZYGY_PE_DECOMPOSE_IMAGE_TO_TEXT_APP_H_
#define SYZYGY_PE_DECOMPOSE_IMAGE_TO_TEXT_APP_H_

#include "base/file_path.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/common/application.h"

namespace pe {

// This class implements the decompose image to text command-line utility.
//
// See the description given in PrintUsage() for information about running
// this utility.
class DecomposeImageToTextApp : public common::AppImplBase {
 public:
  // @name Implementation of the AppImplBase interface.
  // @{
  bool ParseCommandLine(const CommandLine* command_line);

  int Run();
  // @}

 protected:
  typedef block_graph::BlockGraph BlockGraph;

  void DecomposeImageToTextApp::PrintUsage(const FilePath& program,
                                           const base::StringPiece& message);

  // Given @p address_space, dump it in text format to @p out. Also, increment
  // @p num_refs with the count of the number of block references in the address
  // space if @p num_refs is not NULL.
  void DumpAddressSpaceToText(const BlockGraph::AddressSpace& address_space,
                              FILE* out,
                              size_t* num_refs);

  // Dump the image at @p image_path to @p out.
  bool DumpImageToText(const FilePath& image_path, FILE* out);

  // The image to decompose.
  FilePath image_path_;
};

}  // namespace pe

#endif  // SYZYGY_PE_DECOMPOSE_IMAGE_TO_TEXT_APP_H_
