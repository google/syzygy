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
// Decomposes an image and serializes the decomposed image to file.

#include "syzygy/pe/decompose_app.h"

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/file_util.h"
#include "base/files/file_path.h"
#include "base/strings/string_util.h"
#include "base/time/time.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/pe/serialization.h"

namespace pe {

using block_graph::BlockGraph;
using block_graph::BlockGraphSerializer;
using common::ScopedTimeLogger;

namespace {

const char kUsageFormatStr[] =
    "Usage: %ls [options]\n"
    "\n"
    "  A tool that uses symbol information and disassembly to decompose a\n"
    "  PE image file into discrete blocks of code (and data), and to infer\n"
    "  the references between them, serializing the resulting decomposition\n"
    "  for later use.\n"
    "\n"
    "Required parameters\n"
    "  --image=<image file>\n"
    "Optional parameters\n"
    "  --benchmark-load\n"
    "    Causes the output to be deserialized after serialization,\n"
    "    for benchmarking.\n"
    "  --graph-only\n"
    "    Causes the serialized output to only contain the block-graph, with\n"
    "    all data inlined. The PE file (and pe_lib) will not be needed to\n"
    "    deserialize the resulting file. Useful for producing canned unittest\n"
    "    data.\n"
    "  --output=<output file>\n"
    "    The location of output file. If not specified, will append\n"
    "    '.bg' to the image file.\n"
    "  --strip-strings\n"
    "    If specified then the serialized decomposition will not contain any\n"
    "    strings.\n";

}  // namespace

void DecomposeApp::PrintUsage(const base::FilePath& program,
                              const base::StringPiece& message) {
  if (!message.empty()) {
    ::fwrite(message.data(), 1, message.length(), out());
    ::fprintf(out(), "\n\n");
  }

  ::fprintf(out(), kUsageFormatStr, program.BaseName().value().c_str());
}

bool DecomposeApp::ParseCommandLine(const CommandLine* cmd_line) {
  DCHECK(cmd_line != NULL);

  if (cmd_line->HasSwitch("help")) {
    PrintUsage(cmd_line->GetProgram(), "");
    return false;
  }

  image_path_ = cmd_line->GetSwitchValuePath("image");
  if (image_path_.empty()) {
    PrintUsage(cmd_line->GetProgram(), "Must specify '--image' parameter!");
    return false;
  }

  // If no output file specified, use default.
  output_path_ = cmd_line->GetSwitchValuePath("output");
  if (output_path_.empty()) {
    output_path_ = base::FilePath(image_path_.value() + L".bg");
    LOG(INFO) << "Inferring output path from image path.";
  }

  benchmark_load_ = cmd_line->HasSwitch("benchmark-load");
  graph_only_ = cmd_line->HasSwitch("graph-only");
  strip_strings_ = cmd_line->HasSwitch("strip-strings");

  return true;
}

int DecomposeApp::Run() {
  LOG(INFO) << "Processing \"" << image_path_.value() << "\".";

  // Parse the PE File.
  pe::PEFile pe_file;
  {
    ScopedTimeLogger scoped_time_logger("Parsing PE file");
    if (!pe_file.Init(image_path_))
      return 1;
  }

  // Decompose the image.
  BlockGraph block_graph;
  pe::ImageLayout image_layout(&block_graph);
  pe::Decomposer decomposer(pe_file);
  {
    ScopedTimeLogger scoped_time_logger("Decomposing image");
    if (!decomposer.Decompose(&image_layout))
      return 1;
  }

  // Save the decomposition do the output path.
  {
    ScopedTimeLogger scoped_time_logger("Saving decomposed image");
    if (!SaveDecomposedImage(pe_file, image_layout, output_path_))
      return 1;
  }

  // If requested, benchmark the time it takes to reload the decomposition.
  if (benchmark_load_) {
    ScopedTimeLogger scoped_time_logger("Loading decomposed image");
    if (!LoadDecomposedImage(output_path_))
      return 1;
  }

  return 0;
}

bool DecomposeApp::SaveDecomposedImage(
    const pe::PEFile& pe_file, const pe::ImageLayout& image_layout,
    const base::FilePath& output_path) const {
  base::ScopedFILE out_file(base::OpenFile(output_path, "wb"));
  core::FileOutStream out_stream(out_file.get());
  core::NativeBinaryOutArchive out_archive(&out_stream);

  BlockGraphSerializer::Attributes attributes = 0;
  if (strip_strings_)
    attributes |= BlockGraphSerializer::OMIT_STRINGS;

  if (graph_only_) {
    BlockGraphSerializer bgs;
    bgs.set_attributes(attributes);
    bgs.set_data_mode(BlockGraphSerializer::OUTPUT_ALL_DATA);
    if (!bgs.Save(*image_layout.blocks.graph(), &out_archive)) {
      LOG(ERROR) << "Unable to save block-graph.";
      return false;
    }
  } else {
    if (!SaveBlockGraphAndImageLayout(pe_file, attributes, image_layout,
                                      &out_archive)) {
      LOG(ERROR) << "Unable to save image decomposition.";
      return false;
    }
  }

  if (!out_archive.Flush())
    return false;

  return true;
}

bool DecomposeApp::LoadDecomposedImage(const base::FilePath& file_path) const {
  pe::PEFile pe_file;
  BlockGraph block_graph;

  base::ScopedFILE in_file(base::OpenFile(file_path, "rb"));
  core::FileInStream in_stream(in_file.get());
  core::NativeBinaryInArchive in_archive(&in_stream);

  if (graph_only_) {
    BlockGraphSerializer bgs;
    if (!bgs.Load(&block_graph, &in_archive)) {
      LOG(ERROR) << "Unable to load block-graph.";
      return false;
    }
  } else {
    pe::ImageLayout image_layout(&block_graph);
    BlockGraphSerializer::Attributes attributes = 0;
    if (!LoadBlockGraphAndImageLayout(&pe_file, &attributes, &image_layout,
                                      &in_archive)) {
      LOG(ERROR) << "Unable to load image decomposition.";
      return false;
    }
  }

  LOG(INFO) << "Successfully loaded image decomposition.";
  return true;
}

}  // namespace pe
