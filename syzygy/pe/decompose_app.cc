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
// Decomposes an image and serializes the decomposed image to file.

#include "syzygy/pe/decompose_app.h"

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/file_path.h"
#include "base/file_util.h"
#include "base/string_util.h"
#include "base/time.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/pe_file.h"

namespace pe {

using block_graph::BlockGraph;
using common::ScopedTimeLogger;

namespace {

const char kUsageFormatStr[] =
    "Usage: %ls [options]\n"
    "\n"
    "  A tool that uses symbol information and disassembly to decompose a\n"
    "  PE image file into discrete blocks of code (and data), and to infer\n"
    "  the references between them.\n"
    "\n"
    "Required parameters\n"
    "  --image=<image file>\n"
    "Optional parameters\n"
    "  --missing-contribs=<output file>\n"
    "    Outputs a list of blocks (and their symbol information) that were\n"
    "    not parsed from section contributions.\n"
    "  --output=<output file>\n"
    "    The location of output file. If not specified, will append\n"
    "    '.bg' to the image file.\n"
    "  --benchmark-load\n"
    "    Causes the output to be deserialized after serialization,\n"
    "    for benchmarking.\n";

}  // namespace

void DecomposeApp::PrintUsage(const FilePath& program,
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
    output_path_ = FilePath(image_path_.value() + L".bg");
    LOG(INFO) << "Inferring output path from image path.";
  }

  missing_contribs_path_ = cmd_line->GetSwitchValuePath("missing-contribs");
  benchmark_load_ = cmd_line->HasSwitch("benchmark-load");

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

  // Dump missing session contribs if required.
  if (!missing_contribs_path_.empty()) {
    LOG(INFO) << "Writing missing section contributions to \""
              << missing_contribs_path_.value() << "\".";
    if (!DumpMissingSectionContributions(missing_contribs_path_,
                                         image_layout.blocks)) {
      return 1;
    }
  }

  // Save the decomposition do the output path.
  {
    ScopedTimeLogger scoped_time_logger("Saving decomposed image");
    if (!SaveDecomposedImage(pe_file, block_graph, image_layout, output_path_))
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

bool DecomposeApp::DumpBlockSet(const BlockSet& set, FILE* file) {
  DCHECK(file != NULL);

  BlockSet::const_iterator it = set.begin();
  for (; it != set.end(); ++it) {
    if (fprintf(file, "    0x%08X: %s (%s)\n", (*it)->addr().value(),
                (*it)->name(),
                BlockGraph::BlockTypeToString((*it)->type())) < 0) {
      return false;
    }
  }

  return true;
}

bool DecomposeApp::DumpBlock(const BlockGraph::Block* block, FILE* file) {
  DCHECK(block != NULL);
  DCHECK(file != NULL);

  size_t base = block->addr().value();
  if (fprintf(file,
              "0x%08X(%d): %s (%s)\n",
              base,
              block->size(),
              block->name().c_str(),
              BlockGraph::BlockTypeToString(block->type())) < 0) {
    return false;
  }

  // Dump any labels.
  if (block->labels().size() > 0) {
    BlockGraph::Block::LabelMap::const_iterator label_it =
        block->labels().begin();
    if (fprintf(file, "  Labels:\n") < 0)
      return false;
    for (; label_it != block->labels().end(); ++label_it) {
      if (fprintf(file, "    0x%08x: %s\n", base + label_it->first,
                  label_it->second.ToString().c_str()) < 0)
        return false;
    }
  }

  // Get a list of incoming referrers. We don't care about offsets, but rather
  // unique referring blocks.
  if (block->referrers().size() > 0) {
    BlockSet blocks;
    BlockGraph::Block::ReferrerSet::const_iterator iref_it =
        block->referrers().begin();
    for (; iref_it != block->referrers().end(); ++iref_it) {
      DCHECK(iref_it->first != NULL);
      blocks.insert(iref_it->first);
    }
    if (fprintf(file, "  Referrers:\n") < 0 ||
        !DumpBlockSet(blocks, file))
      return false;
  }

  // Dump the outgoing references. Once again, we don't really care about
  // offsets.
  if (block->references().size() > 0) {
    BlockSet blocks;
    BlockGraph::Block::ReferenceMap::const_iterator oref_it =
        block->references().begin();
    for (; oref_it != block->references().end(); ++oref_it) {
      DCHECK(oref_it->second.referenced() != NULL);
      blocks.insert(oref_it->second.referenced());
    }
    if (fprintf(file, "  References:\n") < 0 ||
        !DumpBlockSet(blocks, file))
      return false;
  }

  return true;
}

bool DecomposeApp::DumpMissingSectionContributions(const FilePath& path,
                                                   const AddressSpace& blocks) {
  file_util::ScopedFILE out_file(file_util::OpenFile(path, "wb"));
  BlockGraph::AddressSpace::RangeMapConstIter it =
      blocks.begin();

  BlockGraph::BlockAttributes skip_mask =
      BlockGraph::SECTION_CONTRIB | BlockGraph::PADDING_BLOCK |
      BlockGraph::PE_PARSED;

  for (; it != blocks.end(); ++it) {
    const BlockGraph::Block* block = it->second;
    if (block->attributes() & skip_mask)
      continue;

    if (!DumpBlock(block, out_file.get())) {
      LOG(ERROR) << "DumpBlock failed.";
      return false;
    }
  }

  return true;
}

bool DecomposeApp::SaveDecomposedImage(const pe::PEFile& pe_file,
                                       const BlockGraph& block_graph,
                                       const pe::ImageLayout& image_layout,
                                       const FilePath& output_path) {
  file_util::ScopedFILE out_file(file_util::OpenFile(output_path, "wb"));
  core::FileOutStream out_stream(out_file.get());
  core::NativeBinaryOutArchive out_archive(&out_stream);
  if (!pe::SaveDecomposition(pe_file,
                             block_graph,
                             image_layout,
                             &out_archive)) {
      return false;
  }

  if (!out_archive.Flush())
    return false;

  return true;
}

bool DecomposeApp::LoadDecomposedImage(const FilePath& file_path) {
  pe::PEFile pe_file;
  BlockGraph block_graph;
  pe::ImageLayout image_layout(&block_graph);

  file_util::ScopedFILE in_file(file_util::OpenFile(file_path, "rb"));
  core::FileInStream in_stream(in_file.get());
  core::NativeBinaryInArchive archive(&in_stream);
  if (!pe::LoadDecomposition(&archive,
                             &pe_file,
                             &block_graph,
                             &image_layout)) {
    LOG(ERROR) << "Unable to load image decomposition.";
    return false;
  }

  LOG(INFO) << "Successfully loaded image decomposition.";
  return true;
}

}  // namespace pe
