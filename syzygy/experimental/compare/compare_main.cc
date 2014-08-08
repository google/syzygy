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
// Compares two decomposed images for similarity.

#include <algorithm>
#include <iostream>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/file_util.h"
#include "base/strings/string_util.h"
#include "base/time/time.h"
#include "base/files/file_path.h"
#include "syzygy/common/syzygy_version.h"
#include "syzygy/core/serialization.h"
#include "syzygy/experimental/compare/compare.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/pe/serialization.h"

using block_graph::BlockGraph;
using block_graph::ConstBlockVector;
using experimental::BlockGraphMapping;

namespace {

int Usage(char** argv, const char* message) {
  if (message != NULL) {
    std::cout << message << std::endl << std::endl;
  }

  std::cout <<
      "Usage: " << argv[0] << " [options]" << std::endl;
  std::cout <<
      "  A tool that compares two decomposed images.\n"
      "\n"
      "Required parameters\n"
      "  --from=<bg file>\n"
      "  --to=<bg file>\n";

  return 1;
}

// Loads a decomposed image from the given file_path.
bool LoadDecomposition(const base::FilePath& file_path,
                       pe::PEFile* pe_file,
                       BlockGraph* block_graph,
                       pe::ImageLayout* image_layout) {
  DCHECK(!file_path.empty());
  DCHECK(pe_file != NULL);
  DCHECK(block_graph != NULL);
  DCHECK(image_layout != NULL);

  base::ScopedFILE from_file(base::OpenFile(file_path, "rb"));
  if (from_file.get() == NULL) {
    LOG(ERROR) << "Unable to open \"" << file_path.value() << "\" for reading.";
    return false;
  }

  LOG(INFO) << "Loading decomposition \"" << file_path.value() << "\".";
  core::FileInStream in_stream(from_file.get());
  core::NativeBinaryInArchive in_archive(&in_stream);
  block_graph::BlockGraphSerializer::Attributes attributes = 0;
  if (!LoadBlockGraphAndImageLayout(pe_file, &attributes, image_layout,
                                    &in_archive)) {
    LOG(ERROR) << "Failed to load serialized decomposition.";
    return false;
  }

  return true;
}

// This holds summary stats for a collection of blocks.
struct BlockStats {
  size_t net_blocks;
  size_t code_blocks;
  size_t data_blocks;
  size_t net_bytes;
  size_t code_bytes;
  size_t data_bytes;

  void Clear() {
    memset(this, 0, sizeof(BlockStats));
  }

  static const BlockGraph::BlockAttributes kSkipAttributes =
      BlockGraph::PADDING_BLOCK;

  void Update(const BlockGraph::Block* block) {
    DCHECK(block != NULL);

    if ((block->attributes() & kSkipAttributes) != 0)
      return;

    ++net_blocks;
    net_bytes += block->size();

    if (block->type() == BlockGraph::CODE_BLOCK) {
      ++code_blocks;
      code_bytes += block->size();
    } else if (block->type() == BlockGraph::DATA_BLOCK) {
      ++data_blocks;
      data_bytes += block->size();
    }
  }

  // Outputs these statistics.
  void Dump() {
    //      01234  01234567 (100.0%)  0123456789 (100.0%)
    printf("  Type   Count              Bytes\n");
    printf("  Code   %8d"   "           %10d\n", code_blocks, code_bytes);
    printf("  Data   %8d"   "           %10d\n", data_blocks, data_bytes);
    printf("  Total  %8d"   "           %10d\n", net_blocks, net_bytes);
  }

  // Outputs these statistics, comparing them to a provided baseline.
  void Dump(const BlockStats& other) {
    //        01234  01234567 (100.0%)  0123456789 (100.0%)
    printf("  Type   Count              Bytes\n");
    printf("  Code   %8d (%5.1f%%)  %10d (%5.1f%%)\n",
        code_blocks, 100.0 * code_blocks / other.code_blocks,
        code_bytes, 100.0 * code_bytes / other.code_bytes);
    printf("  Data   %8d (%5.1f%%)  %10d (%5.1f%%)\n",
        data_blocks, 100.0 * data_blocks / other.data_blocks,
        data_bytes, 100.0 * data_bytes / other.data_bytes);
    printf("  Total  %8d (%5.1f%%)  %10d (%5.1f%%)\n",
        net_blocks, 100.0 * net_blocks / other.net_blocks,
        net_bytes, 100.0 * net_bytes / other.net_bytes);
  }
};

// Aggregates block statistics for all blocks in a block graph.
void GetBlockGraphStats(const BlockGraph& bg, BlockStats* stats) {
  DCHECK(stats != NULL);

  stats->Clear();
  BlockGraph::BlockMap::const_iterator it = bg.blocks().begin();
  for (; it != bg.blocks().end(); ++it) {
    stats->Update(&it->second);
  }
}

// Aggregates block statistics for all blocks in a block graph mapping.
void GetMappingStats(const BlockGraphMapping& mapping,
                     BlockStats* stats) {
  DCHECK(stats != NULL);

  stats->Clear();
  BlockGraphMapping::const_iterator it = mapping.begin();
  for (; it != mapping.end(); ++it) {
    stats->Update(it->first);
  }
}

}  // namespace

int main(int argc, char** argv) {
  base::AtExitManager at_exit_manager;
  CommandLine::Init(argc, argv);

  logging::LoggingSettings settings;
  settings.logging_dest = logging::LOG_TO_SYSTEM_DEBUG_LOG;
  settings.lock_log = logging::DONT_LOCK_LOG_FILE;
  settings.delete_old = logging::APPEND_TO_OLD_LOG_FILE;
  if (!logging::InitLogging(settings))
    return 1;

  CommandLine* cmd_line = CommandLine::ForCurrentProcess();
  DCHECK(cmd_line != NULL);

  base::FilePath path_from = cmd_line->GetSwitchValuePath("from");
  base::FilePath path_to = cmd_line->GetSwitchValuePath("to");
  if (path_from.empty() || path_to.empty())
    return Usage(argv, "Must specify '--from' and '--to' parameters!");

  LOG(INFO) << "Toolchain version: "
            << common::kSyzygyVersion.GetVersionString() << ".";

  pe::PEFile pe_file_from;
  BlockGraph block_graph_from;
  pe::ImageLayout image_layout_from(&block_graph_from);
  if (!LoadDecomposition(path_from,
                         &pe_file_from,
                         &block_graph_from,
                         &image_layout_from)) {
    return 1;
  }

  pe::PEFile pe_file_to;
  BlockGraph block_graph_to;
  pe::ImageLayout image_layout_to(&block_graph_to);
  if (!LoadDecomposition(path_to,
                         &pe_file_to,
                         &block_graph_to,
                         &image_layout_to)) {
    return 1;
  }

  LOG(INFO) << "Generating block graph mapping.";

  BlockGraphMapping mapping;
  ConstBlockVector unmapped1, unmapped2;
  if (!experimental::BuildBlockGraphMapping(block_graph_from,
                                            block_graph_to,
                                            &mapping,
                                            &unmapped1,
                                            &unmapped2)) {
    LOG(ERROR) << "BuildBlockGraphMapping failed.";
    return 1;
  }

  LOG(INFO) << "Analyzing mapping.";
  BlockStats stats_from;
  BlockStats stats_to;
  BlockStats stats_mapping;
  GetBlockGraphStats(block_graph_from, &stats_from);
  GetBlockGraphStats(block_graph_to, &stats_to);
  GetMappingStats(mapping, &stats_mapping);

  printf("\nFROM\n");
  stats_from.Dump();

  printf("\nMAPPING AS PORTION OF FROM\n");
  stats_mapping.Dump(stats_from);

  printf("\nTO\n");
  stats_to.Dump();

  printf("\nMAPPING AS PORTION OF TO\n");
  stats_mapping.Dump(stats_to);

  return 0;
}
