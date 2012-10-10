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

#include "syzygy/grinder/basic_block_entry_count_grinder.h"

#include <limits>

#include "base/file_path.h"
#include "base/json/json_reader.h"
#include "syzygy/common/basic_block_frequency_data.h"
#include "syzygy/common/syzygy_version.h"
#include "syzygy/core/json_file_writer.h"
#include "syzygy/pdb/pdb_reader.h"
#include "syzygy/pdb/pdb_util.h"
#include "syzygy/pe/find.h"
#include "syzygy/pe/metadata.h"
#include "syzygy/pe/pe_file.h"

namespace grinder {

namespace  {

using common::kSyzygyVersion;
using core::JSONFileWriter;
using basic_block_util::EntryCountMap;
using basic_block_util::EntryCountType;
using basic_block_util::EntryCountVector;
using basic_block_util::GetFrequency;
using basic_block_util::IsValidFrequencySize;
using basic_block_util::ModuleInformation;
using trace::parser::AbsoluteAddress64;

const char kMetadata[] = "metadata";
const char kNumBasicBlocks[] = "num_basic_blocks";
const char kEntryCounts[] = "entry_counts";

}  // namespace

BasicBlockEntryCountGrinder::BasicBlockEntryCountGrinder()
    : parser_(NULL),
      event_handler_errored_(false) {
}

bool BasicBlockEntryCountGrinder::ParseCommandLine(
    const CommandLine* command_line) {
  serializer_.set_pretty_print(command_line->HasSwitch("pretty-print"));
  return true;
}

void BasicBlockEntryCountGrinder::SetParser(Parser* parser) {
  DCHECK(parser != NULL);
  parser_ = parser;
}

bool BasicBlockEntryCountGrinder::Grind() {
  if (entry_count_map_.empty()) {
    LOG(ERROR) << "No basic-block frequency data was encountered.";
    return false;
  }

  return true;
}

bool BasicBlockEntryCountGrinder::OutputData(FILE* file) {
  DCHECK(file != NULL);

  BasicBlockEntryCountSerializer serializer;
  if (!serializer.SaveAsJson(entry_count_map_, file))
    return false;

  return true;
}

void BasicBlockEntryCountGrinder::OnBasicBlockFrequency(
    base::Time time,
    DWORD process_id,
    DWORD thread_id,
    const TraceBasicBlockFrequencyData* data) {
  DCHECK(data != NULL);
  DCHECK(parser_ != NULL);

  if (data->num_basic_blocks == 0) {
    LOG(INFO) << "Skipping empty basic block frequency data.";
    return;
  }

  if (!IsValidFrequencySize(data->frequency_size)) {
     LOG(ERROR) << "Basic block frequency data has invalid frequency_size ("
                << data->frequency_size << ").";
     event_handler_errored_ = true;
     return;
  }

  // Get the module information for which this BB frequency data belongs.
  const ModuleInformation* module_info = parser_->GetModuleInformation(
      process_id, AbsoluteAddress64(data->module_base_addr));
  if (module_info == NULL) {
    LOG(ERROR) << "Failed to find module information.";
    event_handler_errored_ = true;
    return;
  }

  UpdateBasicBlockEntryCount(module_info, data);
}

void BasicBlockEntryCountGrinder::UpdateBasicBlockEntryCount(
    const ModuleInformation* module_info,
    const TraceBasicBlockFrequencyData* data) {
  DCHECK(module_info != NULL);
  DCHECK(data != NULL);
  DCHECK_NE(0U, data->num_basic_blocks);
  DCHECK_EQ(data->module_base_addr,
            reinterpret_cast<ModuleAddr>(module_info->base_address));
  DCHECK_EQ(data->module_base_size, module_info->module_size);
  DCHECK_EQ(data->module_checksum, module_info->image_checksum);
  DCHECK_EQ(data->module_time_date_stamp, module_info->time_date_stamp);

  EntryCountVector& bb_entries = entry_count_map_[*module_info];
  if (bb_entries.size() != data->num_basic_blocks) {
    // This should be the first (and only) time we're initializing this
    // entry count vector.
    if (!bb_entries.empty()) {
     LOG(ERROR) << "Inconsistent number of data block observed for "
                << module_info->image_file_name << ".";
     event_handler_errored_ = true;
     return;
    }
    bb_entries.resize(data->num_basic_blocks, 0);
  }

  // Run over the BB frequency data and increment bb_entries for each basic
  // block using saturation arithmetic.
  for (size_t bb_id = 0; bb_id < data->num_basic_blocks; ++bb_id) {
    EntryCountType amount = GetFrequency(data, bb_id);
    EntryCountType& value = bb_entries[bb_id];
    value += std::min(
        amount, std::numeric_limits<EntryCountType>::max() - value);
  }
}

}  // namespace grinder
