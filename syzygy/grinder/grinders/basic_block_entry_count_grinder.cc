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

#include "syzygy/grinder/grinders/basic_block_entry_count_grinder.h"

#include <limits>

#include "base/files/file_path.h"
#include "base/json/json_reader.h"
#include "syzygy/common/indexed_frequency_data.h"
#include "syzygy/common/syzygy_version.h"
#include "syzygy/core/json_file_writer.h"
#include "syzygy/pdb/pdb_reader.h"
#include "syzygy/pdb/pdb_util.h"
#include "syzygy/pe/find.h"
#include "syzygy/pe/metadata.h"
#include "syzygy/pe/pe_file.h"

namespace grinder {
namespace grinders {

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

  if (!serializer_.SaveAsJson(entry_count_map_, file))
    return false;

  return true;
}

void BasicBlockEntryCountGrinder::OnIndexedFrequency(
    base::Time time,
    DWORD process_id,
    DWORD thread_id,
    const TraceIndexedFrequencyData* data) {
  DCHECK(data != NULL);
  DCHECK(parser_ != NULL);

  if (data->data_type != common::IndexedFrequencyData::BASIC_BLOCK_ENTRY &&
      data->data_type != common::IndexedFrequencyData::COVERAGE)
    return;

  if (data->num_entries == 0) {
    LOG(INFO) << "Skipping empty basic block frequency data.";
    return;
  }

  if (!basic_block_util::IsValidFrequencySize(data->frequency_size)) {
     LOG(ERROR) << "Basic block frequency data has invalid frequency_size ("
                << data->frequency_size << ").";
     event_handler_errored_ = true;
     return;
  }

  using trace::parser::AbsoluteAddress64;

  // Get the module information for which this BB frequency data belongs.
  const ModuleInformation* module_info = parser_->GetModuleInformation(
      process_id, AbsoluteAddress64(data->module_base_addr));
  if (module_info == NULL) {
    LOG(ERROR) << "Failed to find module information.";
    event_handler_errored_ = true;
    return;
  }

  const InstrumentedModuleInformation* instrumented_module =
      FindOrCreateInstrumentedModule(module_info);
  if (instrumented_module == NULL) {
    LOG(ERROR) << "Failed to find instrumented module "
               << module_info->image_file_name;
    event_handler_errored_ = true;
    return;
  }

  if (data->num_entries != instrumented_module->block_ranges.size()) {
    LOG(ERROR) << "Unexpected data size for instrumented module "
               << module_info->image_file_name;
    event_handler_errored_ = true;
    return;
  }

  UpdateBasicBlockEntryCount(*instrumented_module, data);
}

void BasicBlockEntryCountGrinder::UpdateBasicBlockEntryCount(
    const InstrumentedModuleInformation& instrumented_module,
    const TraceIndexedFrequencyData* data) {
  using basic_block_util::BasicBlockOffset;
  using basic_block_util::EntryCountType;
  using basic_block_util::EntryCountMap;
  using basic_block_util::GetFrequency;

  DCHECK(data != NULL);
  DCHECK_NE(0U, data->num_entries);

  DCHECK(data->data_type == common::IndexedFrequencyData::BASIC_BLOCK_ENTRY ||
         data->data_type == common::IndexedFrequencyData::COVERAGE);

  EntryCountMap& bb_entries =
      entry_count_map_[instrumented_module.original_module];

  // Run over the BB frequency data and increment bb_entries for each basic
  // block using saturation arithmetic.

  for (size_t bb_id = 0; bb_id < data->num_entries; ++bb_id) {
    EntryCountType amount = GetFrequency(data, bb_id);
    if (amount != 0) {
      BasicBlockOffset offs =
          instrumented_module.block_ranges[bb_id].start().value();

      EntryCountType& value = bb_entries[offs];
      if (amount < 0) {
        // We need to detect uint32 to int32 overflow because JSON file output
        // int32 and basic block agent use an uint32 counter.
        value = std::numeric_limits<EntryCountType>::max();
      } else {
        value += std::min(
            amount, std::numeric_limits<EntryCountType>::max() - value);
      }
    }
  }
}

const BasicBlockEntryCountGrinder::InstrumentedModuleInformation*
BasicBlockEntryCountGrinder::FindOrCreateInstrumentedModule(
    const ModuleInformation* module_info) {
  // See if we already encountered this instrumented module.
  InstrumentedModuleMap::iterator it(instrumented_modules_.find(*module_info));
  if (it != instrumented_modules_.end())
    return &it->second;

  // Get the original file's metadata.
  base::FilePath module_path(module_info->image_file_name);
  pe::PEFile instrumented_module;
  if (!instrumented_module.Init(module_path)) {
    LOG(ERROR) << "Unable to locate instrumented module: "
               << module_path.value();
    return NULL;
  }

  pe::Metadata metadata;
  if (!metadata.LoadFromPE(instrumented_module)) {
    LOG(ERROR) << "Unable to load metadata from module: "
               << module_path.value();
    return NULL;
  }

  // Find the PDB file for the module.
  base::FilePath pdb_path;
  if (!pe::FindPdbForModule(module_path, &pdb_path) || pdb_path.empty()) {
    LOG(ERROR) << "Failed to find PDB for module: " << module_path.value();
    return NULL;
  }

  RelativeAddressRangeVector block_ranges;
  // This logs verbosely for us.
  if (!basic_block_util::LoadBasicBlockRanges(pdb_path, &block_ranges)) {
    return NULL;
  }

  // We've located all the information we need, create and
  // initialize the record.
  InstrumentedModuleInformation& info = instrumented_modules_[*module_info];
  basic_block_util::InitModuleInfo(metadata.module_signature(),
                                   &info.original_module);

  info.block_ranges.swap(block_ranges);

  return &info;
}

}  // namespace grinders
}  // namespace grinder
