// Copyright 2013 Google Inc. All Rights Reserved.
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

#include "syzygy/grinder/grinders/indexed_frequency_data_grinder.h"

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

IndexedFrequencyDataGrinder::IndexedFrequencyDataGrinder()
    : parser_(NULL),
      event_handler_errored_(false) {
}

bool IndexedFrequencyDataGrinder::ParseCommandLine(
    const CommandLine* command_line) {
  serializer_.set_pretty_print(command_line->HasSwitch("pretty-print"));
  return true;
}

void IndexedFrequencyDataGrinder::SetParser(Parser* parser) {
  DCHECK(parser != NULL);
  parser_ = parser;
}

bool IndexedFrequencyDataGrinder::Grind() {
  if (frequency_data_map_.empty()) {
    LOG(ERROR) << "No basic-block frequency data was encountered.";
    return false;
  }

  return true;
}

bool IndexedFrequencyDataGrinder::OutputData(FILE* file) {
  DCHECK(file != NULL);
  if (!serializer_.SaveAsJson(frequency_data_map_, file))
    return false;
  return true;
}

void IndexedFrequencyDataGrinder::OnIndexedFrequency(
    base::Time time,
    DWORD process_id,
    DWORD thread_id,
    const TraceIndexedFrequencyData* data) {
  DCHECK(data != NULL);
  DCHECK(parser_ != NULL);
  DCHECK_NE(0U, data->num_columns);

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

  UpdateBasicBlockFrequencyData(*instrumented_module, data);
}

void IndexedFrequencyDataGrinder::UpdateBasicBlockFrequencyData(
    const InstrumentedModuleInformation& instrumented_module,
    const TraceIndexedFrequencyData* data) {
  using basic_block_util::BasicBlockOffset;
  using basic_block_util::EntryCountType;
  using basic_block_util::GetFrequency;
  using basic_block_util::IndexedFrequencyInformation;
  using basic_block_util::IndexedFrequencyMap;
  using basic_block_util::RelativeAddress;

  DCHECK(data != NULL);
  DCHECK_NE(0U, data->num_entries);
  DCHECK_NE(0U, data->num_columns);

  // Find the entry for this module.
  ModuleIndexedFrequencyMap::iterator look =
      frequency_data_map_.find(instrumented_module.original_module);

  if (look == frequency_data_map_.end()) {
    IndexedFrequencyInformation info = {};
    info.num_entries = data->num_entries;
    info.num_columns = data->num_columns;
    info.frequency_size = data->frequency_size;
    info.data_type =
        static_cast<common::IndexedFrequencyData::DataType>(data->data_type);

    look = frequency_data_map_.insert(
        std::make_pair(instrumented_module.original_module,
                       info)).first;
  }

  // Validate fields are compatible to be grinded together.
  IndexedFrequencyInformation& info = look->second;
  if (info.num_entries != data->num_entries ||
      info.num_columns != data->num_columns ||
      info.frequency_size != data->frequency_size ||
      info.data_type != data->data_type) {
    event_handler_errored_ = true;
    return;
  }

  // Run over the BB frequency data and increment values for each basic block
  // using saturation arithmetic.
  IndexedFrequencyMap& bb_entries = info.frequency_map;
  for (size_t bb_id = 0; bb_id < data->num_entries; ++bb_id) {
    for (size_t column = 0; column < data->num_columns; ++column) {
      EntryCountType amount = GetFrequency(data, bb_id, column);
      if (amount != 0) {
        BasicBlockOffset offs =
            instrumented_module.block_ranges[bb_id].start().value();

        EntryCountType& value = bb_entries[
            std::make_pair(RelativeAddress(offs), column)];
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
}

const IndexedFrequencyDataGrinder::InstrumentedModuleInformation*
IndexedFrequencyDataGrinder::FindOrCreateInstrumentedModule(
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

  // We've located all the information we need, create and initialize the
  // record.
  InstrumentedModuleInformation& info = instrumented_modules_[*module_info];
  basic_block_util::InitModuleInfo(metadata.module_signature(),
                                   &info.original_module);

  info.block_ranges.swap(block_ranges);

  return &info;
}

}  // namespace grinders
}  // namespace grinder
