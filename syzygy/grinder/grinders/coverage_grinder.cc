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

#include "syzygy/grinder/grinders/coverage_grinder.h"

#include "base/string_util.h"
#include "base/files/file_path.h"
#include "syzygy/common/indexed_frequency_data.h"
#include "syzygy/grinder/cache_grind_writer.h"
#include "syzygy/grinder/lcov_writer.h"
#include "syzygy/pdb/pdb_reader.h"
#include "syzygy/pdb/pdb_util.h"
#include "syzygy/pe/find.h"

namespace grinder {
namespace grinders {

namespace {

using basic_block_util::ModuleInformation;
using basic_block_util::RelativeAddressRange;
using basic_block_util::GetFrequency;
using basic_block_util::LoadPdbInfo;
using basic_block_util::IsValidFrequencySize;
using basic_block_util::PdbInfo;
using basic_block_util::PdbInfoMap;
using trace::parser::AbsoluteAddress64;

}  // namespace

CoverageGrinder::CoverageGrinder()
    : parser_(NULL),
      event_handler_errored_(false),
      output_format_(kLcovFormat) {
}

CoverageGrinder::~CoverageGrinder() {
}

bool CoverageGrinder::ParseCommandLine(const CommandLine* command_line) {
  DCHECK(command_line != NULL);

  // If the switch isn't present we have nothing to do!
  const char kOutputFormat[] = "output-format";
  if (!command_line->HasSwitch(kOutputFormat))
    return true;

  std::string format = command_line->GetSwitchValueASCII(kOutputFormat);
  if (LowerCaseEqualsASCII(format, "lcov")) {
    output_format_ = kLcovFormat;
  } else if (LowerCaseEqualsASCII(format, "cachegrind")) {
    output_format_ = kCacheGrindFormat;
  } else {
    LOG(ERROR) << "Unknown output format: " << format << ".";
    return false;
  }
  return true;
}

void CoverageGrinder::SetParser(Parser* parser) {
  DCHECK(parser != NULL);
  parser_ = parser;
}

bool CoverageGrinder::Grind() {
  if (event_handler_errored_) {
    LOG(WARNING) << "Failed to handle all basic block frequency data events, "
                 << "coverage results will be partial.";
  }

  if (pdb_info_cache_.empty()) {
    LOG(ERROR) << "No coverage data was encountered.";
    return false;
  }

  PdbInfoMap::const_iterator it = pdb_info_cache_.begin();
  for (; it != pdb_info_cache_.end(); ++it) {
    if (!coverage_data_.Add(it->second.line_info)) {
      LOG(ERROR) << "Failed to aggregate line information from PDB: "
                 << it->first.path;
      return false;
    }
  }
  DCHECK(!coverage_data_.source_file_coverage_data_map().empty());

  return true;
}

bool CoverageGrinder::OutputData(FILE* file) {
  DCHECK(file != NULL);
  DCHECK(!coverage_data_.source_file_coverage_data_map().empty());

  // These functions log verbosely for us.
  switch (output_format_) {
    case kLcovFormat: {
      if (!WriteLcovCoverageFile(coverage_data_, file))
        return false;
      break;
    }

    case kCacheGrindFormat: {
      if (!WriteCacheGrindCoverageFile(coverage_data_, file))
        return false;
      break;
    }

    default: NOTREACHED() << "Unknown OutputFormat.";
  }

  return true;
}

void CoverageGrinder::OnIndexedFrequency(
    base::Time time,
    DWORD process_id,
    DWORD thread_id,
    const TraceIndexedFrequencyData* data) {
  DCHECK(data != NULL);
  DCHECK(parser_ != NULL);

  if (data->data_type != common::IndexedFrequencyData::COVERAGE &&
      data->data_type != common::IndexedFrequencyData::BASIC_BLOCK_ENTRY) {
    return;
  }

  if (data->num_entries == 0) {
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
    LOG(ERROR) << "Failed to find module information for basic block frequency"
               << " data.";
    event_handler_errored_ = true;
    return;
  }

  // TODO(chrisha): Validate that the PE file itself is instrumented as
  //     expected? This isn't strictly necessary but would add another level of
  //     safety checking.

  // Get the PDB info. This loads the line information and the basic-block
  // ranges if not already done, otherwise it returns the cached version.
  PdbInfo* pdb_info = NULL;
  if (!LoadPdbInfo(&pdb_info_cache_, *module_info, &pdb_info)) {
    event_handler_errored_ = true;
    return;
  }

  DCHECK(pdb_info != NULL);

  // Sanity check the contents.
  if (data->num_entries != pdb_info->bb_ranges.size()) {
    LOG(ERROR) << "Mismatch between trace data BB count and PDB BB count.";
    event_handler_errored_ = true;
    return;
  }

  // Run over the BB frequency data and mark non-zero frequency BBs as having
  // been visited.
  for (size_t bb_index = 0; bb_index < data->num_entries; ++bb_index) {
    uint32 bb_freq = GetFrequency(data, bb_index, 0);

    if (bb_freq == 0)
      continue;

    // Mark this basic-block as visited.
    const RelativeAddressRange& bb_range = pdb_info->bb_ranges[bb_index];
    if (!pdb_info->line_info.Visit(bb_range.start(),
                                   bb_range.size(),
                                   bb_freq)) {
      LOG(ERROR) << "Failed to visit BB at " << bb_range << ".";
      event_handler_errored_ = true;
      return;
    }
  }
}

}  // namespace grinders
}  // namespace grinder
