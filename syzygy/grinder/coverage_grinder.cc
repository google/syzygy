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

#include "syzygy/grinder/coverage_grinder.h"

#include "base/file_path.h"
#include "syzygy/common/basic_block_frequency_data.h"
#include "syzygy/pdb/pdb_reader.h"
#include "syzygy/pdb/pdb_util.h"
#include "syzygy/pe/find.h"

namespace grinder {

namespace {

using sym_util::ModuleInformation;
using trace::parser::AbsoluteAddress64;

bool GetBasicBlockRanges(
    const FilePath& pdb_path,
    CoverageGrinder::RelativeAddressRangeVector* bb_ranges) {
  DCHECK(!pdb_path.empty());
  DCHECK(bb_ranges != NULL);

  // Read the PDB file.
  pdb::PdbReader pdb_reader;
  pdb::PdbFile pdb_file;
  if (!pdb_reader.Read(pdb_path, &pdb_file)) {
    LOG(ERROR) << "Failed to read PDB: " << pdb_path.value();
    return false;
  }

  // Get the name-stream map from the PDB.
  pdb::PdbInfoHeader70 pdb_header = {};
  pdb::NameStreamMap name_stream_map;
  if (!pdb::ReadHeaderInfoStream(pdb_file, &pdb_header, &name_stream_map)) {
    LOG(ERROR) << "Failed to read PDB header info stream: " << pdb_path.value();
    return false;
  }

  // Get the basic block addresses from the PDB file.
  pdb::NameStreamMap::const_iterator name_it = name_stream_map.find(
      common::kBasicBlockRangesStreamName);
  if (name_it == name_stream_map.end()) {
    LOG(ERROR) << "PDB does not contain basic block ranges stream: "
               << pdb_path.value();
    return false;
  }
  scoped_refptr<pdb::PdbStream> bb_ranges_stream;
  bb_ranges_stream = pdb_file.GetStream(name_it->second);
  if (bb_ranges_stream.get() == NULL) {
    LOG(ERROR) << "PDB basic block ranges stream has invalid index: "
               << name_it->second;
    return false;
  }

  // Read the basic block range stream.
  if (!bb_ranges_stream->Seek(0) ||
      !bb_ranges_stream->Read(bb_ranges)) {
    LOG(ERROR) << "Failed to read basic block range stream from PDB: "
               << pdb_path.value();
    return false;
  }

  return true;
}

uint32 GetFrequency(const uint8* data, size_t size, size_t bb_index) {
  DCHECK(data != NULL);
  DCHECK(size == 1 || size == 2 || size == 4);

  switch (size) {
    case 1: return data[bb_index];
    case 2: return reinterpret_cast<const uint16*>(data)[bb_index];
    case 4: return reinterpret_cast<const uint32*>(data)[bb_index];
  }

  NOTREACHED();
  return 0;
}

}  // namespace

CoverageGrinder::CoverageGrinder()
    : parser_(NULL), event_handler_errored_(false) {
}

CoverageGrinder::~CoverageGrinder() {
}

bool CoverageGrinder::ParseCommandLine(const CommandLine* command_line) {
  // We don't do any additional parsing.
  return true;
}

void CoverageGrinder::SetParser(Parser* parser) {
  parser_ = parser;
}

bool CoverageGrinder::Grind() {
  if (event_handler_errored_) {
    LOG(WARNING) << "Failed to handle all basic block frequency data events, "
                 << "coverage results will be partial.";
  }

  if (pdb_info_map_.empty()) {
    LOG(ERROR) << "No coverage data was encountered.";
    return false;
  }

  PdbInfoMap::const_iterator it = pdb_info_map_.begin();
  for (; it != pdb_info_map_.end(); ++it) {
    if (!lcov_writer_.Add(it->second.line_info)) {
      LOG(ERROR) << "Failed to aggregate line information from PDB: "
                 << it->first;
      return false;
    }
  }
  DCHECK(!lcov_writer_.source_file_coverage_info_map().empty());

  return true;
}

bool CoverageGrinder::OutputData(FILE* file) {
  DCHECK(file != NULL);
  DCHECK(!lcov_writer_.source_file_coverage_info_map().empty());

  if (!lcov_writer_.Write(file)) {
    LOG(ERROR) << "Failed to write LCOV file.";
    return false;
  }

  return true;
}

void CoverageGrinder::OnBasicBlockFrequency(
    base::Time time,
    DWORD process_id,
    DWORD thread_id,
    const TraceBasicBlockFrequencyData* data) {
  DCHECK(parser_ != NULL);

  if (data->num_basic_blocks == 0) {
    LOG(INFO) << "Skipping empty basic block frequency data.";
    return;
  }

  if (data->frequency_size != 1 && data->frequency_size != 2 &&
      data->frequency_size != 4) {
    LOG(ERROR) << "Basic block frequency data has invalid frequency_size ("
               << data->frequency_size << ").";
    event_handler_errored_ = true;
    return;
  }

  // Get the module information for which this BB frequency data belongs.
  const ModuleInformation* module_info = parser_->GetModuleInformation(
      process_id, AbsoluteAddress64(data->module_base_addr));
  if (module_info == NULL) {
    LOG(ERROR) << "Failed to find module information for basic block frequency "
               << "data.";
    event_handler_errored_ = true;
    return;
  }

  // TODO(chrisha): Validate that the PE file itself is instrumented as
  //     expected? This isn't strictly necessary but would add another level of
  //     safety checking.

  // Find the PDB for the module.
  FilePath module_path(module_info->image_file_name);
  FilePath pdb_path;
  if (!pe::FindPdbForModule(module_path, &pdb_path) || pdb_path.empty()) {
    LOG(ERROR) << "Failed to find PDB for module: " << module_path.value();
    event_handler_errored_ = true;
    return;
  }

  // Get the PDB info. This loads the line information and the basic-block
  // ranges if not already done, otherwise it returns the cached version.
  PdbInfo* pdb_info = NULL;
  if (!GetPdbInfo(pdb_path, &pdb_info)) {
    event_handler_errored_ = true;
    return;
  }
  DCHECK(pdb_info != NULL);

  // Sanity check the contents.
  if (data->num_basic_blocks != pdb_info->bb_ranges.size()) {
    LOG(ERROR) << "Mismatch between trace data BB count and PDB BB count.";
    event_handler_errored_ = true;
    return;
  }

  // Run over the BB frequency data and mark non-zero frequency BBs as having
  // been visited.
  for (size_t bb_index = 0; bb_index < data->num_basic_blocks; ++bb_index) {
    uint32 bb_freq = GetFrequency(data->frequency_data,
                                  data->frequency_size,
                                  bb_index);

    if (bb_freq == 0)
      continue;

    // Mark this basic-block as visited.
    const RelativeAddressRange& bb_range = pdb_info->bb_ranges[bb_index];
    if (!pdb_info->line_info.Visit(bb_range.start(), bb_range.size())) {
      LOG(ERROR) << "Failed to visit BB at " << bb_range << ".";
      event_handler_errored_ = true;
      return;
    }
  }
}

bool CoverageGrinder::GetPdbInfo(const FilePath& pdb_path, PdbInfo** pdb_info) {
  DCHECK(pdb_info != NULL);

  *pdb_info = NULL;

  // Look for a cached entry first.
  PdbInfoMap::iterator it = pdb_info_map_.find(pdb_path.value());
  if (it != pdb_info_map_.end()) {
    *pdb_info = &(it->second);
    return true;
  }

  // Load the line information from the PDB.
  PdbInfo& pdb_info_ref = pdb_info_map_[pdb_path.value()];
  if (!pdb_info_ref.line_info.Init(pdb_path)) {
    LOG(ERROR) << "Failed to extract line information from PDB file: "
               << pdb_path.value();
    return false;
  }

  // This logs verbosely for us.
  if (!GetBasicBlockRanges(pdb_path, &pdb_info_ref.bb_ranges))
    return false;

  *pdb_info = &pdb_info_ref;

  return true;
}

}  // namespace grinder
