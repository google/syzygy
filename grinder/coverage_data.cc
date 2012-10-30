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

#include "syzygy/grinder/coverage_data.h"

namespace grinder {

bool CoverageData::Add(const LineInfo& line_info) {
  // Multiple entries for the same source file are stored consecutively in
  // the LineInfo, hence we use this as a cache to prevent repeated lookups
  // of source file names in our SourceFileCoverageDataMap.
  const std::string* old_source_file_name = NULL;
  SourceFileCoverageDataMap::iterator source_it;

  LineInfo::SourceLines::const_iterator line_it =
      line_info.source_lines().begin();
  for (; line_it != line_info.source_lines().end(); ++line_it) {
    DCHECK(line_it->source_file_name != NULL);

    // Different source file? Then insert/lookup in our map.
    if (old_source_file_name != line_it->source_file_name) {
      // We don't care whether it already exists or not.
      source_it = source_file_coverage_data_map_.insert(
          std::make_pair(*line_it->source_file_name,
                         SourceFileCoverageData())).first;
      old_source_file_name = line_it->source_file_name;
    }

    // Insert/lookup the execution count by line number.
    LineExecutionCountMap::iterator line_exec_it =
        source_it->second.line_execution_count_map.insert(
            std::make_pair(line_it->line_number, 0)).first;

    // Update the execution count using saturation arithmetic.
    if (line_it->visit_count > 0) {
      line_exec_it->second =
          std::min(line_exec_it->second,
                   std::numeric_limits<size_t>::max() - line_it->visit_count) +
          line_it->visit_count;
    }
  }

  return true;
}

}  // namespace grinder
