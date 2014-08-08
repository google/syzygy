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

#include "syzygy/grinder/lcov_writer.h"

#include "base/file_util.h"

namespace grinder {

bool WriteLcovCoverageFile(const CoverageData& coverage,
                           const base::FilePath& path) {
  base::ScopedFILE file(base::OpenFile(path, "wb"));
  if (file.get() == NULL) {
    LOG(ERROR) << "Failed to open file for writing: " << path.value();
    return false;
  }

  if (!WriteLcovCoverageFile(coverage, file.get())) {
    LOG(ERROR) << "Failed to write LCOV file: " << path.value();
    return false;
  }

  return true;
}

bool WriteLcovCoverageFile(const CoverageData& coverage, FILE* file) {
  DCHECK(file != NULL);

  CoverageData::SourceFileCoverageDataMap::const_iterator source_it =
      coverage.source_file_coverage_data_map().begin();
  CoverageData::SourceFileCoverageDataMap::const_iterator source_it_end =
      coverage.source_file_coverage_data_map().end();
  for (; source_it != source_it_end; ++source_it) {
    if (::fprintf(file, "SF:%s\n", source_it->first.c_str()) < 0)
      return false;

    // Iterate over the line execution data, keeping summary statistics as we
    // go.
    size_t lines_executed = 0;
    CoverageData::LineExecutionCountMap::const_iterator line_it =
        source_it->second.line_execution_count_map.begin();
    CoverageData::LineExecutionCountMap::const_iterator line_it_end =
        source_it->second.line_execution_count_map.end();
    for (; line_it != line_it_end; ++line_it) {
      if (::fprintf(file, "DA:%d,%d\n", line_it->first, line_it->second) < 0)
        return false;
      if (line_it->second > 0)
        ++lines_executed;
    }

    // Output the summary statistics for this file.
    if (::fprintf(file, "LH:%d\n", lines_executed) < 0 ||
        ::fprintf(file, "LF:%d\n",
                  source_it->second.line_execution_count_map.size()) < 0 ||
        ::fprintf(file, "end_of_record\n") < 0) {
      return false;
    }
  }

  return true;
}

}  // namespace grinder
