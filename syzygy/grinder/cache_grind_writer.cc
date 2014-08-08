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

#include "syzygy/grinder/cache_grind_writer.h"

#include "base/file_util.h"
#include "base/strings/string_util.h"

namespace grinder {

bool WriteCacheGrindCoverageFile(const CoverageData& coverage,
                                 const base::FilePath& path) {
  base::ScopedFILE file(base::OpenFile(path, "wb"));
  if (file.get() == NULL) {
    LOG(ERROR) << "Failed to open file for writing: " << path.value();
    return false;
  }

  if (!WriteCacheGrindCoverageFile(coverage, file.get())) {
    LOG(ERROR) << "Failed to write CacheGrind file: " << path.value();
    return false;
  }

  return true;
}

bool WriteCacheGrindCoverageFile(const CoverageData& coverage, FILE* file) {
  DCHECK(file != NULL);

  // Output the position and event types.
  if (::fprintf(file, "positions: line\n") < 0)
    return false;
  if (::fprintf(file, "events: Instrumented Executed\n") < 0)
    return false;

  // Iterate over the source files.
  CoverageData::SourceFileCoverageDataMap::const_iterator source_it =
      coverage.source_file_coverage_data_map().begin();
  CoverageData::SourceFileCoverageDataMap::const_iterator source_it_end =
      coverage.source_file_coverage_data_map().end();
  for (; source_it != source_it_end; ++source_it) {
    // Output the path, being sure to use forward slashes instead of
    // back slashes.
    std::string path = source_it->first;
    if (!base::ReplaceChars(path, "\\", "/", &path))
      return false;
    if (::fprintf(file, "fl=%s\n", path.c_str()) < 0)
      return false;

    // We need to output a dummy function name for cache-grind aggregation to
    // work appropriately.
    if (::fprintf(file, "fn=all\n") < 0)
      return false;

    // Iterate over the instrumented lines. We output deltas to save space so
    // keep track of the previous line. Lines are 1 indexed so we can use zero
    // as a special value.
    size_t prev_line = 0;
    CoverageData::LineExecutionCountMap::const_iterator line_it =
        source_it->second.line_execution_count_map.begin();
    CoverageData::LineExecutionCountMap::const_iterator line_it_end =
        source_it->second.line_execution_count_map.end();
    for (; line_it != line_it_end; ++line_it) {
      if (prev_line == 0) {
        // Output the raw line number.
        if (::fprintf(file, "%d 1 %d\n", line_it->first, line_it->second) < 0)
          return false;
      } else {
        // Output the line number as a delta from the previous line number.
        DCHECK_LT(prev_line, line_it->first);
        if (::fprintf(file, "+%d 1 %d\n", line_it->first - prev_line,
                      line_it->second) < 0) {
          return false;
        }
      }
      prev_line = line_it->first;
    }
  }

  return true;
}

}  // namespace grinder
