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
// Declares CoverageData, a utility class for accumulating coverage info with
// a file and line centric indexing.

#ifndef SYZYGY_GRINDER_COVERAGE_DATA_H_
#define SYZYGY_GRINDER_COVERAGE_DATA_H_

#include <map>

#include "base/files/file_path.h"
#include "syzygy/grinder/line_info.h"

namespace grinder {

// A simple class for accumulating data from LineInfo objects, representing
// it with an alternative index.
class CoverageData {
 public:
  struct SourceFileCoverageData;  // Forward declaration.

  // A map of line numbers to execution counts.
  typedef std::map<size_t, uint32_t> LineExecutionCountMap;
  // A map of file names to coverage information.
  typedef std::map<std::string, SourceFileCoverageData>
      SourceFileCoverageDataMap;

  // Adds the given line information to the internal representation.
  // @param line_info the LineInfo object whose coverage information is to be
  //     merged with our internal representation.
  // @returns true on success, false otherwise.
  bool Add(const LineInfo& line_info);

  const SourceFileCoverageDataMap& source_file_coverage_data_map() const {
    return source_file_coverage_data_map_;
  }

 protected:
  // Store coverage results, per source file.
  SourceFileCoverageDataMap source_file_coverage_data_map_;
};

// Coverage information that is stored per file. Right now this consists only
// of line execution data, but branch and function data could be added.
struct CoverageData::SourceFileCoverageData {
  LineExecutionCountMap line_execution_count_map;
};

}  // namespace grinder

#endif  // SYZYGY_GRINDER_COVERAGE_DATA_H_
