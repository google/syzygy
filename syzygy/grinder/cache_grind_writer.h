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
// Declares utility function for writing coverage data as KCacheGrind
// and QCacheGrind compatible .cachegrind files.
//
// The file format is documented here:
//
// http://kcachegrind.sourceforge.net/cgi-bin/show.cgi/KcacheGrindCalltreeFormat

#ifndef SYZYGY_GRINDER_CACHE_GRIND_WRITER_H_
#define SYZYGY_GRINDER_CACHE_GRIND_WRITER_H_

#include "base/files/file_path.h"
#include "syzygy/grinder/coverage_data.h"

namespace grinder {

// Dumps the provided @p coverage information to an CacheGrind file.
// @param coverage the summarized coverage info to be written.
// @param path the path to the file to be created or overwritten.
// @param file the file handle to be written to.
// @returns true on success, false otherwise.
bool WriteCacheGrindCoverageFile(const CoverageData& coverage,
                                 const base::FilePath& path);
bool WriteCacheGrindCoverageFile(const CoverageData& coverage, FILE* file);

}  // namespace grinder

#endif  // SYZYGY_GRINDER_CACHE_GRIND_WRITER_H_
