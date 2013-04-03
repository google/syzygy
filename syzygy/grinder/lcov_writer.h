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
// Declares utility functions for outputting an LCOV formatted coverage file
// from a populated CoverageData object.
//
// We only support the minimum subset of LCOV that is used by Chromium code
// coverage report generating tool, croc. Namely, the DA, LF and LH tags.
//
// There is no single document defining the LCOV file format so we summarize
// it here. The information has been taken from LCOV source code and manpages
// and collected here.
//
// An LCOV file is a plain-text ASCII file. Each line begins with a tag (in
// all capital letters, to be discussed below) immediately followed by a
// colon. Following each tag is an arbitrary amount of whitespace (may be none)
// and then the tag data, the format of which depends on the tag type.
//
// The following tags are header tags and may be present only once at the
// beginning of a file:
//
//   TN: <name of test>
//   TD: <textual description of test>
//
// Following the header there are multiple records, one per source file for
// which coverage results are present. Each record starts with the tag:
//
//   SF: <full path to source file>
//
// Each instrumented line of text is indicated using the tag:
//
//   DA: <line number>, <execution count>
//
// A line that is instrumented but not executed should be indicated with an
// execution count of 0. A line that is not instrumented should have no DA
// record.
//
// Optionally, a record may specify function information using the following
// tags:
//
//   FN: <line number of start of function>, <function name>
//   FNDA: <call count>, <function name>
//
// Again, FN* records should not be specified for functions that are not
// instrumented.
//
// Optionally, branch coverage may be specified. For each instrumented branch
// point in the code information is recorded using the following tag:
//
//   BA: <line number>, <branch coverage value>
//
// where <branch coverage value> is one of:
//
//   0 - branch not executed.
//   1 - branch executed but not taken.
//   2 - branch executed and taken.
//
// Following DA/FN/FNDA/BA tags a record should contain appropriate summary
// tags.
//
// If line instrumentation is present the following tags should be present:
//
//   LH: <number of lines with non-zero execution count>
//   LF: <number of instrumented lines (number of DA records)>
//
// If function information is present the followings tags should be present:
//
//   FNH: <number of functions (number of FN records)>
//   FNF: <number of functions with non-zero call count>
//
// Finally, a record (information regarding a single source file) should be
// terminated with a single line containing the string 'end_of_record'.

#ifndef SYZYGY_GRINDER_LCOV_WRITER_H_
#define SYZYGY_GRINDER_LCOV_WRITER_H_

#include "base/files/file_path.h"
#include "syzygy/grinder/coverage_data.h"

namespace grinder {

// Dumps the provided @p coverage information to an LCOV file.
// @param coverage the summarized coverage info to be written.
// @param path the path to the file to be created or overwritten.
// @param file the file handle to be written to.
// @returns true on success, false otherwise.
bool WriteLcovCoverageFile(const CoverageData& coverage,
                           const base::FilePath& path);
bool WriteLcovCoverageFile(const CoverageData& coverage, FILE* file);

}  // namespace grinder

#endif  // SYZYGY_GRINDER_LCOV_WRITER_H_
