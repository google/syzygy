// Copyright 2011 Google Inc. All Rights Reserved.
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
// A few utility functions for determining if paths refer to the same file
// or not.
#ifndef SYZYGY_CORE_FILE_UTIL_H_
#define SYZYGY_CORE_FILE_UTIL_H_

#include "base/files/file_path.h"

namespace core {

// Possible return values from this test.
enum FilePathCompareResult {
  kFilePathCompareError,

  // This is returned of the two file paths are equivalent on this machine.
  // That is they both refer to the same file on disk, even if that is via
  // junctions or indirection.
  kEquivalentFilePaths,

  // This is returned if the two file paths are guaranteed to refer to different
  // files on disk. It does not mean that they are both immediately creatable,
  // as there may be part of a directory hierarchy that also needs to be
  // created.
  kDistinctFilePaths,

  // This is returned if *neither* of the file paths exist. That is, they
  // may very well refer to the same path via filesystem shenanigans, but there
  // is no way to know without creating at least one of them.
  kUnableToCompareFilePaths,
};

// Compares two paths, determining if they both refer to the same object.
//
// This test is read-only, and as such it is possible for the test to fail.
// This can occur if neither of the paths exist, yet they do in fact refer to
// the same file via some aliasing mechanism (junctions, mounts, etc). In that
// case this will return kUnableToCompare. To attempt a comparison in this case
// both paths will be converted to absolute paths using the current working
// directory. If the paths are identical we can infer that the files will be
// the same (but not vice versa). To get a solid answer at least one of the
// paths must exist.
//
// @param path1 the first path to compare.
// @param path2 the second path to compare.
// @returns a FilePathCompareResult, described above.
FilePathCompareResult CompareFilePaths(const base::FilePath& path1,
                                       const base::FilePath& path2);

// A list of known file types.
enum FileType {
  kUnknownFileType,
  kPdbFileType,
  kCoffFileType,
  kPeFileType,
  kArchiveFileType,
  kResourceFileType,
};

// Guesses the type of the given file. This does not do extensive validation.
// There may be false positives, but there will be no false negatives.
// @param path The path of the file whose type is to be determined.
// @param file_type Will be populated with the type of the file.
// @returns true on success, false on failure. On success sets @p file_type.
bool GuessFileType(const base::FilePath& path, FileType* file_type);

}  // namespace core

#endif  // SYZYGY_CORE_FILE_UTIL_H_
