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

#include "syzygy/core/file_util.h"

#include "base/file_util.h"
#include "base/win/scoped_handle.h"
#include "syzygy/common/com_utils.h"

namespace core {

namespace {

enum FileInformationResult {
  kFileNotFound,
  kSuccess,
  kFailure
};

// Gets a handle to a file, and the file information for it. Leaves the handle
// open.
FileInformationResult GetFileInformation(
    const base::FilePath& path,
    base::win::ScopedHandle* handle,
    BY_HANDLE_FILE_INFORMATION* file_info) {
  // Open the file in the least restrictive possible way.
  handle->Set(
      ::CreateFile(path.value().c_str(),
                   SYNCHRONIZE,
                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                   NULL,
                   OPEN_EXISTING,
                   FILE_ATTRIBUTE_NORMAL,
                   NULL));
  if (!handle->IsValid()) {
    // The file not being found is a special case.
    DWORD error = ::GetLastError();
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
      return kFileNotFound;

    LOG(ERROR) << "Unable to open \"" << path.value() << "\": "
               << common::LogWe(error);
    return kFailure;
  }

  if (!::GetFileInformationByHandle(handle->Get(), file_info)) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "GetFileInformationByHandle failed for \"" << path.value()
               << "\": " << common::LogWe(error);
    return kFailure;
  }

  return kSuccess;
}

}  // namespace

FilePathCompareResult CompareFilePaths(const base::FilePath& path1,
                                       const base::FilePath& path2) {
  // Now we try opening both files for reading to see if they point to the same
  // underlying volume and file index. We open both files simultaneously to
  // avoid a race condition whereby the file could be moved/removed in between
  // the two calls to GetFileInformation.

  base::win::ScopedHandle handle1;
  BY_HANDLE_FILE_INFORMATION info1 = {};
  FileInformationResult result1 = GetFileInformation(path1, &handle1, &info1);
  if (result1 == kFailure)
    return kFilePathCompareError;

  base::win::ScopedHandle handle2;
  BY_HANDLE_FILE_INFORMATION info2 = {};
  FileInformationResult result2 = GetFileInformation(path2, &handle2, &info2);
  if (result2 == kFailure)
    return kFilePathCompareError;

  // If neither file exists we can't really compare them based on anything
  // other than the path itself.
  if (result1 == kFileNotFound && result2 == kFileNotFound) {
    base::FilePath abs1(MakeAbsoluteFilePath(path1));
    base::FilePath abs2(MakeAbsoluteFilePath(path2));

    if (abs1.empty() || abs2.empty())
      return kUnableToCompareFilePaths;

    if (abs1 == abs2)
      return kEquivalentFilePaths;

    return kUnableToCompareFilePaths;
  }

  // If only one of them exists, then they can't possibly be the same file.
  if (result1 == kFileNotFound || result2 == kFileNotFound)
    return kDistinctFilePaths;

  // If they both exist we compare the details of where they live on disk.
  bool identical = info1.dwVolumeSerialNumber == info2.dwVolumeSerialNumber &&
      info1.nFileIndexLow == info2.nFileIndexLow &&
      info1.nFileIndexHigh == info2.nFileIndexHigh;

  return identical ? kEquivalentFilePaths : kDistinctFilePaths;
}

}  // namespace core
