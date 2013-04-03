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
// Declares some utilities for dealing with paths.

#ifndef SYZYGY_COMMON_PATH_UTIL_H_
#define SYZYGY_COMMON_PATH_UTIL_H_

#include "base/files/file_path.h"

namespace common {

// Given a path of the format '\Device\DeviceName\...', converts it to the form
// 'C:\...'. If no matching device name is found, returns the original string.
// This can only fail if the underlying OS API calls fail, in which case an
// error will be logged.
//
// @param device_path The path to be converted.
// @param drive_path The path to be populated with the converted path.
// @returns true on success, false otherwise.
bool ConvertDevicePathToDrivePath(const base::FilePath& device_path,
                                  base::FilePath* drive_path);

}  // namespace common

#endif  // SYZYGY_COMMON_PATH_UTIL_H_
