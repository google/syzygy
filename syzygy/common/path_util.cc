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

#include "syzygy/common/path_util.h"

#include <windows.h>

#include "base/logging.h"
#include "syzygy/common/com_utils.h"

namespace common {

bool ConvertDevicePathToDrivePath(const base::FilePath& device_path,
                                  base::FilePath* drive_path) {
  DCHECK(drive_path != NULL);
  static const wchar_t kPathSeparator = L'\\';

  // Get the set of logical drives that exist as a bitmask.
  DWORD drive_bits = ::GetLogicalDrives();

  // For each logical drive get the device name, looking for one that
  // matches the prefix of device_path.
  DWORD drive_bit = 1;
  wchar_t drive_letter = L'A';
  wchar_t drive[] = { 'A', ':', 0 };
  for (; drive_bit != 0; drive_bit <<= 1, ++drive_letter) {
    // If the bit is not set, this drive does not exist.
    if ((drive_bits & drive_bit) == 0)
      continue;

    // Generate the drive name.
    drive[0] = drive_letter;

    // The call to QueryDosDevice is racy, as the system state may have changed
    // since we called GetLogicalDriveStrings. So on failure we simply log a
    // warning and continue on our merry way.
    wchar_t device[1024] = { 0 };
    DWORD device_length = ::QueryDosDevice(drive, device, arraysize(device));
    if (device_length == 0) {
      DWORD error = ::GetLastError();
      LOG(WARNING) << "QueryDosDevice failed: " << common::LogWe(error);
    } else {
      // The string that QueryDosDevice writes is terminated with 2 nulls.
      DCHECK_GT(device_length, 2u);
      device_length -= 2;
      DCHECK_EQ(device_length, ::wcslen(device));

      // Is this the device we're looking for?
      if (_wcsnicmp(device, device_path.value().c_str(), device_length) == 0) {
        // The device path must consist only of the device name, or must be
        // immediately followed by a path separator. This prevents matching
        // "\Device\HarddiskVolume10" with "\Device\HarddiskVolume1".
        if (device_path.value().size() == device_length ||
            device_path.value()[device_length] == kPathSeparator) {
          // Replace the device name with the drive letter and return the
          // translated path.
          *drive_path = base::FilePath(drive).Append(
              device_path.value().substr(device_length));
          return true;
        }
      }
    }
  }

  // We didn't find a matching device.
  *drive_path = device_path;
  return true;
}

}  // namespace common
