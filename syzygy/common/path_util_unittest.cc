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

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace common {

namespace {

void GetCurrentDriveAndDevice(std::wstring* drive_out,
                              std::wstring* device_out) {
  ASSERT_TRUE(drive_out != NULL);
  ASSERT_TRUE(device_out != NULL);

  std::wstring cwd(MAX_PATH, 0);
  DWORD status = ::GetCurrentDirectory(cwd.size(), &cwd[0]);
  ASSERT_GT(status, 0u);

  std::vector<std::wstring> cwd_components;
  base::FilePath(cwd).GetComponents(&cwd_components);
  ASSERT_GT(cwd_components.size(), 0u);
  const std::wstring& drive = cwd_components[0];

  // Get the device name associated with the current drive. We know it exists
  // as the drive exists.
  wchar_t device[MAX_PATH] = { 0 };
  status = ::QueryDosDevice(drive.c_str(), device, arraysize(device));
  ASSERT_GT(status, 0u);
  ASSERT_LE(status, arraysize(device));

  *drive_out = drive;
  *device_out = device;

  ASSERT_GT(drive_out->size(), 0u);
  ASSERT_GT(device_out->size(), 0u);
}

class PathUtilTest : public ::testing::Test {
 public:
  virtual void SetUp() override {
    ASSERT_NO_FATAL_FAILURE(GetCurrentDriveAndDevice(&cur_drive_,
                                                     &cur_device_));
  }

  std::wstring cur_drive_;
  std::wstring cur_device_;
};

}  // namespace

TEST_F(PathUtilTest, ConvertDevicePathToDrivePathWithDrivePath) {
  base::FilePath device(L"C:\\foo.txt");
  base::FilePath drive;
  ASSERT_TRUE(ConvertDevicePathToDrivePath(device, &drive));
  ASSERT_EQ(device.value(), drive.value());
}

TEST_F(PathUtilTest, ConvertDevicePathToDrivePathWithNonExistentDevicePath) {
  base::FilePath device(L"\\Device\\ThisDeviceDoesNotExist\\foo.txt");
  base::FilePath drive;
  ASSERT_TRUE(ConvertDevicePathToDrivePath(device, &drive));
  ASSERT_EQ(device.value(), drive.value());
}

TEST_F(PathUtilTest, ConvertDevicePathToDrivePathWithDevicePath) {
  base::FilePath device(cur_device_);
  device = device.Append(L"foo.txt");

  base::FilePath drive;
  ASSERT_TRUE(ConvertDevicePathToDrivePath(device, &drive));

  // We can't use FilePath::Append directly, as both ":" and "\" are seen as
  // delimiters. Thus, appending "foo.txt" to "C:" yields "C:foo.txt", which
  // is not exactly what we want.
  base::FilePath expected_drive(std::wstring(cur_drive_).append(L"\\foo.txt"));
  ASSERT_THAT(expected_drive.value(), ::testing::StrCaseEq(drive.value()));
}

TEST_F(PathUtilTest, ConvertDevicePathToDrivePathWithDeviceOnly) {
  base::FilePath device(cur_device_);
  base::FilePath drive;
  ASSERT_TRUE(ConvertDevicePathToDrivePath(device, &drive));

  ASSERT_THAT(cur_drive_, ::testing::StrCaseEq(drive.value()));
}

TEST_F(PathUtilTest, ConvertDevicePathToDrivePathWithDeviceWithPrefix) {
  // This tries to convert an invalid device name that contains a valid
  // device as a prefix. The conversion should do nothing.
  base::FilePath device(std::wstring(cur_device_).append(L"1234567"));
  device = device.Append(L"foo.txt");

  base::FilePath drive;
  ASSERT_TRUE(ConvertDevicePathToDrivePath(device, &drive));

  ASSERT_EQ(device.value(), drive.value());
}

}  // namespace common
