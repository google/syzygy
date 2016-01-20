// Copyright 2016 Google Inc. All Rights Reserved.
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
#ifndef SYZYGY_KASKO_KASKO_UPLOAD_APP_H_
#define SYZYGY_KASKO_KASKO_UPLOAD_APP_H_

#include "base/files/file_path.h"
#include "syzygy/application/application.h"

namespace kasko {

// The application class that takes care of uploading a minidump and matching
// crash key file.
class KaskoUploadApp : public application::AppImplBase {
 public:
  // Return codes from 'Run'. These constants should be kept the same so that
  // any scripts depending on them continue to work.
  enum ReturnCodes : int {
    // This is by convention.
    kReturnCodeSuccess = 0,
    // This is imposed by the application base class.
    kReturnCodeInvalidCommandLine = 1,
    // These are custom return codes used by this application.
    kReturnCodeCrashKeysFileMissing = 2,
    kReturnCodeCrashKeysFileMalformed = 3,
    kReturnCodeCrashKeysAbsent = 4,
    kReturnCodeMinidumpFileMissing = 5,
    kReturnCodeUploadFailed = 6,
  };

  KaskoUploadApp();

  // @name Implementation of the AppImplBase interface.
  // @{
  bool ParseCommandLine(const base::CommandLine* command_line);
  int Run();
  void TearDown() {}
  // @}

  // @name Utility functions
  // @{
  void PrintUsage(const base::FilePath& program,
                  const base::StringPiece& message);
  // @}

  // Accessors.
  // @{
  const base::FilePath& minidump_path() const { return minidump_path_; }
  const base::FilePath& crash_keys_path() const { return crash_keys_path_; }
  const base::string16& upload_url() const { return upload_url_; }
  // @}

  // Switches.
  // @{
  static const char kMinidumpSwitch[];
  static const char kCrashKeysSwitch[];
  static const char kUploadUrlSwitch[];
  // @}

  // Default values.
  static const base::char16 kDefaultUploadUrl[];

 private:
  base::FilePath minidump_path_;
  base::FilePath crash_keys_path_;
  base::string16 upload_url_;

  DISALLOW_COPY_AND_ASSIGN(KaskoUploadApp);
};

}  // namespace kasko

#endif  // SYZYGY_KASKO_KASKO_UPLOAD_APP_H_
