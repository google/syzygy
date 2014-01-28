// Copyright 2014 Google Inc. All Rights Reserved.
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
// Defines the SwapImportApp class, which implements the command-line
// "swapimport" tool.

#ifndef SYZYGY_SWAPIMPORT_SWAPIMPORT_APP_H_
#define SYZYGY_SWAPIMPORT_SWAPIMPORT_APP_H_

#include "base/command_line.h"
#include "base/files/file_path.h"
#include "syzygy/common/application.h"

namespace swapimport {

// Implements the "swapimport" command-line application.
//
// Refer to kUsageFormatStr (referenced from SwapImportApp::Usage()) for
// usage information.
class SwapImportApp : public common::AppImplBase {
 public:
  SwapImportApp()
      : common::AppImplBase("SwapImport"), overwrite_(false), verbose_(false) {
  }

  // @name Implementation of the AppImplBase interface.
  // @{
  bool ParseCommandLine(const CommandLine* command_line);
  int Run();
  // @}

 protected:
  // @name Utility members.
  // @{
  bool Usage(const CommandLine* command_line,
             const base::StringPiece& message) const;
  // @}

  // @name Implementation of import swapping.
  // @{
  template <typename PEFileType> int SwapImports();
  // @}

  std::string import_name_;
  base::FilePath input_image_;
  base::FilePath output_image_;
  bool overwrite_;
  bool verbose_;
  bool x64_;
};

}  // namespace swapimport

#endif  // SYZYGY_SWAPIMPORT_SWAPIMPORT_APP_H_
