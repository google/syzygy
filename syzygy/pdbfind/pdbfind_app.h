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
// Defines the PdbFindApp class, which implements a command-line tool for
// finding the PDB file associated with a given PE file. This uses the same
// search mechanism as that employed by the decomposer but outputs meaningful
// return code and easily parsable output.

#ifndef SYZYGY_PDBFIND_PDBFIND_APP_H_
#define SYZYGY_PDBFIND_PDBFIND_APP_H_

#include "base/command_line.h"
#include "base/files/file_path.h"
#include "syzygy/application/application.h"

namespace pdbfind {

// Implements the "pdbfind" command-line application.
//
// Refer to kUsageFormatStr (referenced from PdbFindApp::Usage()) for
// usage information.
class PdbFindApp : public application::AppImplBase {
 public:
  PdbFindApp()
      : application::AppImplBase("PdbFind") {
  }

  // @name Implementation of the AppImplBase interface.
  // @{
  bool ParseCommandLine(const base::CommandLine* command_line);
  int Run();
  // @}

 protected:
  // @name Utility members.
  // @{
  bool Usage(const base::CommandLine* command_line,
             const base::StringPiece& message) const;
  // @}

  // @name Command-line parameters.
  // @{
  base::FilePath input_image_path_;
  // @}
};

}  // namespace pdbfind

#endif  // SYZYGY_PDBFIND_PDBFIND_APP_H_
