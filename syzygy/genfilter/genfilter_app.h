// Copyright 2013 Google Inc. All Rights Reserved.
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
// Define the GenFilterApp class. GenFilterApp is a command-line application for
// generating Syzygy instrumentation filters.

#ifndef SYZYGY_GENFILTER_GENFILTER_APP_H_
#define SYZYGY_GENFILTER_GENFILTER_APP_H_

#include "base/command_line.h"
#include "base/files/file_path.h"
#include "syzygy/application/application.h"

namespace genfilter {

// Implements the "filter" command-line application.
//
// Refer to kUsageFormatStr (referenced from GenFilterApp::Usage()) for
// usage information.
class GenFilterApp : public application::AppImplBase {
 public:
  // The valid actions.
  enum Action {
    kCompile,
    kIntersect,
    kInvert,
    kSubtract,
    kUnion,
  };

  GenFilterApp()
      : application::AppImplBase("GenFilterApp"),
        action_(kCompile),
        pretty_print_(false),
        overwrite_(false) {
  }

  // @name Implementation of the AppImplBase interface.
  // @{
  bool ParseCommandLine(const base::CommandLine* command_line);
  int Run();
  // @}

 protected:
  // @name Utility members.
  // @{
  void PrintUsage(const base::CommandLine* command_line,
                  const base::StringPiece& message) const;
  // @}

  // @name Main bodies of the various actions.
  // @{
  bool RunCompileAction();
  bool RunSetAction();
  // @}

  Action action_;
  base::FilePath input_image_;
  base::FilePath input_pdb_;
  base::FilePath output_file_;
  std::vector<base::FilePath> inputs_;
  bool overwrite_;
  bool pretty_print_;
};

}  // namespace genfilter

#endif  // SYZYGY_GENFILTER_GENFILTER_APP_H_
