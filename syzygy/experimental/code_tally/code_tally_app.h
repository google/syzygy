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
// A command line application to compute the code contribution size per
// object file, function and source line for a given executable.
// Generates output in JSON for easy downstream processing.

#ifndef SYZYGY_EXPERIMENTAL_CODE_TALLY_CODE_TALLY_APP_H_
#define SYZYGY_EXPERIMENTAL_CODE_TALLY_CODE_TALLY_APP_H_

#include "base/command_line.h"
#include "base/strings/string_piece.h"
#include "base/files/file_path.h"
#include "syzygy/common/application.h"
#include "syzygy/experimental/code_tally/code_tally.h"


// This class implements the code_tally command-line utility.
//
// See the description given in CodeTallyApp:::PrintUsage() for information
// about running this utility.
class CodeTallyApp : public common::AppImplBase {
 public:
  // @name Implementation of the AppImplBase interface.
  // @{
  CodeTallyApp() : common::AppImplBase("CodeTally"), pretty_print_(false) {
  }

  bool ParseCommandLine(const CommandLine* command_line);

  int Run();
  // @}

 protected:
  // @name Utility functions
  // @{
  void PrintUsage(const base::FilePath& program,
                  const base::StringPiece& message);

  // @}

  // @name Command-line options.
  // @{
  base::FilePath input_image_;
  base::FilePath input_pdb_;
  base::FilePath output_file_;
  bool pretty_print_;
  // @}

 private:
  DISALLOW_COPY_AND_ASSIGN(CodeTallyApp);
};

#endif  // SYZYGY_EXPERIMENTAL_CODE_TALLY_CODE_TALLY_APP_H_
