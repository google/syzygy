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
// Defines the OptimizeApp class, which implements the command-line optimize.exe
// tool.

#ifndef SYZYGY_OPTIMIZE_OPTIMIZE_APP_H_
#define SYZYGY_OPTIMIZE_OPTIMIZE_APP_H_

#include "base/command_line.h"
#include "base/string_piece.h"
#include "base/time.h"
#include "base/files/file_path.h"
#include "syzygy/common/application.h"

namespace optimize {

// This class implements the command-line optimize utility.
class OptimizeApp : public common::AppImplBase {
 public:
  OptimizeApp()
      : AppImplBase("Optimize"),
        basic_block_reorder_(false),
        block_alignment_(false),
        fuzz_(false),
        inlining_(false),
        overwrite_(false),
        peephole_(false) {
  }

  // @name Implementation of the AppImplBase interface.
  // @{
  bool ParseCommandLine(const CommandLine* command_line);
  bool SetUp();
  int Run();
  // @}

 protected:
  // @name Utility members.
  // @{
  bool Usage(const CommandLine* command_line,
             const base::StringPiece& message) const;
  // @}

  // @name Command-line parameters.
  // @{
  base::FilePath input_image_path_;
  base::FilePath input_pdb_path_;
  base::FilePath output_image_path_;
  base::FilePath output_pdb_path_;
  base::FilePath branch_file_path_;
  bool block_alignment_;
  bool basic_block_reorder_;
  bool fuzz_;
  bool inlining_;
  bool peephole_;
  bool overwrite_;
  // @}

 private:
  DISALLOW_COPY_AND_ASSIGN(OptimizeApp);
};

}  // namespace optimize

#endif  // SYZYGY_OPTIMIZE_OPTIMIZE_APP_H_
