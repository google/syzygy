// Copyright 2012 Google Inc.
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
// Defines the RelinkApp class, which implements the command-line relink tool.

#ifndef SYZYGY_RELINK_RELINK_APP_H_
#define SYZYGY_RELINK_RELINK_APP_H_

#include "base/command_line.h"
#include "base/file_path.h"
#include "base/string_piece.h"
#include "base/time.h"
#include "syzygy/common/application.h"

namespace relink {

// This class implements the command-line relink utility.
class RelinkApp : public common::AppImplBase {
 public:
  RelinkApp()
      : seed_(0),
        padding_(0),
        augment_pdb_(false),
        compress_pdb_(false),
        strip_strings_(false),
        output_metadata_(false),
        overwrite_(false),
        basic_blocks_(false),
        exclude_bb_padding_(false) {
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
  FilePath input_dll_path_;
  FilePath input_pdb_path_;
  FilePath output_dll_path_;
  FilePath output_pdb_path_;
  FilePath order_file_path_;
  uint32 seed_;
  size_t padding_;
  bool augment_pdb_;
  bool compress_pdb_;
  bool strip_strings_;
  bool output_metadata_;
  bool overwrite_;
  bool basic_blocks_;
  bool exclude_bb_padding_;
  // @}

 private:
  DISALLOW_COPY_AND_ASSIGN(RelinkApp);
};

}  // namespace relink

#endif  // SYZYGY_RELINK_RELINK_APP_H_
