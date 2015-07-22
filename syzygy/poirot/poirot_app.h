// Copyright 2015 Google Inc. All Rights Reserved.
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

#ifndef SYZYGY_POIROT_POIROT_APP_H_
#define SYZYGY_POIROT_POIROT_APP_H_

#include "base/command_line.h"
#include "base/files/file_path.h"
#include "base/strings/string_piece.h"
#include "syzygy/application/application.h"
#include "syzygy/poirot/minidump_processor.h"

namespace poirot {

// This class implements the minidump processor command-line utility.
//
// See the description given in PoirotApp:::PrintUsage() for
// information about running this utility.
class PoirotApp : public application::AppImplBase {
 public:
  // @name Implementation of the AppImplBase interface.
  // @{
  PoirotApp() : application::AppImplBase("PoirotApp") {}

  bool ParseCommandLine(const base::CommandLine* command_line);

  int Run();
  // @}

 protected:
  // @name Utility function
  // @{
  void PrintUsage(const base::FilePath& program,
                  const base::StringPiece& message);
  // @}

  // @name Command-line options.
  // @{
  base::FilePath input_minidump_;
  base::FilePath output_file_;
  // @}

 private:
  DISALLOW_COPY_AND_ASSIGN(PoirotApp);
};

}  // namespace poirot

#endif  // SYZYGY_POIROT_POIROT_APP_H_
