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
//
// A command line application to compute the code contribution size per
// object file, function and source line for a given executable.
// Generates output in JSON for easy downstream processing.

#ifndef SYZYGY_EXPERIMENTAL_HEAP_ENUMERATE_HEAP_ENUMERATE_APP_H_
#define SYZYGY_EXPERIMENTAL_HEAP_ENUMERATE_HEAP_ENUMERATE_APP_H_

#include <cstdio>

#include "base/command_line.h"
#include "base/files/file_path.h"
#include "base/strings/string_piece.h"
#include "syzygy/application/application.h"

// This class implements the code_tally command-line utility.
//
// See the description given in HeapEnumerateApp:::PrintUsage() for information
// about running this utility.
class HeapEnumerateApp : public application::AppImplBase {
 public:
  // @name Implementation of the AppImplBase interface.
  // @{
  HeapEnumerateApp()
      : application::AppImplBase("HeapEnumerate"), output_file_(nullptr) {}

  bool ParseCommandLine(const base::CommandLine* command_line);

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
  base::FilePath output_file_;
  // @}

 private:
  DISALLOW_COPY_AND_ASSIGN(HeapEnumerateApp);
};

#endif  // SYZYGY_EXPERIMENTAL_HEAP_ENUMERATE_HEAP_ENUMERATE_APP_H_
