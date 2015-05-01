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
// A command line application to decompose an image multiple times and
// generate timing information.

#ifndef SYZYGY_EXPERIMENTAL_TIMED_DECOMPOSER_TIMED_DECOMPOSER_APP_H_
#define SYZYGY_EXPERIMENTAL_TIMED_DECOMPOSER_TIMED_DECOMPOSER_APP_H_

#include "base/command_line.h"
#include "base/files/file_path.h"
#include "syzygy/application/application.h"

namespace experimental {

// This class implements the timed_decomposer command-line utility.
//
// See the description given in TimedDecomposerApp:::PrintUsage() for
// information about running this utility.
class TimedDecomposerApp : public application::AppImplBase {
 public:
  TimedDecomposerApp();

  // @name Implementation of the AppImplBase interface.
  // @{
  bool ParseCommandLine(const base::CommandLine* command_line);

  int Run();
  // @}

 protected:
  // Print the app's usage information.
  void PrintUsage(const base::FilePath& program,
                  const base::StringPiece& message);

  // @name Command-line options.
  // @{
  base::FilePath image_path_;
  base::FilePath csv_path_;
  int num_iterations_;
  // @}

 private:
  DISALLOW_COPY_AND_ASSIGN(TimedDecomposerApp);
};

}  // namespace experimental

#endif  // SYZYGY_EXPERIMENTAL_TIMED_DECOMPOSER_TIMED_DECOMPOSER_APP_H_
