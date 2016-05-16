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
#ifndef SYZYGY_GRINDER_GRINDER_APP_H_
#define SYZYGY_GRINDER_GRINDER_APP_H_

#include "base/files/file_path.h"
#include "syzygy/application/application.h"
#include "syzygy/grinder/grinder.h"

namespace grinder {

// The application class that takes care of running Grinder over a set of
// profiler trace files.
class GrinderApp : public application::AppImplBase {
 public:
  GrinderApp();

  // The mode of processing we are performing.
  enum Mode {
    kBasicBlockEntry,
    kCoverage,
    kIndexedFrequencyData,
    kMemReplay,
    kProfile,
    kSample,
  };

  // @name Implementation of the AppImplbase interface.
  // @{
  bool ParseCommandLine(const base::CommandLine* command_line);
  int Run();
  void TearDown();
  // @}

  // @name Utility functions
  // @{
  void PrintUsage(const base::FilePath& program,
                  const base::StringPiece& message);
  // @}

 protected:
  std::vector<base::FilePath> trace_files_;
  base::FilePath output_file_;
  Mode mode_;
  std::unique_ptr<GrinderInterface> grinder_;
};

}  // namespace grinder

#endif  // SYZYGY_GRINDER_GRINDER_APP_H_
