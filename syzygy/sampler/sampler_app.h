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
#ifndef SYZYGY_SAMPLER_SAMPLER_APP_H_
#define SYZYGY_SAMPLER_SAMPLER_APP_H_

#include "base/files/file_path.h"
#include "syzygy/common/application.h"

namespace sampler {

// The application class that takes care of running a profiling sampler. This
// works by polling running processes and attaching a
// base::win::SamplingProfiler instance to every module of interest. The output
// is then shuttled to trace data files.
class SamplerApp : public common::AppImplBase {
 public:
  SamplerApp();

  // @name Implementation of the AppImplbase interface.
  // @{
  bool ParseCommandLine(const CommandLine* command_line);
  int Run();
  // @}

 protected:
  // Helper function for printing a usage statement.
  // @param program The path to the executable.
  // @param message An optional message that will precede the usage statement.
  // @returns false.
  bool PrintUsage(const base::FilePath& program,
                  const base::StringPiece& message);
};

}  // namespace sampler

#endif  // SYZYGY_SAMPLER_SAMPLER_APP_H_
