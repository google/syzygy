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
// Defines the RunLaaApp class which implements a command-line tool for
// running applications with Large Address Aware mode enabled or disabled.

#ifndef SYZYGY_RUNLAA_RUNLAA_APP_H_
#define SYZYGY_RUNLAA_RUNLAA_APP_H_

#include "base/command_line.h"
#include "base/files/file_path.h"
#include "syzygy/application/application.h"

namespace runlaa {

class RunLaaApp : public application::AppImplBase {
 public:
  RunLaaApp()
      : AppImplBase("RunLAA"),
        is_laa_(false),
        in_place_(false),
        keep_temp_dir_(false) {}

  // @name Implementation of the AppImplBase interface.
  // @{
  bool ParseCommandLine(const base::CommandLine* command_line);
  int Run();
  // @}

  // Exposed for unittesting.
 protected:
  std::string expect_mode_;
  base::FilePath image_;
  bool is_laa_;
  bool in_place_;
  bool keep_temp_dir_;
  base::CommandLine::StringVector child_argv_;
};

}  // namespace runlaa

#endif  // SYZYGY_RUNLAA_RUNLAA_APP_H_
