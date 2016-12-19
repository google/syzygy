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

#ifndef SYZYGY_PROTECT_PROTECT_LIB_PROTECT_APP_H_
#define SYZYGY_PROTECT_PROTECT_LIB_PROTECT_APP_H_

#include "base/command_line.h"
#include "base/files/file_path.h"
#include "base/strings/string_piece.h"
#include "base/time/time.h"
#include "base/values.h"
#include "syzygy/application/application.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/experimental/protect/protect_lib/protect_flummox.h"

namespace protect {

// This class implements the command-line Protect utility.
class ProtectApp : public application::AppImplBase {
public:
  ProtectApp() : AppImplBase("ProtectApp") {}

  // @name Implementation of the AppImplBase interface.
  // @{
  bool ParseCommandLine(const base::CommandLine* command_line);
  bool SetUp();
  int Run();
  // @}

 protected:
  bool overwrite_;
  scoped_ptr<CustomFlummoxInstrumenter> instrumenter_;

 private:
  DISALLOW_COPY_AND_ASSIGN(ProtectApp);
};

}  // namespace protect

#endif // SYZYGY_PROTECT_PROTECT_LIB_PROTECT_APP_H_
