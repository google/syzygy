// Copyright 2010 Google Inc.
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
#include "base/at_exit.h"
#include "base/command_line.h"
#include "gtest/gtest.h"
#include "sawbuck/viewer/viewer_module.h"

#include <initguid.h>  // NOLINT
#include "sawbuck/viewer/sawbuck_guids.h"  // NOLINT

SawbuckAppModule g_sawbuck_app_module;

int main(int argc, char** argv) {
  testing::InitGoogleTest(&argc, argv);

  base::AtExitManager at_exit;
  CommandLine::Init(argc, argv);

  return RUN_ALL_TESTS();
}
