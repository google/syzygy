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

#include <objbase.h>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/logging.h"
#include "base/files/file_path.h"
#include "gtest/gtest.h"

int main(int argc, char** argv) {
  ::CoInitialize(NULL);

  testing::InitGoogleTest(&argc, argv);
  CommandLine::Init(argc, argv);
  base::AtExitManager at_exit;

  if (!logging::InitLogging(
          L"",
          logging::LOG_ONLY_TO_SYSTEM_DEBUG_LOG,
          logging::DONT_LOCK_LOG_FILE,
          logging::APPEND_TO_OLD_LOG_FILE,
          logging::ENABLE_DCHECK_FOR_NON_OFFICIAL_RELEASE_BUILDS)) {
    return 1;
  }

  logging::SetMinLogLevel(logging::LOG_ERROR);

  int ret = RUN_ALL_TESTS();

  ::CoUninitialize();

  return ret;
}
