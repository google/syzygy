// Copyright 2011 Google Inc.
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
// Log viewer module declaration.
#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/i18n/icu_util.h"
#include "base/logging.h"
#include "base/logging_win.h"
#include "base/message_loop.h"

#include <InitGuid.h>  // NOLINT
#include "sawdust/tracer/sawdust_guids.h"  // NOLINT
#include "sawdust/app/sawdust_app.h"

int APIENTRY wWinMain(HINSTANCE instance,
                      HINSTANCE prev_instance,
                      LPTSTR /*cmd_line*/,
                      int show) {
  CommandLine::Init(0, NULL);
  base::AtExitManager at_exit;

  // Initialize ICU.
  icu_util::Initialize();

  // Init logging to no file logging.
  logging::InitLogging(NULL,
                       logging::LOG_NONE,
                       logging::DONT_LOCK_LOG_FILE,
                       logging::DELETE_OLD_LOG_FILE,
                       logging::DISABLE_DCHECK_FOR_NON_OFFICIAL_RELEASE_BUILDS);
  logging::LogEventProvider::Initialize(kSawdustLoggingGuid);

  SawdustApplication app(instance);
  MessageLoop main_loop(MessageLoop::TYPE_UI);

  if (FAILED(app.Initialize(show)))
    return -1;

  main_loop.Run();
  return 0;
}
