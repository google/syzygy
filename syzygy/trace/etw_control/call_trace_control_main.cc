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
// A utility for controlling call-traces from the command-line.
#include <iostream>
#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/logging.h"
#include "syzygy/trace/etw_control/call_trace_control.h"

static const char kUsage[] =
    "Usage: call_trace_control [command] [options]\n"
    "Commands:\n"
    "  start: start the call-trace, creating the ETW logs.\n"
    "  query: query the call-trace status.\n"
    "  stop: stop the call-trace, flushing and closing the ETW logs.\n"
    "\n"
    "Options to 'start':\n"
    "  --append: Append to the ETW log files rather than overwriting them.\n"
    "  --call-trace-file: Path to call-trace ETW log file.\n"
    "      Defaults to 'call_trace.etl' in the current working directory.\n"
    "  --chrome-file: Path to Chrome ETW log file.\n"
    "      If not specified, does not enable Chrome ETW logging.\n"
    "  --min-buffers: The minimum number of buffers to use for call-trace.\n"
    "      Augment this from the defaults if seeing lost events.\n"
    "  --kernel-file: Path to kernel ETW log file.\n"
    "      Defaults to 'kernel.etl' in the current working directory.\n"
    "  --kernel-flags: Flags to pass to kernel ETW logger (numeric).\n"
    "      Defaults to PROCESS|THREAD|IMAGE_LOAD|DISK_IO|DISK_FILE_IO|\n"
    "                  MEMORY_PAGE_FAULTS|MEMORY_HARD_FAULTS|FILE_IO.\n";

int Usage() {
  std::cout << kUsage;
  return 1;
}

enum Command {
  kStart,
  kQuery,
  kStop,
};

struct Options {
  Command command;
};

bool ParseOptions(Options* options) {
  DCHECK(options != NULL);

  CommandLine* cmd_line = CommandLine::ForCurrentProcess();

  if (cmd_line->HasSwitch("help") || cmd_line->HasSwitch("h")) {
    Usage();
    return false;
  }

  if (cmd_line->GetArgs().size() == 0) {
    LOG(ERROR) << "Must specify a command.";
    return false;
  }

  if (cmd_line->GetArgs().size() > 1) {
    LOG(ERROR) << "Can only specify one command.";
    return false;
  }

  if (cmd_line->GetArgs()[0] == L"start") {
    options->command = kStart;
  } else if (cmd_line->GetArgs()[0] == L"query") {
    options->command = kQuery;
  } else if (cmd_line->GetArgs()[0] == L"stop") {
    options->command = kStop;
  } else {
    LOG(ERROR) << "Unknown command: " << cmd_line->GetArgs()[0] << ".";
    return false;
  }

  return true;
}

int main(int argc, char** argv) {
  base::AtExitManager at_exit;
  CommandLine::Init(argc, argv);

  logging::LoggingSettings settings;
  settings.logging_dest = logging::LOG_TO_SYSTEM_DEBUG_LOG;
  settings.lock_log = logging::DONT_LOCK_LOG_FILE;
  settings.delete_old = logging::APPEND_TO_OLD_LOG_FILE;
  if (!logging::InitLogging(settings))
    return 1;

  Options options;
  if (!ParseOptions(&options))
    return 1;

  // Call the command we care about.
  bool success = false;
  switch (options.command) {
    case kStart: {
      success = StartCallTraceImpl();
      break;
    }

    case kQuery: {
      success = QueryCallTraceImpl();
      break;
    }

    case kStop: {
      success = StopCallTraceImpl();
      break;
    }

    default: {
      NOTREACHED() << "Unexpected command.";
    }
  }

  return success ? 0 : 1;
}
