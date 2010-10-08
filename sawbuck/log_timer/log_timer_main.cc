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
//
// Processes an ETW log searching for specific Provider/Task/Opcode triplets
// and printing out the time difference between these triplets.

#include <objbase.h>
#include <string>
#include <vector>
#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/file_path.h"
#include "base/logging.h"
#include "base/stringprintf.h"
#include "base/utf_string_conversions.h"
#include "pcrecpp.h"  // NOLINT
#include "sawbuck/log_timer/log_timer.h"

pcrecpp::RE kEventRe("([^/]+)/([^/]+)/([^/]+)(/([^/]+))?");

bool ParseCommandLine(FilePath* logfile_path,
                      std::vector<LogTimer::Event>* events) {
  CommandLine::Init(0, NULL);
  CommandLine* cmd_line = CommandLine::ForCurrentProcess();

  if (!cmd_line->HasSwitch("log-file")) {
    LOG(ERROR) << "No log file specified (--log-file).";
    return false;
  }
  *logfile_path = cmd_line->GetSwitchValuePath("log-file");

  std::vector<CommandLine::StringType> args = cmd_line->args();
  if (args.size() == 0) {
    LOG(ERROR) << "No events specified. Should be of the form:" <<
        "<provider>/<task>/<opcode>[/<guid>]";
    return false;
  }

  for (unsigned int i = 0; i < args.size(); ++i) {
    std::string arg(WideToUTF8(args[i]));
    std::string provider;
    std::string task;
    std::string opcode;
    std::string dummy;
    std::string guid;
    if (!kEventRe.FullMatch(arg, &provider, &task, &opcode, &dummy, &guid)) {
      LOG(ERROR) << "Could not parse argument: " << arg;
      return false;
    }

    LogTimer::Event event;
    UTF8ToWide(provider.c_str(), provider.length(), &event.provider);
    UTF8ToWide(task.c_str(), task.length(), &event.task);
    UTF8ToWide(opcode.c_str(), opcode.length(), &event.opcode);

    if (!guid.empty()) {
      std::wstring guid_str;
      UTF8ToWide(guid.c_str(), guid.length(), &guid_str);
      HRESULT hr = CLSIDFromString(guid_str.c_str(), &event.guid);
      if (FAILED(hr)) {
        LOG(ERROR) << "Could not parse guid: " << guid;
        return false;
      }
    }

    events->push_back(event);
  }

  return true;
}

void wmain() {
  base::AtExitManager at_exit;

  FilePath logfile_path;
  std::vector<LogTimer::Event> events;
  if (!ParseCommandLine(&logfile_path, &events))
    return;

  LogTimer timer;
  for (unsigned int i = 0; i < events.size(); ++i) {
    timer.AddEvent(events[i]);
  }

  timer.ProcessLog(logfile_path.value());
}
