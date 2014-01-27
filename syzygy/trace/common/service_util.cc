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

#include "syzygy/trace/common/service_util.h"

#include "base/file_util.h"
#include "syzygy/common/com_utils.h"

namespace trace {
namespace common {

bool AcquireMutex(const base::StringPiece16& mutex_name,
                  base::win::ScopedHandle* mutex) {
  DCHECK(mutex != NULL);
  DCHECK(!mutex->IsValid());

  std::wstring name(mutex_name.begin(), mutex_name.end());
  const wchar_t* name_ptr = name.empty() ? NULL : name.c_str();

  base::win::ScopedHandle tmp_mutex(::CreateMutex(NULL, FALSE, name_ptr));
  if (!tmp_mutex.IsValid()) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to create named mutex: " << ::common::LogWe(error)
               << ".";
    return false;
  }
  const DWORD kOneSecondInMs = 1000;

  switch (::WaitForSingleObject(tmp_mutex, kOneSecondInMs)) {
    case WAIT_ABANDONED:
      LOG(WARNING) << "Orphaned named mutex found!";
      // Fall through...

    case WAIT_OBJECT_0:
      VLOG(1) << "Named mutex acquired.";
      mutex->Set(tmp_mutex.Take());
      return true;

    case WAIT_TIMEOUT:
      LOG(ERROR) << "A synonymous named mutex already exists.";
      break;

    default: {
      DWORD error = ::GetLastError();
      LOG(ERROR) << "Failed to acquire mutex: " << ::common::LogWe(error)
                 << ".";
      break;
    }
  }
  return false;
}

bool InitEvent(const base::StringPiece16& event_name,
               base::win::ScopedHandle* handle) {
  DCHECK(handle != NULL);
  DCHECK(!handle->IsValid());

  // StringPieces aren't guaranteed to be NULL terminated, so we make a copy.
  std::wstring name(event_name.begin(), event_name.end());
  const wchar_t* name_ptr = name.empty() ? NULL : name.c_str();

  handle->Set(::CreateEvent(NULL, TRUE, FALSE, name_ptr));
  if (!handle->IsValid())
    return false;
  return true;
}

ScopedConsoleCtrlHandler::ScopedConsoleCtrlHandler() : handler_(NULL) {
}

ScopedConsoleCtrlHandler::~ScopedConsoleCtrlHandler() {
  if (handler_ != NULL) {
    ignore_result(::SetConsoleCtrlHandler(handler_, FALSE));
    handler_ = NULL;
  }
}

bool ScopedConsoleCtrlHandler::Init(PHANDLER_ROUTINE handler) {
  DCHECK(handler != NULL);
  DCHECK(handler_ == NULL);

  if (!::SetConsoleCtrlHandler(handler, TRUE)) {
    DWORD err = ::GetLastError();
    LOG(ERROR) << "Failed to register console control handler: "
               << ::common::LogWe(err) << ".";
    return false;
  }

  handler_ = handler;
  return true;
}

bool SplitCommandLine(const CommandLine* orig_command_line,
                      CommandLine* logger_command_line,
                      scoped_ptr<CommandLine>* app_command_line) {
  DCHECK(orig_command_line != NULL);
  DCHECK(!orig_command_line->argv().empty());
  DCHECK(logger_command_line != NULL);
  DCHECK(app_command_line != NULL);

  // Copy the initial parts of the command-line, up to and including the
  // first non-switch argument (which should be the "action"), into a
  // string vector for the logger command line.
  CommandLine::StringVector logger_argv;
  CommandLine::StringVector::const_iterator it =
      orig_command_line->argv().begin();
  logger_argv.push_back(*(it++));  // Always copy the program.
  for (; it != orig_command_line->argv().end(); ++it) {
    logger_argv.push_back(*it);
    if ((*it)[0] != L'-') {
      ++it;
      break;
    }
  }

  // Strip out the (optional) sentinel which marks the split between the
  // two command-lines.
  if (it != orig_command_line->argv().end() && *it == L"--")
    ++it;

  // Copy the rest of the command-line arguments into a string vector for the
  // app command line.
  CommandLine::StringVector app_argv;
  for (; it != orig_command_line->argv().end(); ++it) {
    app_argv.push_back(*it);
  }

  // Initialize logger command lines with the new arguments.
  logger_command_line->InitFromArgv(logger_argv);

  // Initialize application command lines with the new arguments.
  if (!app_argv.empty()) {
    // Avoid switches processing in application commandLine parsing.
    // Otherwise, we break command like:
    //     agent_logger.exe START -- <app> -d 1 -c 2.
    // We should not re-order <app> parameters.
    app_command_line->reset(new CommandLine(base::FilePath(app_argv[0])));
    for (size_t arg = 1; arg < app_argv.size(); ++arg)
      app_command_line->get()->AppendArgNative(app_argv[arg]);
  }

  return true;
}

}  // namespace common
}  // namespace trace
