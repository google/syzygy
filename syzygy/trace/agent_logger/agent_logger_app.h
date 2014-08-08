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
// This file declares the trace::agent_logger::LoggerApp class which implements
// a simple logging service for binding to RPC.

#ifndef SYZYGY_TRACE_AGENT_LOGGER_AGENT_LOGGER_APP_H_
#define SYZYGY_TRACE_AGENT_LOGGER_AGENT_LOGGER_APP_H_

#include "base/basictypes.h"
#include "base/command_line.h"
#include "base/files/file_path.h"
#include "base/strings/string_piece.h"
#include "base/strings/string_util.h"
#include "base/time/time.h"
#include "syzygy/common/application.h"

namespace trace {
namespace agent_logger {

// Encapsulates a Logger as a command-line application.
//
// The application runs as a singleton for a given instance id. This is
// enforced using a named mutex, specialized by the instance id, that the
// logger acquires on startup. If the mutex is already held by another
// process (presumably another logger instance) then the logger aborts.
//
// The logger also exposes two named events which are set on logger startup
// and shutdown, respectively. The spawn command waits for the startup event
// to be set (or the termination of the spawned logger) before returning and
// the stop command waits for the shutdown event to be set before returning.
class LoggerApp : public common::AppImplBase {
 public:
  LoggerApp();
  ~LoggerApp();

  static const size_t kMaxInstanceIdLength = 16;

  // @name Implementation of the AppImplBase interface.
  // @{
  bool ParseCommandLine(const CommandLine* command_line);
  int Run();
  // @}

  // Public for unit-testing purposes.
  // @{
  // Start the logger in the foreground. Running app_command_line_ if it is
  // not empty.
  bool Start();
  // Start the logger in the background.
  bool Spawn();
  // Print the status (running/not-running) of the logger.
  bool Status();
  // Stop a (separately running) logger instance.
  bool Stop();
  // @}

 protected:
  // The type of function to which action keywords are mapped.
  typedef bool (LoggerApp::*ActionHandler)();

  // A structure to hold a mapping between an action and its implementation.
  struct ActionTableEntry {
    const wchar_t* const action;
    const ActionHandler handler;
  };

  // A functor to allow searching (and sorting validation) of a table of
  // ActionTableEntry items.
  struct ActionTableEntryCompare {
    bool operator()(const ActionTableEntry& lhs,
                    const ActionTableEntry& rhs) const {
      return ::_wcsicmp(lhs.action, rhs.action) < 0;
    }

    bool operator()(const base::StringPiece16& lhs,
                    const ActionTableEntry& rhs) const {
      return ::_wcsnicmp(lhs.data(), rhs.action, lhs.size()) < 0;
    }

    bool operator()(const ActionTableEntry& lhs,
                    const base::StringPiece16& rhs) const {
      return ::_wcsnicmp(lhs.action, rhs.data(), rhs.size()) < 0;
    }
  };

  // A helper function to find the handler method for a given action.
  static const ActionTableEntry* FindActionHandler(
      const base::StringPiece16& action);

  // Helper to resolve output_file_path_ to an open file. This will set
  // @p must_close to true if @path denotes a newly opened file, and false
  // if it denotes stderr or stdout.
  bool OpenOutputFile(FILE** output_file, bool* must_close);

  // Print the usage/help text, plus an optional @p message.
  bool Usage(const CommandLine* command_line,
             const base::StringPiece& message) const;

  // A table mapping action keywords to their handler implementations.
  static const ActionTableEntry kActionTable[];

  // Command-line actions.
  // @{
  static const wchar_t kStart[];
  static const wchar_t kSpawn[];
  static const wchar_t kStatus[];
  static const wchar_t kStop[];
  // @}

  // Command-line options.
  // @{
  static const char kInstanceId[];
  static const char kUniqueInstanceId[];
  static const char kOutputFile[];
  static const char kAppend[];
  static const char kMiniDumpDir[];
  // @}

  // Special-case output file value tokens.
  // @{
  static const wchar_t kStdOut[];
  static const wchar_t kStdErr[];
  // @}

  // The command line parameters pertaining to the logger.
  CommandLine logger_command_line_;

  // The command-line parameters pertaining to the subprocess to exec.
  scoped_ptr<CommandLine> app_command_line_;

  // Members to hold the logger's parsed command-line parameters
  // @{
  std::wstring instance_id_;
  std::wstring action_;
  ActionHandler action_handler_;
  base::FilePath output_file_path_;
  base::FilePath mini_dump_dir_;
  bool append_;
  // @}

 private:
  DISALLOW_COPY_AND_ASSIGN(LoggerApp);
};

}  // namespace agent_logger
}  // namespace trace

#endif  // SYZYGY_TRACE_AGENT_LOGGER_AGENT_LOGGER_APP_H_
