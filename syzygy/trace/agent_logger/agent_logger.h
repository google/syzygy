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
// This file declares the trace::agent_logger::AgentLogger class which
// implements a simple logging service over RPC.

#ifndef SYZYGY_TRACE_AGENT_LOGGER_AGENT_LOGGER_H_
#define SYZYGY_TRACE_AGENT_LOGGER_AGENT_LOGGER_H_

#include "base/callback.h"
#include "base/file_util.h"
#include "base/message_loop/message_loop.h"
#include "base/process/process.h"
#include "base/strings/string_piece.h"
#include "base/threading/platform_thread.h"
#include "syzygy/trace/common/service.h"
#include "syzygy/trace/rpc/logger_rpc.h"

namespace trace {
namespace agent_logger {

// Implements the Logger interface (see "logger_rpc.idl").
//
// Note: The Logger expects to be the only RPC service running in the process.
class AgentLogger : public trace::common::Service {
 public:
  AgentLogger();
  virtual ~AgentLogger();

  // Set the destination file for this logger.
  void set_destination(FILE* destination) {
    DCHECK(destination != NULL);
    base::AutoLock auto_lock(write_lock_);
    destination_ = destination;
  }

  // Get/Set the directory to which minidumps should be written.
  // @{
  const base::FilePath& minidump_dir() const { return minidump_dir_; }
  void set_minidump_dir(const base::FilePath& dir) { minidump_dir_ = dir; }
  // @}

  // Get/Set the symbolize_stack_traces_ flag.
  // @{
  bool symbolize_stack_traces() { return symbolize_stack_traces_; }
  void set_symbolize_stack_traces(bool value) {
    symbolize_stack_traces_ = value;
  }
  // @}

  // Append a trace dump for @p process, given @p trace_data containing
  // @p trace_length elements. The output will be appended to @p message.
  //
  // Note that the DWORD elements of @p trace_data are really void* values
  // pointing to the frame pointers of a call stack in @p process.
  //
  // Calls to this method are serialized under symbol_lock_.
  bool AppendTrace(HANDLE process,
                   const DWORD* trace_data,
                   size_t trace_length,
                   std::string* message);

  // Captures a stack trace in a @p process given a program @p context.
  // @param process An open handle to the running process.
  // @param context The program context from which to trace.
  // @param trace_data The vector into which the trace will be populated.
  // @returns true on success, false otherwise.
  bool CaptureRemoteTrace(HANDLE process,
                          CONTEXT* context,
                          std::vector<DWORD>* trace_data);

  // Write @p message to the log destination. Note that calls to this method
  // are serialized using write_lock_.
  bool Write(const base::StringPiece& message);

  // Generate a minidump for the calling process.
  // @param process An open handle to the running process.
  // @param pid The process id of the process to dump.
  // @param tid The thread id (in the process to dump) of the thread which is
  //     causing the minidump to be generated.
  // @param exc_ptr The pointer value (in the memory address space of the
  //     process to dump) of the exception record for which the dump is being
  //     generated.
  // @param flags Reserved.
  // @returns true on success, false otherwise.
  bool SaveMiniDump(HANDLE process,
                    base::ProcessId pid,
                    DWORD tid,
                    DWORD exc_ptr,
                    DWORD flags);

 protected:
  // @name Implementation of Service.
  // @{
  virtual bool StartImpl();
  virtual bool StopImpl();
  virtual bool JoinImpl();
  // @}

  // @name RPC Server Management Functions.
  // These functions, unless otherwise noted, are single threaded and must
  // all be called from the thread that created this instance.
  // @{
  bool InitRpc();
  bool StartRpc();
  bool StopRpc();  // This non-blocking function may be called from any thread.
  bool FinishRpc();  // This function is blocking.
  // @}

  // The file to which received log messages should be written. This must
  // remain valid for at least as long as the logger is valid. Writes to
  // the destination are serialized with lock_;
  FILE* destination_;

  // The directory to which minidumps should be written.
  base::FilePath minidump_dir_;

  // The lock used to serializes writes to destination_;
  base::Lock write_lock_;

  // The lock used to serialize access to the debug help library used to
  // symbolize traces.
  base::Lock symbol_lock_;

  // Indicates if we should symbolize the stack traces. Defaults to true.
  bool symbolize_stack_traces_;

 private:
  DISALLOW_COPY_AND_ASSIGN(AgentLogger);
};

}  // namespace agent_logger
}  // namespace trace

#endif  // SYZYGY_TRACE_AGENT_LOGGER_AGENT_LOGGER_H_
