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
// This file declares the trace::logger::Logger class which implements
// a simple logging service over RPC.

#ifndef SYZYGY_TRACE_LOGGER_LOGGER_H_
#define SYZYGY_TRACE_LOGGER_LOGGER_H_

#include "base/callback.h"
#include "base/message_loop.h"
#include "base/string_piece.h"
#include "base/threading/platform_thread.h"
#include "syzygy/trace/common/service.h"
#include "syzygy/trace/rpc/logger_rpc.h"

namespace trace {
namespace logger {

// Implements the Logger interface (see "logger_rpc.idl").
//
// Note: The Logger expects to be the only RPC service running in the process.
//
// TODO(rogerm): Add a Write function more amenable to out-of-process ASAN
//     error reporting (i.e., accepts module info and stack traces in some
//     format).
class Logger : public trace::common::Service {
 public:
  Logger();
  virtual ~Logger();

  // Set the destination file for this logger.
  void set_destination(FILE* destination) {
    DCHECK(destination != NULL);
    destination_ = destination;
  }

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

  // The lock used to serializes writes to destination_;
  base::Lock write_lock_;

  // The lock used to serialize access to the debug help library used to
  // symbolize traces.
  base::Lock symbol_lock_;

 private:
  DISALLOW_COPY_AND_ASSIGN(Logger);
};

}  // namespace logger
}  // namespace trace

#endif  // SYZYGY_TRACE_LOGGER_LOGGER_H_
