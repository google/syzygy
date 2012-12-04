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
class Logger {
 public:
  typedef base::Callback<bool(Logger*)> LoggerCallback;

  enum State {
    kStopped,
    kInitialized,
    kRunning,
    kStopping,
  };

  Logger();
  ~Logger();

  // Set the id for this instance.
  void set_instance_id(const base::StringPiece16& id) {
    DCHECK_EQ(kStopped, state_);
    instance_id_.assign(id.begin(), id.end());
  }

  // Set the destination file for this logger.
  void set_destination(FILE* destination) {
    DCHECK(destination != NULL);
    destination_ = destination;
  }

  // Set a callback to be invoked when the logger has started.
  void set_logger_started_callback(LoggerCallback callback) {
    logger_started_callback_ = callback;
  }

  // Set a callback to be invoked when the logger has stopped.
  void set_logger_stopped_callback(LoggerCallback callback) {
    logger_stopped_callback_ = callback;
  }

  // Begin accepting and handling RPC invocations. This method may only be
  // called by the thread which created the logger.
  //
  // This call is non-blocking. The request handlers will be run on a thread
  // pool owned by the RPC runtime.
  bool Start();

  // Request that the logger stop. This method be called by any thread once
  // the logger has started.
  //
  // This call is non-blocking. The request handlers run on a thread pool
  // owned by the RPC runtime.
  bool Stop();

  // Run the logger until is has completely shutdown. This method may only
  // be called by the thread which created, and subsequently started, the
  // logger.
  //
  // Following the receipt of an AsyncStop() request, it is the responsibility
  // of the thread which owns the logger to ensure that RunToCompletion() is
  // called as it will take care of flushing any in-flight log requests to disk
  // before terminating.
  //
  // This is a blocking call, it will return after all outstanding requests
  // have been handled and all log messages have been flushed.
  bool RunToCompletion();

  // Write @p message to the log destination. Note that calls to this method
  // are serialized using lock_.
  bool Write(const base::StringPiece& message);

 protected:
  // @name RPC Server Management Functions.
  // These functions, unless otherwise noted, are single threaded and must
  // all be called from the thread that created this instance.
  // @{
  bool InitRpc();
  bool StartRPC();
  bool StopRpc();  // This non-blocking function may be called from any thread.
  bool FinishRpc();  // This function is blocking.
  // @}

  // The ID of the thread that created this logger.
  base::PlatformThreadId owning_thread_id_;

  // A unique id to identify this logger instance.
  std::wstring instance_id_;

  // The current state of the logger.
  State state_;

  // The file to which received log messages should be written. This must
  // remain valid for at least as long as the logger is valid. Writes to
  // the destination are serialized with lock_;
  FILE* destination_;

  // The lock used to serializes writes to destination_;
  base::Lock lock_;

  // A callback to be invoked when the logger has successfully started.
  LoggerCallback logger_started_callback_;

  // A callback to be invoked when the logger has successfully stopped.
  LoggerCallback logger_stopped_callback_;

 private:
  DISALLOW_COPY_AND_ASSIGN(Logger);
};

}  // namespace logger
}  // namespace trace

#endif  // SYZYGY_TRACE_LOGGER_LOGGER_H_
