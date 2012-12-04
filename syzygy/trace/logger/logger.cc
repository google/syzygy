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
// This file defines the trace::logger::Logger class which implements the
// Logger RPC interface.

#include "syzygy/trace/logger/logger.h"

#include "base/bind.h"
#include "base/string_util.h"
#include "base/win/scoped_handle.h"
#include "sawbuck/common/com_utils.h"
#include "syzygy/trace/rpc/rpc_helpers.h"

namespace trace {
namespace logger {

using trace::client::GetInstanceString;

Logger::Logger()
    : owning_thread_id_(base::PlatformThread::CurrentId()),
      destination_(NULL),
      state_(kStopped) {
}

Logger::~Logger() {
  DCHECK_EQ(owning_thread_id_, base::PlatformThread::CurrentId());
  if (state_ != kStopped) {
    ignore_result(Stop());
    ignore_result(RunToCompletion());
  }
  DCHECK_EQ(kStopped, state_);
}

bool Logger::Start() {
  DCHECK_EQ(owning_thread_id_, base::PlatformThread::CurrentId());
  DCHECK_EQ(kStopped, state_);

  LOG(INFO) << "Starting the logging service.";

  if (!InitRpc())
    return false;

  if (!StartRPC())
    return false;

  return true;
}

bool Logger::Stop() {
  if (!StopRpc())
    return false;

  return true;
}

bool Logger::RunToCompletion() {
  DCHECK_EQ(owning_thread_id_, base::PlatformThread::CurrentId());
  DCHECK_EQ(kRunning, state_);

  // Finish processing all RPC events. If Stop() has previously been called
  // this will simply ensure that all outstanding requests are handled. If
  // Stop has not been called, this will continue (i.e., block) handling events
  // until someone else calls Stop() in another thread.
  if (!FinishRpc())
    return false;

  DCHECK_EQ(kStopped, state_);

  return true;
}

bool Logger::Write(const base::StringPiece& message) {
  if (message.empty())
    return true;

  base::AutoLock auto_lock(lock_);

  size_t chars_written = ::fwrite(message.data(),
                                  sizeof(std::string::value_type),
                                  message.size(),
                                  destination_);

  if (chars_written != message.size()) {
    LOG(ERROR) << "Failed to write log message.";
    return false;
  }

  if (message[message.size() - 1] != '\n' &&
      ::fwrite("\n", 1, 1, destination_) != 1) {
    LOG(ERROR) << "Failed to append trailing newline.";
    return false;
  }

  return true;
}

bool Logger::InitRpc() {
  // This method must be called by the owning thread, so no need to otherwise
  // synchronize the method invocation.
  DCHECK_EQ(owning_thread_id_, base::PlatformThread::CurrentId());
  DCHECK_EQ(kStopped, state_);

  RPC_STATUS status = RPC_S_OK;

  // Initialize the RPC protocol we want to use.
  std::wstring protocol(kLoggerRpcProtocol);
  std::wstring endpoint(
      GetInstanceString(kLoggerRpcEndpointRoot, instance_id_));

  VLOG(1) << "Initializing RPC endpoint '" << endpoint << "' "
          << "using the '" << protocol << "' protocol.";
  status = ::RpcServerUseProtseqEp(
      reinterpret_cast<RPC_WSTR>(&protocol[0]),
      RPC_C_LISTEN_MAX_CALLS_DEFAULT,
      reinterpret_cast<RPC_WSTR>(&endpoint[0]),
      NULL /* Security descriptor. */);
  if (status != RPC_S_OK && status != RPC_S_DUPLICATE_ENDPOINT) {
    LOG(ERROR) << "Failed to init RPC protocol: " << com::LogWe(status) << ".";
    return false;
  }

  // Register the logger interface.
  VLOG(1) << "Registering the Logger interface.";
  status = ::RpcServerRegisterIf(
      LoggerService_Logger_v1_0_s_ifspec, NULL, NULL);
  if (status != RPC_S_OK) {
    LOG(ERROR) << "Failed to register RPC interface: "
               << com::LogWe(status) << ".";
    return false;
  }

  // Register the logger control interface.
  VLOG(1) << "Registering the Logger Control interface.";
  status = ::RpcServerRegisterIf(
      LoggerService_LoggerControl_v1_0_s_ifspec, NULL, NULL);
  if (status != RPC_S_OK) {
    LOG(ERROR) << "Failed to register RPC interface: "
               << com::LogWe(status) << ".";
    return false;
  }

  state_ = kInitialized;

  return true;
}

bool Logger::StartRPC() {
  // This method must be called by the owning thread, so no need to otherwise
  // synchronize the method invocation.
  VLOG(1) << "Starting the RPC server.";

  DCHECK_EQ(owning_thread_id_, base::PlatformThread::CurrentId());
  DCHECK_EQ(kInitialized, state_);

  RPC_STATUS status = ::RpcServerListen(
      1,  // Minimum number of handler threads.
      RPC_C_LISTEN_MAX_CALLS_DEFAULT,
      TRUE);

  if (status != RPC_S_OK) {
    LOG(ERROR) << "Failed to run RPC server: " << com::LogWe(status) << ".";
    ignore_result(FinishRpc());
    return false;
  }

  state_ = kRunning;

  // Invoke the callback for the logger started event, giving it a chance to
  // abort the startup.
  if (!logger_started_callback_.is_null() &&
      !logger_started_callback_.Run(this)) {
    ignore_result(StopRpc());
    ignore_result(FinishRpc());
    return false;
  }

  return true;
}

bool Logger::StopRpc() {
  // This method may be called by any thread, but it does not inspect or modify
  // the internal state of the Logger; so, no synchronization is required.
  VLOG(1) << "Requesting an asynchronous shutdown of the logging service.";

  RPC_STATUS status = ::RpcMgmtStopServerListening(NULL);
  if (status != RPC_S_OK) {
    LOG(ERROR) << "Failed to stop the RPC server: "
                << com::LogWe(status) << ".";
    return false;
  }

  return true;
}

bool Logger::FinishRpc() {
  // This method must be called by the owning thread, so no need to otherwise
  // synchronize the method invocation.
  DCHECK_EQ(owning_thread_id_, base::PlatformThread::CurrentId());
  DCHECK(state_ == kRunning || state_ == kInitialized);

  bool error = false;
  RPC_STATUS status = RPC_S_OK;

  // Run the RPC server to completion. This is a blocking call which will only
  // terminate after someone calls StopRpc() on another thread.
  if (state_ == kRunning) {
    state_ = kStopping;
    status = RpcMgmtWaitServerListen();
    if (status != RPC_S_OK) {
      LOG(ERROR) << "Failed to wait for RPC server shutdown: "
                  << com::LogWe(status) << ".";
      error = true;
    }
  }

  status = ::RpcServerUnregisterIf(
      LoggerService_Logger_v1_0_s_ifspec, NULL, FALSE);
  if (status != RPC_S_OK) {
    LOG(ERROR) << "Failed to unregister the Logger RPC interface: "
                << com::LogWe(status) << ".";
    error = true;
  }

  status = ::RpcServerUnregisterIf(
      LoggerService_LoggerControl_v1_0_s_ifspec, NULL, FALSE);
  if (status != RPC_S_OK) {
    LOG(ERROR) << "Failed to unregister Logger Control RPC interface: "
                << com::LogWe(status) << ".";
    error = true;
  }

  state_ = kStopped;

  LOG(INFO) << "The logging service has stopped.";

  if (!logger_stopped_callback_.is_null() &&
      !logger_stopped_callback_.Run(this)) {
    error = true;
  }

  return !error;
}

}  // namespace logger
}  // namespace trace
