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

// This file implements the RPC stubs which bind the LoggerService RPC
// handlers to a Logger instance.

#include "syzygy/trace/logger/logger_rpc_impl.h"
#include "syzygy/trace/logger/logger.h"
#include "syzygy/trace/rpc/logger_rpc.h"

using trace::logger::RpcLoggerInstanceManager;
using trace::logger::Logger;

// The instance to which the RPC callbacks are bound.
Logger* RpcLoggerInstanceManager::instance_ = NULL;

// RPC entrypoint for Logger::Write().
boolean LoggerService_Write(
    /* [in] */ handle_t binding,
    /* [string][in] */ const unsigned char *text) {
  Logger* instance = RpcLoggerInstanceManager::GetInstance();
  return instance->Write(reinterpret_cast<const char*>(text));
}

// RPC entrypoint for Logger::Stop().
boolean LoggerService_Stop(/* [in] */ handle_t binding) {
  Logger* instance = RpcLoggerInstanceManager::GetInstance();
  return instance->Stop();
}
