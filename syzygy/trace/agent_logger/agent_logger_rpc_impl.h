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
// This file declares the RpcLoggerInstanceManager which binds the call
// trace service RPC handlers to a trace::agent_logger::Logger instance.

#ifndef SYZYGY_TRACE_AGENT_LOGGER_AGENT_LOGGER_RPC_IMPL_H_
#define SYZYGY_TRACE_AGENT_LOGGER_AGENT_LOGGER_RPC_IMPL_H_

#include "base/logging.h"

namespace trace {
namespace agent_logger {

// Forward declaration.
class AgentLogger;

// A helper class to manage a "global" Logger instance to which the RPC
// callbacks are bound. You can create an instance of this manager to
// bind and unbind a given instance to the callbacks within a particular
// scope.
class RpcLoggerInstanceManager {
 public:
  explicit RpcLoggerInstanceManager(AgentLogger* logger) {
    DCHECK(logger != NULL);
    DCHECK(instance_ == NULL);
    instance_ = logger;
  }

  ~RpcLoggerInstanceManager() {
    DCHECK(instance_ != NULL);
    instance_ = NULL;
  }

  static AgentLogger* GetInstance() {
    DCHECK(instance_ != NULL);
    return instance_;
  }

 protected:
  static AgentLogger* instance_;
};

}  // namespace agent_logger
}  // namespace trace

#endif  // SYZYGY_TRACE_AGENT_LOGGER_AGENT_LOGGER_RPC_IMPL_H_
