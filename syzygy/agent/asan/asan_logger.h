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

#ifndef SYZYGY_AGENT_ASAN_ASAN_LOGGER_H_
#define SYZYGY_AGENT_ASAN_ASAN_LOGGER_H_

#include <string>

#include "base/logging.h"
#include "syzygy/trace/rpc/rpc_helpers.h"

namespace agent {
namespace asan {

struct AsanErrorInfo;

// A wrapper class to manage the singleton ASAN RPC logger instance.
class AsanLogger {
 public:
  AsanLogger();

  // Set the RPC instance ID to use. If an instance-id is to be used by the
  // logger, it must be set before calling Init().
  const std::wstring& instance_id() const { return instance_id_; }
  void set_instance_id(const base::StringPiece16& instance_id) {
    DCHECK(rpc_binding_.Get() == NULL);
    instance_id_.assign(instance_id.begin(), instance_id.end());
  }

  // Set whether to write text to the asan log.
  bool log_as_text() const { return log_as_text_; }
  void set_log_as_text(bool value) { log_as_text_ = value; }

  // Set whether to save a minidump on error.
  bool minidump_on_failure() const { return minidump_on_failure_; }
  void set_minidump_on_failure(bool value) { minidump_on_failure_ = value; }

  // Initialize the logger.
  void Init();

  // Stop the logger.
  void Stop();

  // Write a @p message to the logger.
  void Write(const std::string& message);

  // Write a @p message to the logger, and have the logger include the most
  // detailed and accurate stack trace it can derive given the execution
  // @p context .
  void WriteWithContext(const std::string& message, const CONTEXT& context);

  // Write a @p message to the logger, with an optional stack @p trace
  // containing @p trace_length elements.
  void WriteWithStackTrace(const std::string& message,
                           const void* const* trace_data,
                           size_t trace_length);

  // Ask the logger to capture a minidump of the process for the given
  // @p context and @p error_info.
  void SaveMiniDump(CONTEXT* context, AsanErrorInfo* error_info);

 protected:
  // The RPC binding.
  trace::client::ScopedRpcBinding rpc_binding_;

  // The logger's instance id.
  std::wstring instance_id_;

  // True if the runtime has been asked to write text to the logger.
  // Default: true.
  bool log_as_text_;

  // True if the runtime has been asked to save a minidump on error.
  // Default: false.
  bool minidump_on_failure_;

 private:
  DISALLOW_COPY_AND_ASSIGN(AsanLogger);
};

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_ASAN_LOGGER_H_
