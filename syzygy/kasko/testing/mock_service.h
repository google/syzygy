// Copyright 2015 Google Inc. All Rights Reserved.
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

#ifndef SYZYGY_KASKO_TESTING_MOCK_SERVICE_H_
#define SYZYGY_KASKO_TESTING_MOCK_SERVICE_H_

#include <map>
#include <string>
#include <vector>

#include "base/macros.h"
#include "base/process/process_handle.h"
#include "base/strings/string16.h"
#include "syzygy/kasko/service.h"

namespace kasko {
namespace testing {

// Handles Kasko RPC invocations by logging their parameters.
class MockService : public Service {
 public:
  // Records the parameters of an RPC invocation.
  struct CallRecord {
    // The caller process ID.
    const base::ProcessId client_process_id;

    // The supplied protobuf.
    const std::string protobuf;

    // The supplied crash keys.
    const std::map<base::string16, base::string16> crash_keys;
  };

  // Instantiates a service that records calls in the provided vector.
  // @param call_log The vector in which calls should be recorded.
  // @note call_log will be modified in whichever thread the RPC is handled.
  //     It is the client's responsibility to prevent problems from concurrent
  //     access.
  explicit MockService(std::vector<CallRecord>* call_log);
  virtual ~MockService();

  // Service implementation.
  virtual void SendDiagnosticReport(
      base::ProcessId client_process_id,
      uint64_t exception_info_address,
      base::PlatformThreadId thread_id,
      const char* protobuf,
      size_t protobuf_length,
      const std::map<base::string16, base::string16>& crash_keys) override;

 private:
  std::vector<CallRecord>* call_log_;

  DISALLOW_COPY_AND_ASSIGN(MockService);
};

}  // namespace testing
}  // namespace kasko

#endif  // SYZYGY_KASKO_TESTING_MOCK_SERVICE_H_
