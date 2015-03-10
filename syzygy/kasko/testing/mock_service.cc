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

#include "syzygy/kasko/testing/mock_service.h"

namespace kasko {
namespace testing {

MockService::MockService(std::vector<CallRecord>* call_log)
    : call_log_(call_log) {}

MockService::~MockService() {}

void MockService::SendDiagnosticReport(
    base::ProcessId client_process_id,
    uint64_t exception_info_address,
    base::PlatformThreadId thread_id,
    MinidumpType minidump_type,
    const char* protobuf,
    size_t protobuf_length,
    const std::map<base::string16, base::string16>& crash_keys) {
  CallRecord record = {client_process_id,
                       minidump_type,
                       std::string(protobuf, protobuf_length),
                       crash_keys};
  call_log_->push_back(record);
}

}  // namespace testing
}  // namespace kasko
