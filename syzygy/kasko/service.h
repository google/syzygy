// Copyright 2014 Google Inc. All Rights Reserved.
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

#ifndef SYZYGY_KASKO_SERVICE_H_
#define SYZYGY_KASKO_SERVICE_H_

#include "base/process/process_handle.h"
#include "base/threading/platform_thread.h"

namespace kasko {

struct MinidumpRequest;

// Defines an RPC-agnostic implementation of the methods exposed by the Kasko
// RPC service.
class Service {
 public:
  virtual ~Service() {}

  // Responds to a request to send a diagnostic report.
  // @param thread_id The crashing thread to report on. Ignored if
  //     request.exception_info_address is null.
  // @param request The report parameters.
  virtual void SendDiagnosticReport(base::ProcessId client_process_id,
                                    base::PlatformThreadId thread_id,
                                    const MinidumpRequest& request) = 0;
};

}  // namespace kasko

#endif  // SYZYGY_KASKO_SERVICE_H_
