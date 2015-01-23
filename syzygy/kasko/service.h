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

#include <stdint.h>

#include <map>

#include "base/process/process_handle.h"
#include "base/strings/string16.h"
#include "base/threading/platform_thread.h"

namespace kasko {

// Defines an RPC-agnostic implementation of the methods exposed by the Kasko
// RPC service.
class Service {
  public:
   virtual ~Service() {}

   // Responds to a request to send a diagnostic report.
   // @param client_process_id The process to be reported on.
   // @param exception_info_address An optional address (in the target process
   //     memory space) of an EXCEPTION_POINTERS structure.
   // @param thread_id The (optional) faulting thread in the target process.
   // @param protobuf An optional protobuf to be included in the report.
   // @param protobuf_length The length of the protobuf.
   // @param crash_keys Crash keys to be included in the report.
   virtual void SendDiagnosticReport(
       base::ProcessId client_process_id,
       uint64_t exception_info_address,
       base::PlatformThreadId thread_id,
       const char* protobuf,
       size_t protobuf_length,
       const std::map<base::string16, base::string16>& crash_keys) = 0;
};

}  // namespace kasko

#endif  // SYZYGY_KASKO_SERVICE_H_
