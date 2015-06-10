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

#ifndef SYZYGY_KASKO_CLIENT_H_
#define SYZYGY_KASKO_CLIENT_H_

#include "base/macros.h"
#include "base/strings/string16.h"

namespace kasko {

struct MinidumpRequest;

// Implements the client process lifetime. Holds configuration and provides an
// API for triggering a diagnostic report of the current process..
class Client {
 public:
  // Instantiates a diagnostic reporting client.
  // @param endpoint_name The RPC endpoint name shared with the reporter
  //     process.
  explicit Client(const base::string16& endpoint);

  ~Client();

  // Sends a diagnostic report for the current process.
  // @param request The report parameters.
  void SendReport(const MinidumpRequest& request) const;

 private:
  // The RPC endpoint name shared with the reporter process.
  const base::string16 endpoint_;

  DISALLOW_COPY_AND_ASSIGN(Client);
};

}  // namespace kasko

#endif  // SYZYGY_KASKO_CLIENT_H_
